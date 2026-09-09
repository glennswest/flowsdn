use crate::{Kind, ReconcileError, Reconciler, Target, Work};
use flowsdn_table::{Keyed, Revision, Snapshot};
use std::{collections::VecDeque, time::{Duration, Instant}};

struct Pass<T: Keyed> {
    snapshot: Snapshot<T>,
    started: Instant,
    from: Revision,
    exhausted: bool,
    candidates: VecDeque<Work<T>>,
    next_eligible: Option<Instant>,
}

pub(crate) struct RefreshState<T: Keyed> {
    next_due: Option<Instant>,
    not_before: Option<Instant>,
    pass: Option<Pass<T>>,
}
impl<T: Keyed> Default for RefreshState<T> {
    fn default() -> Self { Self { next_due: None, not_before: None, pass: None } }
}
impl<T: Keyed> RefreshState<T> {
    pub(crate) fn reset_pass(&mut self) {
        self.next_due = None;
        self.pass = None;
    }
}

impl<T: Keyed, U: Target<T>> Reconciler<'_, T, U> {
    /// The next refresh scan or rate-limited dispatch. None means disabled or
    /// that no round has established the first interval yet.
    pub fn next_refresh(&self) -> Option<Instant> { self.refresh.next_due }

    pub(crate) fn arm_refresh(&mut self, now: Instant) -> Result<(), ReconcileError> {
        if self.options.refresh_interval.is_zero() || self.refresh.next_due.is_some() { return Ok(()); }
        self.finish_refresh_pass(now)
    }

    fn finish_refresh_pass(&mut self, now: Instant) -> Result<(), ReconcileError> {
        let next = now.checked_add(self.options.refresh_interval)
            .ok_or(ReconcileError::RefreshDeadlineOverflow)?;
        let next = self.refresh.pass.as_ref().and_then(|pass| pass.next_eligible).map_or(next, |eligible| next.min(eligible.max(now)));
        self.refresh.next_due = Some(self.refresh.not_before.map_or(next, |limit| next.max(limit)));
        self.refresh.pass = None;
        Ok(())
    }

    pub(crate) fn complete_refresh_work(&mut self, now: Instant) -> Result<(), ReconcileError> {
        if self.refresh.pass.as_ref().is_some_and(|pass| pass.exhausted && pass.candidates.is_empty()) {
            self.finish_refresh_pass(now)?;
        }
        Ok(())
    }

    fn refresh_eligible(&self, work: &Work<T>, started: Instant) -> bool {
        self.current(work) && self.statuses.get(&work.key).is_some_and(|status| {
            status.id == work.revision && status.kind == Kind::Done
                && status.updated_at.is_some_and(|updated| started.saturating_duration_since(updated) >= self.options.refresh_interval)
        })
    }

    fn remember_recent(&mut self, work: &Work<T>) -> Result<(), ReconcileError> {
        if !self.current(work) { return Ok(()); }
        if let Some(status) = self.statuses.get(&work.key).filter(|status| status.id == work.revision && status.kind == Kind::Done) {
            if let Some(updated) = status.updated_at {
                let eligible = updated.checked_add(self.options.refresh_interval).ok_or(ReconcileError::RefreshDeadlineOverflow)?;
                let pass = self.refresh.pass.as_mut().expect("refresh pass exists");
                if eligible > pass.started {
                    pass.next_eligible = Some(pass.next_eligible.map_or(eligible, |old| old.min(eligible)));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn next_refresh_work(&mut self, now: Instant) -> Result<Option<Work<T>>, ReconcileError> {
        if self.options.refresh_interval.is_zero() { return Ok(None); }
        self.arm_refresh(now)?;
        if self.refresh.next_due.is_some_and(|due| due > now) { return Ok(None); }
        if self.refresh.pass.is_none() {
            self.refresh.pass = Some(Pass { snapshot: self.table.snapshot(), started: now, from: 0, exhausted: false, candidates: VecDeque::new(), next_eligible: None });
        }
        // A scan chunk retains at most round_size candidates. The immutable
        // snapshot and revision cursor prevent rescanning earlier rows or
        // mixing versions when writers race with this pass.
        let pass = self.refresh.pass.as_ref().expect("refresh pass was created");
        if pass.candidates.is_empty() && !pass.exhausted {
            let snapshot = pass.snapshot.clone();
            let started = pass.started;
            let mut rows = snapshot.by_revision(pass.from).peekable();
            let mut candidates = VecDeque::new();
            let mut from = pass.from;
            let mut exhausted = false;
            for _ in 0..self.options.round_size {
                let Some((row, revision)) = rows.next() else { exhausted = true; break; };
                let work = Work { key: row.primary_key(), revision, row: Some(row), failures: 0, refresh: true };
                if self.refresh_eligible(&work, started) { candidates.push_back(work); }
                else { self.remember_recent(&work)?; }
                if let Some(next) = revision.checked_add(1) { from = next; }
                else { exhausted = true; break; }
            }
            exhausted |= rows.peek().is_none();
            let pass = self.refresh.pass.as_mut().expect("refresh pass exists");
            pass.from = from;
            pass.exhausted = exhausted;
            pass.candidates = candidates;
        }
        let started = self.refresh.pass.as_ref().expect("refresh pass exists").started;
        loop {
            let candidate = self.refresh.pass.as_ref().expect("refresh pass exists").candidates.front().cloned();
            match candidate {
                Some(work) if !self.refresh_eligible(&work, started) => {
                    self.remember_recent(&work)?;
                    self.refresh.pass.as_mut().expect("refresh pass exists").candidates.pop_front();
                }
                Some(_) => break,
                None => {
                    if self.refresh.pass.as_ref().expect("refresh pass exists").exhausted { self.finish_refresh_pass(now)?; }
                    else { self.refresh.next_due = Some(now); }
                    return Ok(None);
                }
            }
        }
        if self.refresh.not_before.is_some_and(|limit| limit > now) {
            self.refresh.next_due = self.refresh.not_before;
            return Ok(None);
        }
        let nanos = 1_000_000_000_u64.div_ceil(u64::from(self.options.refresh_rate));
        let next = now.checked_add(Duration::from_nanos(nanos))
            .ok_or(ReconcileError::RefreshDeadlineOverflow)?;
        let pass = self.refresh.pass.as_mut().expect("refresh pass exists");
        let work = pass.candidates.pop_front();
        self.refresh.not_before = Some(next);
        // Keep the exhausted pass until its final dispatched operation has
        // completed (or been replayed after cancellation).
        self.refresh.next_due = Some(next);
        Ok(work)
    }
}
