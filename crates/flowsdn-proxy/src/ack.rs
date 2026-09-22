//! Per-endpoint regeneration barrier. All methods use caller-supplied monotonic
//! ticks; the caller executes rollback, retries and guarded BPF publication.
use std::{collections::{BTreeMap, BTreeSet}, net::IpAddr};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State { Pending, Ready, Committed, Rejected, TimedOut, Cancelled }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { InvalidRequirement, InvalidResponse, Terminal, NotReady, EpochExhausted }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitPermit { pub attempt: u64, pub policy_revision: u64 }
#[derive(Clone, Debug)]
pub struct Observation { pub node: IpAddr, pub epoch: u64, pub kind: String, pub nonce: u64, pub version: u64, pub nack: bool }
#[derive(Debug)]
pub struct Barrier {
    node: IpAddr, attempt: u64, policy_revision: u64, deadline: u64, epoch: u64,
    required: BTreeMap<String, u64>, sent: BTreeMap<String, u64>, acked: BTreeSet<String>, state: State,
}
impl Barrier {
    pub fn new(node: IpAddr, attempt: u64, policy_revision: u64, deadline: u64, required: BTreeMap<String, u64>) -> Result<Self, Error> {
        if required.is_empty() || required.iter().any(|(kind, version)| kind.is_empty() || *version == 0) { return Err(Error::InvalidRequirement); }
        Ok(Self { node, attempt, policy_revision, deadline, epoch: 0, required, sent: BTreeMap::new(), acked: BTreeSet::new(), state: State::Pending })
    }
    pub fn state(&self) -> State { self.state }
    pub fn epoch(&self) -> u64 { self.epoch }
    fn live(&mut self, now: u64) -> Result<(), Error> {
        if !matches!(self.state, State::Pending | State::Ready) { return Err(Error::Terminal); }
        if now >= self.deadline { self.state = State::TimedOut; return Err(Error::Terminal); }
        Ok(())
    }
    /// Register a response actually sent on the current node/type stream. The
    /// pinned protocol uses response_nonce == version. New responses revoke any
    /// prior acknowledgement for that type until this response is acknowledged.
    pub fn sent(&mut self, kind: &str, version: u64, now: u64) -> Result<(), Error> {
        self.live(now)?;
        let minimum = self.required.get(kind).ok_or(Error::InvalidResponse)?;
        if version < *minimum || self.sent.get(kind).is_some_and(|old| version <= *old) { return Err(Error::InvalidResponse); }
        self.sent.insert(kind.into(), version); self.acked.remove(kind); self.state = State::Pending;
        Ok(())
    }
    /// Unknown node, stale stream epoch and stale nonce cannot acknowledge work.
    /// An error response is a NACK even when version/nonce happen to be equal.
    pub fn observe(&mut self, event: &Observation, now: u64) -> Result<bool, Error> {
        self.live(now)?;
        let Observation { node, epoch, kind, nonce, version, nack } = event;
        let (node, epoch, nonce, version, nack) = (*node, *epoch, *nonce, *version, *nack);
        if node != self.node || epoch != self.epoch || self.sent.get(kind) != Some(&nonce) { return Ok(false); }
        if version > nonce { return Err(Error::InvalidResponse); }
        if nack || version < nonce { self.state = State::Rejected; return Ok(true); }
        self.acked.insert(kind.clone());
        if self.acked.len() == self.required.len() { self.state = State::Ready; }
        Ok(true)
    }
    /// A disconnected pending attempt needs fresh acknowledgements, including
    /// types ACKed on the old connection. No pre-first-ACK resume value counts.
    pub fn reconnect(&mut self, now: u64) -> Result<u64, Error> {
        self.live(now)?;
        self.epoch = self.epoch.checked_add(1).ok_or(Error::EpochExhausted)?;
        self.sent.clear(); self.acked.clear(); self.state = State::Pending; Ok(self.epoch)
    }
    pub fn cancel(&mut self) {
        if matches!(self.state, State::Pending | State::Ready) { self.state = State::Cancelled; }
    }
    pub fn commit(&mut self, now: u64) -> Result<CommitPermit, Error> {
        self.live(now)?;
        if self.state != State::Ready { return Err(Error::NotReady); }
        self.state = State::Committed;
        Ok(CommitPermit { attempt: self.attempt, policy_revision: self.policy_revision })
    }
}
