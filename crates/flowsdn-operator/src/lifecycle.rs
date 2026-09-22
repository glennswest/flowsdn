//! Serialized lifecycle state machine. Callers must execute terminal actions
//! immediately; this gate does not cancel requests or terminate a process.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum State {
    #[default]
    Follower,
    StartingLeader,
    Leading,
    Terminated,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    LeaseAcquired,
    DutiesStarted,
    LeadershipLost,
    DutyStartFailed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    StartLeaderScope,
    PublishLeadership,
    /// Cancel requests, emit leadership-lost, then exit 1 without a drain wait.
    CancelAndExit,
    /// Failed startup cannot retain the Lease with partially started duties.
    CancelReleaseAndExit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTransition;
#[derive(Debug, Default)]
pub struct Lifecycle {
    state: State,
}
impl Lifecycle {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn is_leader(&self) -> bool {
        self.state == State::Leading
    }
    pub fn transition(&mut self, event: Event) -> Result<Action, InvalidTransition> {
        let (state, action) = match (self.state, event) {
            (State::Follower, Event::LeaseAcquired) => {
                (State::StartingLeader, Action::StartLeaderScope)
            }
            (State::StartingLeader, Event::DutiesStarted) => {
                (State::Leading, Action::PublishLeadership)
            }
            (State::StartingLeader | State::Leading, Event::LeadershipLost) => {
                (State::Terminated, Action::CancelAndExit)
            }
            (State::StartingLeader, Event::DutyStartFailed) => {
                (State::Terminated, Action::CancelReleaseAndExit)
            }
            _ => return Err(InvalidTransition),
        };
        self.state = state;
        Ok(action)
    }
}
