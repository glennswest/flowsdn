//! Deterministic export-only session core. Transport must execute actions in
//! order and associate callbacks with the returned connection generation.
//! No socket, inbound route installation, RIB or async timer task is provided.
use crate::{
    ErrorAction, Frame, Kind, ProtocolError,
    capabilities::{Family, Negotiated, negotiate},
    error_action,
    open::Open,
    update,
};
use std::{collections::BTreeSet, net::Ipv4Addr};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseDisposition {
    Hard,
    PeerMayRetainExports,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfig,
    ClockReversed,
    TimeOverflow,
    GenerationExhausted,
}
#[derive(Clone, Debug)]
pub struct Config {
    pub local: Open,
    pub peer_asn: u32,
    pub listen: bool,
    pub passive: bool,
    pub retry_ms: u64,
    pub keepalive_ms: u64,
    pub strict_update_errors: bool,
    pub graceful_shutdown: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Connect {
        generation: u64,
    },
    Send {
        kind: Kind,
        body: Vec<u8>,
    },
    Close,
    Export {
        families: BTreeSet<Family>,
        end_of_rib: bool,
    },
    /// Observation only. No action variant can install a received route.
    ObserveUpdate(update::Summary),
    DiscardUpdate(ProtocolError),
    DropConnection,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Deadlines {
    pub retry: Option<u64>,
    pub hold: Option<u64>,
    pub keepalive: Option<u64>,
    pub idle: Option<u64>,
}
#[derive(Clone, Debug)]
pub struct Session {
    config: Config,
    state: State,
    deadlines: Deadlines,
    negotiated: Option<Negotiated>,
    last_time: u64,
    generation: u64,
    running: bool,
    last_close: CloseDisposition,
}
#[derive(Clone, Copy, Debug)]
pub enum Event<'a> {
    Start,
    TcpEstablished { generation: u64, inbound: bool },
    TcpFailed { generation: u64 },
    TcpClosed { generation: u64 },
    Message { generation: u64, frame: Frame<'a> },
    HardReset,
    SoftResetOut,
    Shutdown,
}
fn deadline(now: u64, delay: u64) -> Result<u64, Error> {
    now.checked_add(delay).ok_or(Error::TimeOverflow)
}
/// Entropy belongs to the caller; modulo is deterministic and bounded, not a
/// cryptographic RNG or a claim of an unbiased random distribution.
pub fn retry_delay(base: u64, entropy: u64) -> Result<u64, Error> {
    if base == 0 {
        return Err(Error::InvalidConfig);
    }
    base.checked_add(entropy.checked_rem(base).ok_or(Error::InvalidConfig)?)
        .ok_or(Error::TimeOverflow)
}
impl Session {
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.local.encode().is_err()
            || config.local.router_id.is_unspecified()
            || config.local.effective_asn().ok() == Some(0)
            || config.passive && !config.listen
            || config.retry_ms == 0
            || config.retry_ms > u64::MAX / 2
            || config.keepalive_ms == 0
        {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            config,
            state: State::Idle,
            deadlines: Deadlines::default(),
            negotiated: None,
            last_time: 0,
            generation: 0,
            running: false,
            last_close: CloseDisposition::Hard,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn last_close(&self) -> CloseDisposition {
        self.last_close
    }
    pub fn deadlines(&self) -> Deadlines {
        self.deadlines
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn negotiated(&self) -> Option<&Negotiated> {
        self.negotiated.as_ref()
    }
    fn new_generation(&mut self) -> Result<(), Error> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        Ok(())
    }
    fn connect(&mut self, now: u64, entropy: u64, out: &mut Vec<Action>) -> Result<(), Error> {
        self.new_generation()?;
        self.state = if self.config.passive {
            State::Active
        } else {
            State::Connect
        };
        self.deadlines = Deadlines {
            retry: Some(deadline(now, retry_delay(self.config.retry_ms, entropy)?)?),
            ..Default::default()
        };
        if !self.config.passive {
            out.push(Action::Connect {
                generation: self.generation,
            });
        }
        Ok(())
    }
    fn reset(
        &mut self,
        now: u64,
        notification: Option<(u8, u8)>,
        out: &mut Vec<Action>,
    ) -> Result<(), Error> {
        let cause = notification.map(|(code, subcode)| if (code, subcode)==(2,1) {
            crate::messages::Notification::unsupported_version()
        } else { crate::messages::Notification {code,subcode,data:vec![]} });
        self.reset_notification(now,cause,out)
    }
    fn reset_notification(&mut self, now:u64, notification:Option<crate::messages::Notification>, out:&mut Vec<Action>)->Result<(),Error> {
        let gr = self.negotiated.as_ref().and_then(|n| n.graceful.as_ref());
        let notifications = gr.is_some_and(|g| g.notifications);
        let hard = notification
            .as_ref().is_some_and(|n| n.code == 6 && matches!(n.subcode, 2 | 3 | 4 | 9));
        self.last_close = if gr.is_some() && !hard && (notification.is_none() || notifications) {
            CloseDisposition::PeerMayRetainExports
        } else {
            CloseDisposition::Hard
        };
        if let Some(cause) = notification {
            let cause = if hard {
                cause
                    .hard_reset(notifications)
                    .map_err(|_| Error::InvalidConfig)?
            } else {
                cause
            };
            out.push(Action::Send {
                kind: Kind::Notification,
                body: cause.encode().map_err(|_| Error::InvalidConfig)?,
            });
        }
        out.push(Action::Close);
        self.new_generation()?;
        self.state = State::Idle;
        self.negotiated = None;
        self.deadlines = Deadlines {
            idle: if self.running {
                Some(deadline(now, 5000)?)
            } else {
                None
            },
            ..Default::default()
        };
        Ok(())
    }
    fn hold_delay(&self) -> u64 {
        u64::from(self.negotiated.as_ref().map_or(0, |n| n.hold_time)).saturating_mul(1000)
    }
    fn reset_hold(&mut self, now: u64) -> Result<(), Error> {
        let hold = self.hold_delay();
        self.deadlines.hold = if hold == 0 {
            None
        } else {
            Some(deadline(now, hold)?)
        };
        Ok(())
    }
    fn keepalive_delay(&self) -> u64 {
        self.config.keepalive_ms.min(self.hold_delay() / 3)
    }
    fn schedule_keepalive(&mut self, now: u64) -> Result<(), Error> {
        let delay = self.keepalive_delay();
        self.deadlines.keepalive = if delay == 0 {
            None
        } else {
            Some(deadline(now, delay)?)
        };
        Ok(())
    }
    /// Hold expiry wins ties and is processed before any newly received frame.
    fn advance(&mut self, now: u64, entropy: u64, out: &mut Vec<Action>) -> Result<bool, Error> {
        if now < self.last_time {
            return Err(Error::ClockReversed);
        }
        self.last_time = now;
        if self.deadlines.hold.is_some_and(|d| now >= d) {
            self.reset(now, Some((4, 0)), out)?;
            return Ok(true);
        }
        if self.deadlines.idle.is_some_and(|d| now >= d) {
            self.connect(now, entropy, out)?;
        } else if self.deadlines.retry.is_some_and(|d| now >= d)
            && matches!(self.state, State::Connect | State::Active)
        {
            out.push(Action::Close);
            self.connect(now, entropy, out)?;
        }
        if self.deadlines.keepalive.is_some_and(|d| now >= d)
            && matches!(self.state, State::OpenConfirm | State::Established)
        {
            out.push(Action::Send {
                kind: Kind::Keepalive,
                body: vec![],
            });
            self.schedule_keepalive(now)?;
        }
        Ok(false)
    }
    /// Failed local clock/overflow validation preserves the previous state.
    pub fn poll(&mut self, now: u64, entropy: u64) -> Result<Vec<Action>, Error> {
        let mut next = self.clone();
        let mut out = Vec::new();
        next.advance(now, entropy, &mut out)?;
        *self = next;
        Ok(out)
    }
    pub fn handle(
        &mut self,
        event: Event<'_>,
        now: u64,
        entropy: u64,
    ) -> Result<Vec<Action>, Error> {
        let mut next = self.clone();
        let mut out = Vec::new();
        next.advance(now, entropy, &mut out)?;
        next.process(event, now, entropy, &mut out)?;
        *self = next;
        Ok(out)
    }
    fn process(
        &mut self,
        event: Event<'_>,
        now: u64,
        entropy: u64,
        out: &mut Vec<Action>,
    ) -> Result<(), Error> {
        match event {
            Event::Start => {
                self.running = true;
                if self.state == State::Idle && self.deadlines.idle.is_none() {
                    self.connect(now, entropy, out)?;
                }
            }
            Event::HardReset => self.reset(now, Some((6, 4)), out)?,
            Event::Shutdown => {
                self.running = false;
                self.reset(
                    now,
                    if self.config.graceful_shutdown {
                        None
                    } else {
                        Some((6, 2))
                    },
                    out,
                )?;
            }
            Event::SoftResetOut => {
                if self.state == State::Established {
                    out.push(Action::Export {
                        families: self
                            .negotiated
                            .as_ref()
                            .expect("established negotiation")
                            .families
                            .clone(),
                        end_of_rib: false,
                    });
                }
            }
            Event::TcpEstablished {
                generation,
                inbound,
            } => {
                if generation != self.generation
                    || !self.running
                    || inbound && !self.config.listen
                    || matches!(
                        self.state,
                        State::OpenSent | State::OpenConfirm | State::Established
                    )
                    || self.deadlines.idle.is_some()
                {
                    out.push(Action::DropConnection);
                    return Ok(());
                }
                if !inbound && self.config.passive {
                    out.push(Action::DropConnection);
                    return Ok(());
                }
                if !inbound && self.state == State::Idle {
                    out.push(Action::DropConnection);
                    return Ok(());
                }
                self.state = State::OpenSent;
                self.deadlines = Deadlines {
                    hold: Some(deadline(now, 240000)?),
                    ..Default::default()
                };
                out.push(Action::Send {
                    kind: Kind::Open,
                    body: self
                        .config
                        .local
                        .encode()
                        .map_err(|_| Error::InvalidConfig)?,
                });
            }
            Event::TcpFailed { generation } => {
                if generation == self.generation
                    && matches!(self.state, State::Connect | State::Active)
                {
                    self.new_generation()?;
                    self.state = State::Active;
                    self.deadlines.retry =
                        Some(deadline(now, retry_delay(self.config.retry_ms, entropy)?)?);
                }
            }
            Event::TcpClosed { generation } => {
                if generation != self.generation {
                    return Ok(());
                }
                match self.state {
                    State::OpenSent => {
                        self.new_generation()?;
                        self.state = State::Active;
                        self.deadlines = Deadlines {
                            retry: Some(deadline(
                                now,
                                retry_delay(self.config.retry_ms, entropy)?,
                            )?),
                            ..Default::default()
                        };
                    }
                    State::OpenConfirm | State::Established => self.reset(now, None, out)?,
                    State::Connect | State::Active => {
                        self.new_generation()?;
                        self.state = State::Active;
                        self.deadlines.retry =
                            Some(deadline(now, retry_delay(self.config.retry_ms, entropy)?)?);
                    }
                    _ => {}
                }
            }
            Event::Message { generation, frame } => {
                if generation != self.generation {
                    return Ok(());
                }
                self.message(frame, now, out)?;
            }
        }
        Ok(())
    }
    /// Consume one buffered wire message. None means more bytes are needed and
    /// leaves timers/state untouched; callers must continue polling timers.
    /// Fatal framing errors consume the supplied buffer and close this session.
    pub fn receive(&mut self, generation:u64, bytes:&[u8], now:u64, entropy:u64) -> Result<Option<(Vec<Action>,usize)>,Error> {
        match crate::decode(bytes) {
            Ok((frame,consumed)) => self.handle(Event::Message {generation,frame},now,entropy).map(|actions|Some((actions,consumed))),
            Err(crate::DecodeError::NeedMore) => Ok(None),
            Err(crate::DecodeError::Protocol(error)) => {
                let mut next=self.clone(); let mut actions=Vec::new();
                next.advance(now,entropy,&mut actions)?;
                if generation==next.generation && matches!(next.state,State::OpenSent|State::OpenConfirm|State::Established) {
                    let data=match error.subcode {2=>bytes.get(16..18).unwrap_or_default().to_vec(),3=>bytes.get(18..19).unwrap_or_default().to_vec(),_=>vec![]};
                    next.reset_notification(now,Some(crate::messages::Notification{code:error.code,subcode:error.subcode,data}),&mut actions)?;
                }
                *self=next; Ok(Some((actions,bytes.len())))
            }
        }
    }
    fn message(&mut self, frame: Frame<'_>, now: u64, out: &mut Vec<Action>) -> Result<(), Error> {
        if !matches!(
            self.state,
            State::OpenSent | State::OpenConfirm | State::Established
        ) {
            return Ok(());
        }
        // Frame may be directly constructed by an adapter: enforce envelope
        // size and message minimums again before interpreting its body.
        if let Err(error) = crate::encode(frame.kind, frame.body) {
            let length = u16::try_from(crate::HEADER_LENGTH.saturating_add(frame.body.len())).unwrap_or(u16::MAX);
            self.reset_notification(now,Some(crate::messages::Notification {code:error.code,subcode:error.subcode,data:length.to_be_bytes().to_vec()}),out)?;
            return Ok(());
        }
        if frame.kind == Kind::Notification {
            let notifications = self
                .negotiated
                .as_ref()
                .and_then(|n| n.graceful.as_ref())
                .is_some_and(|g| g.notifications);
            let graceful = crate::messages::Notification::decode(frame.body)
                .is_ok_and(|n| n.permits_graceful_restart(notifications));
            self.reset(now, None, out)?;
            if !graceful {
                self.last_close = CloseDisposition::Hard;
            }
            return Ok(());
        }
        if self.state == State::OpenSent && frame.kind == Kind::Open {
            match Open::decode(frame.body)
                .and_then(|peer| negotiate(&self.config.local, &peer, self.config.peer_asn))
            {
                Ok(negotiated) => {
                    self.negotiated = Some(negotiated);
                    self.state = State::OpenConfirm;
                    self.deadlines = Deadlines::default();
                    self.reset_hold(now)?;
                    self.schedule_keepalive(now)?;
                    out.push(Action::Send {
                        kind: Kind::Keepalive,
                        body: vec![],
                    });
                }
                Err(error) => {
                    let mut error=error;
                    if error.subcode==4 { error.subcode=open_parameter_subcode(frame.body); }
                    let mut data=if error.subcode==1 {vec![0,4]} else {vec![]};
                    if error.subcode==7 {
                        for capability in self.config.local.capabilities.iter().filter(|c|c.code==1) {
                            data.push(capability.code);
                            data.push(u8::try_from(capability.value.len()).map_err(|_|Error::InvalidConfig)?);
                            data.extend_from_slice(&capability.value);
                        }
                    }
                    self.reset_notification(now,Some(crate::messages::Notification{code:error.code,subcode:error.subcode,data}),out)?;
                },
            }
            return Ok(());
        }
        if self.state == State::OpenConfirm && frame.kind == Kind::Keepalive {
            self.state = State::Established;
            self.reset_hold(now)?;
            out.push(Action::Export {
                families: self
                    .negotiated
                    .as_ref()
                    .expect("negotiated")
                    .families
                    .clone(),
                end_of_rib: true,
            });
            return Ok(());
        }
        if self.state == State::Established {
            match frame.kind {
                Kind::Keepalive => {
                    self.reset_hold(now)?;
                    return Ok(());
                }
                Kind::Update => {
                    let four = self.negotiated.as_ref().expect("negotiated").four_octet_asn;
                    match update::validate_detailed(frame.body, four) {
                        Ok(summary) => {
                            self.reset_hold(now)?;
                            out.push(Action::ObserveUpdate(summary));
                        }
                        Err(failure) => match error_action(failure.error, self.config.strict_update_errors) {
                            ErrorAction::NotifyAndClose => {
                                self.reset_notification(now, Some(crate::messages::Notification {code:failure.error.code, subcode:failure.error.subcode, data:failure.data}), out)?
                            }
                            ErrorAction::CountLogAndDiscard => {
                                out.push(Action::DiscardUpdate(failure.error))
                            }
                        },
                    }
                    return Ok(());
                }
                Kind::RouteRefresh => {
                    if let Ok(family) = crate::messages::decode_refresh(frame.body)
                        && self
                            .negotiated
                            .as_ref()
                            .expect("negotiated")
                            .families
                            .contains(&family)
                    {
                        out.push(Action::Export {
                            families: BTreeSet::from([family]),
                            end_of_rib: false,
                        });
                    }
                    return Ok(());
                }
                _ => {}
            }
        }
        let subcode = match self.state {
            State::OpenSent => 1,
            State::OpenConfirm => 2,
            _ => 3,
        };
        self.reset_notification(now,Some(crate::messages::Notification{code:5,subcode,data:vec![frame.kind as u8]}),out)
    }
}
/// For two unestablished connections, retain the one initiated by the speaker
/// with the greater router ID. Established sessions take priority in the caller.
pub fn retain_outbound(local: Ipv4Addr, peer: Ipv4Addr) -> Option<bool> {
    if local == peer {
        None
    } else {
        Some(u32::from(local) > u32::from(peer))
    }
}

/// RFC4271§6.2: a recognized malformed parameter is Unspecific (0), whereas
/// an unrecognized complete parameter is Unsupported Optional Parameter (4).
/// Decode each bounded prefix so earlier malformed capability content takes
/// precedence over a later unknown parameter. OPEN options are at most255bytes.
fn open_parameter_subcode(body:&[u8])->u8 {
    let Some(length)=body.get(9).copied() else{return 0;};
    if body.len()!=10+usize::from(length){return 0;}
    let mut offset=10;
    while offset<body.len() {
        let Some(kind)=body.get(offset).copied() else{return 0;};
        let Some(length)=body.get(offset+1).copied() else{return 0;};
        let end=offset+2+usize::from(length);
        let Some(prefix)=body.get(..end) else{return 0;};
        if kind!=2{return 4;}
        let mut prefix=prefix.to_vec();
        let Some(total)=prefix.get_mut(9) else{return 0;};
        let Ok(length)=u8::try_from(end-10) else{return 0;};*total=length;
        if Open::decode(&prefix).is_err(){return 0;}
        offset=end;
    }
    0
}
