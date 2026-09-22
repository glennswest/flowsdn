//! Connection ownership independent of socket handles. Invoke after peer OPEN
//! validation and before handing the winner to the session; close a displaced
//! connection with Cease / Connection Collision Resolution (6/7).
use std::{net::Ipv4Addr, sync::Arc};
#[derive(Clone, Debug)]
pub struct Connection {
    issuer: Arc<()>,
    sequence: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
}
#[derive(Debug)]
pub enum Resolution {
    Accepted { displaced: Option<Connection> },
    Rejected,
    InvalidRouterId,
}
#[derive(Debug, Default)]
pub struct Connections {
    issuer: Arc<()>,
    sequence: u64,
    pending: std::collections::BTreeSet<u64>,
    current: Option<(Connection, Direction, bool)>,
}
impl Connections {
    pub fn allocate(&mut self) -> Option<Connection> {
        self.sequence = self.sequence.checked_add(1)?;
        self.pending.insert(self.sequence);
        Some(Connection {
            issuer: self.issuer.clone(),
            sequence: self.sequence,
        })
    }
    pub fn abandon(&mut self, connection: &Connection) -> bool {
        Arc::ptr_eq(&self.issuer, &connection.issuer) && self.pending.remove(&connection.sequence)
    }
    pub fn is_current(&self, connection: &Connection) -> bool {
        Arc::ptr_eq(&self.issuer, &connection.issuer)
            && self
                .current
                .as_ref()
                .is_some_and(|(active, _, _)| active.sequence == connection.sequence)
    }
    pub fn established(&mut self, connection: &Connection) -> bool {
        if !self.is_current(connection) {
            return false;
        }
        if let Some((_, _, established)) = &mut self.current {
            *established = true;
        }
        true
    }
    pub fn closed(&mut self, connection: &Connection) -> bool {
        if !self.is_current(connection) {
            return false;
        }
        self.current = None;
        true
    }
    pub fn consider(
        &mut self,
        connection: Connection,
        direction: Direction,
        local: Ipv4Addr,
        peer: Ipv4Addr,
    ) -> Resolution {
        if !Arc::ptr_eq(&self.issuer, &connection.issuer)
            || !self.pending.remove(&connection.sequence)
        {
            return Resolution::Rejected;
        }
        if local == peer || local.is_unspecified() || peer.is_unspecified() {
            return Resolution::InvalidRouterId;
        }
        if let Some((current, current_direction, established)) = &self.current {
            if *established
                || current.sequence == connection.sequence
                || *current_direction == direction
            {
                return Resolution::Rejected;
            }
            let preferred = if u32::from(local) > u32::from(peer) {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
            if direction != preferred {
                return Resolution::Rejected;
            }
        }
        let displaced = self
            .current
            .replace((connection, direction, false))
            .map(|(old, _, _)| old);
        Resolution::Accepted { displaced }
    }
}
