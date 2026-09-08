use crate::{Keyed, Table};
use std::{collections::BTreeSet, error::Error, fmt, sync::{Arc, Mutex}};
use tokio::sync::watch;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitializationError {
    EmptyName,
    DuplicateName(String),
    Sealed,
}

impl fmt::Display for InitializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => write!(f, "initializer name must not be blank"),
            Self::DuplicateName(name) => write!(f, "duplicate initializer: {name}"),
            Self::Sealed => write!(f, "initializer registration is sealed"),
        }
    }
}
impl Error for InitializationError {}

struct Registration {
    sealed: bool,
    names: BTreeSet<String>,
    pending: BTreeSet<String>,
}

pub(crate) struct Initialization {
    registration: Mutex<Registration>,
    ready: watch::Sender<bool>,
}

impl Initialization {
    pub(crate) fn new() -> Self {
        Self {
            registration: Mutex::new(Registration {
                sealed: false,
                names: BTreeSet::new(),
                pending: BTreeSet::new(),
            }),
            ready: watch::channel(false).0,
        }
    }
}

/// Completion capability for one registered data source. Call `complete()`
/// only after its initial population has been published to the table.
/// Dropping a handle leaves its initializer pending; cancellation is not success.
#[must_use = "keep the initializer handle until its data source completes initial sync"]
pub struct Initializer {
    name: String,
    initialization: Arc<Initialization>,
}

impl fmt::Debug for Initializer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Initializer").field("name", &self.name).finish_non_exhaustive()
    }
}

impl Initializer {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Mark this source complete. Returns true only for the first completion;
    /// repeated calls are harmless and never alter another source's status.
    pub fn complete(&self) -> bool {
        let mut registration = self.initialization.registration.lock().expect("initializer registry poisoned");
        let completed = registration.pending.remove(&self.name);
        if completed && registration.sealed && registration.pending.is_empty() {
            self.initialization.ready.send_replace(true);
        }
        completed
    }
}

impl<T: Keyed> Table<T> {
    /// Register a data source before sealing. Registration and sealing are
    /// serialized, so a racing registration either participates or returns
    /// `Sealed`; it cannot make an initialized table become uninitialized.
    pub fn register_initializer(&self, name: impl Into<String>) -> Result<Initializer, InitializationError> {
        let name = name.into();
        let mut registration = self.initialization.registration.lock().expect("initializer registry poisoned");
        if registration.sealed {
            return Err(InitializationError::Sealed);
        }
        if name.trim().is_empty() {
            return Err(InitializationError::EmptyName);
        }
        if !registration.names.insert(name.clone()) {
            return Err(InitializationError::DuplicateName(name));
        }
        registration.pending.insert(name.clone());
        Ok(Initializer { name, initialization: self.initialization.clone() })
    }

    /// Finish registration. Sealing is idempotent and required even when there
    /// are no sources. Readiness remains false before sealing, preventing a
    /// reconciler from pruning during construction's temporarily empty set.
    pub fn seal_initializers(&self) {
        let mut registration = self.initialization.registration.lock().expect("initializer registry poisoned");
        if !registration.sealed {
            registration.sealed = true;
            if registration.pending.is_empty() {
                self.initialization.ready.send_replace(true);
            }
        }
    }

    /// True only after registration is sealed and every source is complete.
    /// Once true, the result never becomes false.
    pub fn initialized(&self) -> bool {
        *self.initialization.ready.borrow()
    }

    /// Names still awaiting initial sync, in lexical order. An empty list
    /// alone does not imply readiness while registration remains open.
    pub fn pending_initializers(&self) -> Vec<String> {
        self.initialization.registration.lock().expect("initializer registry poisoned").pending.iter().cloned().collect()
    }

    /// Await sealed registration and completion of every initial population.
    /// Dropping this future cancels only this waiter; neither source progress
    /// nor other waiters are affected. No worker task is spawned.
    pub async fn wait_initialized(&self) {
        let mut ready = self.initialization.ready.subscribe();
        loop {
            if *ready.borrow_and_update() {
                return;
            }
            // This future borrows the table, keeping the sender alive.
            ready.changed().await.expect("table initialization sender dropped while borrowed");
        }
    }
}
