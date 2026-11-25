//! The fixture (spec 17 §3.5.1): what one script's agent instance holds.
//!
//! The reference builds a dependency-injection hive per script; ADR-0004
//! removes it. A `Fixture` holds the fakes that survive `hive/recreate` (the
//! Kubernetes API) and the components that do not, started in registration
//! order and stopped in reverse.
use crate::k8s::FakeClient;
use flowsdn_scripttest::{CommandError, Control, Engine, State};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// A hive cell's replacement: something with start and stop hooks.
pub trait Component: Send {
    fn name(&self) -> &str;
    fn start(&mut self) -> Result<(), String>;
    fn stop(&mut self) -> Result<(), String>;
}

/// Builds an area's components for one instance (again on `hive/recreate`,
/// with the replacement's flags).
pub type Components = Box<dyn Fn(&[String]) -> Result<Vec<Box<dyn Component>>, String> + Send>;

/// One script's agent instance.
pub struct Fixture {
    /// The fake Kubernetes API: retained across `hive/recreate`.
    pub k8s: Arc<Mutex<FakeClient>>,
    build: Components,
    components: Vec<Box<dyn Component>>,
    started: bool,
}

/// The fixture as the commands share it.
pub type Shared = Arc<Mutex<Fixture>>;

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
fn fail(message: impl Into<String>) -> CommandError {
    CommandError::Failure(message.into())
}

impl Fixture {
    pub fn new(k8s: FakeClient, flags: &[String], build: Components) -> Result<Self, String> {
        let components = build(flags)?;
        Ok(Self {
            k8s: Arc::new(Mutex::new(k8s)),
            build,
            components,
            started: false,
        })
    }
    /// `hive/start`: every component's start hook, in registration order.
    pub fn start(&mut self) -> Result<(), String> {
        if self.started {
            return Err("the agent instance is already started".into());
        }
        for component in &mut self.components {
            component
                .start()
                .map_err(|e| format!("start {}: {e}", component.name()))?;
        }
        self.started = true;
        Ok(())
    }
    /// `hive/stop`: stop hooks in reverse order.
    pub fn stop(&mut self) -> Result<(), String> {
        if !self.started {
            return Err("the agent instance is not started".into());
        }
        for component in self.components.iter_mut().rev() {
            component
                .stop()
                .map_err(|e| format!("stop {}: {e}", component.name()))?;
        }
        self.started = false;
        Ok(())
    }
    /// `hive/recreate`: a fresh instance with `flags`, keeping the fake
    /// Kubernetes API (spec 17 §3.5.3). The instance must be stopped.
    pub fn recreate(&mut self, flags: &[String]) -> Result<(), String> {
        if self.started {
            return Err("hive/recreate needs a stopped instance".into());
        }
        self.components = (self.build)(flags)?;
        Ok(())
    }
    /// The component names in start order (`hive` with no argument; spec
    /// 17 §3.3.2: flowsdn has no object graph to print, ADR-0004).
    pub fn describe(&self) -> String {
        let mut out = String::from("components (start order):\n");
        for component in &self.components {
            out.push_str(&format!("  {}\n", component.name()));
        }
        out
    }
}

/// Register `hive`, `hive/start`, `hive/stop` and `hive/recreate` (spec 17
/// §3.3.2) on `engine` for `fixture`.
pub fn register_hive(engine: &mut Engine, fixture: &Shared) -> Result<(), String> {
    let f = Arc::clone(fixture);
    engine.register_command("hive", false, move |state: &mut State, args: &[String]| {
        let mut fixture = lock(&f);
        match args.first().map(String::as_str) {
            None => {
                let text = fixture.describe();
                state.publish(text, "");
                Ok(Control::Continue)
            }
            Some("start") => fixture.start().map(|()| Control::Continue).map_err(fail),
            Some("stop") => fixture.stop().map(|()| Control::Continue).map_err(fail),
            Some(other) => Err(fail(format!("hive: unknown argument {other}"))),
        }
    })?;
    let f = Arc::clone(fixture);
    engine.register_command("hive/start", false, move |_: &mut State, _: &[String]| {
        lock(&f).start().map(|()| Control::Continue).map_err(fail)
    })?;
    let f = Arc::clone(fixture);
    engine.register_command("hive/stop", false, move |_: &mut State, _: &[String]| {
        lock(&f).stop().map(|()| Control::Continue).map_err(fail)
    })?;
    let f = Arc::clone(fixture);
    engine.register_command(
        "hive/recreate",
        false,
        move |_: &mut State, args: &[String]| {
            lock(&f)
                .recreate(args)
                .map(|()| Control::Continue)
                .map_err(fail)
        },
    )?;
    Ok(())
}
