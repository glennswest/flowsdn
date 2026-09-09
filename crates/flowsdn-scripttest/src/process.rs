//! Child supervision for foreground and background execution. Executables have the caller's OS permissions;
//! directory capabilities confine fixture operations, not arbitrary child code.
use crate::{CommandError, Control, State, Status};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::{sync::watch, time::Instant};

const MAX_OUTPUT: usize = 8_388_608;

#[derive(Clone, Debug)]
pub struct Cancellation(watch::Sender<bool>);
impl Default for Cancellation {
    fn default() -> Self {
        Self(watch::channel(false).0)
    }
}
impl Cancellation {
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }
    pub(crate) async fn cancelled(&self) {
        let mut receiver = self.0.subscribe();
        let _ = receiver.wait_for(|cancelled| *cancelled).await;
    }
}

#[derive(Clone, Debug)]
pub struct RunOptions {
    pub cancellation: Cancellation,
    pub deadline: Instant,
    /// SIGINT-to-SIGKILL interval, default 100 ms. Cleanup also runs on drop.
    pub grace: Duration,
    /// Whole-section replay backoff; must be nonzero and no greater than the cap.
    pub retry_interval: Duration,
    pub max_retry_interval: Duration,
}
impl Default for RunOptions {
    fn default() -> Self {
        Self::with_timeout(Duration::from_secs(60)).expect("default timeout fits an Instant")
    }
}
impl RunOptions {
    pub fn with_timeout(timeout: Duration) -> Result<Self, CommandError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| failure("timeout exceeds the clock range"))?;
        Ok(Self {
            cancellation: Cancellation::default(),
            deadline,
            grace: Duration::from_millis(100),
            retry_interval: Duration::from_millis(100),
            max_retry_interval: Duration::from_millis(500),
        })
    }
    pub(crate) fn check(&self) -> Result<(), CommandError> {
        if self.cancellation.is_cancelled() {
            Err(CommandError::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(CommandError::Deadline)
        } else {
            Ok(())
        }
    }
}

fn failure(error: impl std::fmt::Display) -> CommandError {
    CommandError::Failure(error.to_string())
}

pub(crate) async fn execute(
    state: &mut State,
    args: &[String],
    options: &RunOptions,
) -> Result<Control, CommandError> {
    options.check()?;
    #[cfg(target_os = "linux")]
    {
        let output = linux::launch(state, args, options, None)?
            .receiver
            .await
            .map_err(|_| failure("child supervisor terminated"))?;
        let output = decode(output);
        state.publish(output.stdout, output.stderr);
        output.result?;
        Ok(Control::Continue)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, args);
        Err(failure("foreground exec currently requires Linux"))
    }
}

struct Output {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    result: Result<(), CommandError>,
}
struct Decoded {
    stdout: String,
    stderr: String,
    result: Result<(), CommandError>,
}
fn decode(output: Output) -> Decoded {
    match (
        String::from_utf8(output.stdout),
        String::from_utf8(output.stderr),
    ) {
        (Ok(stdout), Ok(stderr)) => Decoded {
            stdout,
            stderr,
            result: output.result,
        },
        _ => Decoded {
            stdout: String::new(),
            stderr: String::new(),
            // Keep nonmaskable errors ahead of malformed captured UTF-8.
            result: output
                .result
                .and_then(|_| Err(failure("exec output is not UTF-8"))),
        },
    }
}
struct Pending {
    receiver: oneshot::Receiver<Output>,
    cancellation: Cancellation,
    replay_cancelled: Arc<AtomicBool>,
}
struct Job {
    id: usize,
    line: usize,
    status: Status,
    pending: Result<Pending, CommandError>,
}
#[derive(Default)]
pub(crate) struct Jobs {
    jobs: Vec<Job>,
    budget: Arc<AtomicUsize>,
    next_id: usize,
}
impl Jobs {
    pub(crate) fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
    pub(crate) fn start(
        &mut self,
        state: &State,
        args: &[String],
        options: &RunOptions,
        line: usize,
        status: Status,
    ) -> Result<(), CommandError> {
        if self.jobs.len() >= 32 {
            return Err(CommandError::LimitExceeded(
                "background job limit of 32 exceeded",
            ));
        }
        options.check()?;
        #[cfg(target_os = "linux")]
        let pending = linux::launch(state, args, options, Some(self.budget.clone()));
        #[cfg(not(target_os = "linux"))]
        let pending = {
            let _ = (state, args);
            Err(failure("exec requires Linux"))
        };
        self.jobs.push(Job {
            id: self.next_id,
            line,
            status,
            pending,
        });
        self.next_id = self.next_id.saturating_add(1);
        Ok(())
    }
    pub(crate) fn checkpoint(&self) -> usize { self.next_id }
    pub(crate) async fn discard_attempt(&mut self, checkpoint: usize, options: &RunOptions) -> Result<(), CommandError> {
        let index = self.jobs.iter().position(|job| job.id >= checkpoint).unwrap_or(self.jobs.len());
        let discarded = self.jobs.split_off(index);
        for job in &discarded {
            if let Ok(pending) = &job.pending {
                pending.replay_cancelled.store(true, Ordering::Relaxed);
                pending.cancellation.cancel();
            }
        }
        let mut errors = String::new();
        let mut fatal = false;
        for job in discarded {
            let output = match job.pending {
                Ok(pending) => pending.receiver.await.unwrap_or_else(|_| Output {
                    stdout: Vec::new(), stderr: Vec::new(), result: Err(CommandError::ProcessOwnershipLost),
                }),
                Err(error) => Output { stdout: Vec::new(), stderr: Vec::new(), result: Err(error) },
            };
            self.budget.fetch_sub(output.stdout.len().saturating_add(output.stderr.len()), Ordering::Relaxed);
            let output = decode(output);
            match output.result {
                Ok(()) if job.status == Status::Failure => join_error(&mut errors, &mut fatal, job.line, failure("unexpected background success during retry cleanup")),
                Ok(()) | Err(CommandError::ReplayCancelled) => {},
                Err(CommandError::Failure(_)) if matches!(job.status, Status::Failure | Status::SuccessOrFailure) => {},
                Err(error) => join_error(&mut errors, &mut fatal, job.line, error),
            }
        }
        options.check()?;
        if errors.is_empty() { Ok(()) } else { Err(CommandError::BackgroundFailure(errors)) }
    }
    pub(crate) fn cancel(&self) {
        for job in &self.jobs {
            if let Ok(pending) = &job.pending {
                pending.cancellation.cancel();
            }
        }
    }
    pub(crate) async fn wait(&mut self, state: &mut State) -> Result<Control, CommandError> {
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut errors = String::new();
        let mut fatal = false;
        // The owned iterator retains every remaining receiver across awaits;
        // dropping it triggers cleanup for jobs that have not been drained.
        let mut pending_jobs = std::mem::take(&mut self.jobs).into_iter();
        while let Some(job) = pending_jobs.next() {
            let output = match job.pending {
                Ok(pending) => pending.receiver.await.unwrap_or_else(|_| Output {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    result: Err(CommandError::ProcessOwnershipLost),
                }),
                Err(error) => Output {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    result: Err(error),
                },
            };
            let output = decode(output);
            // Capture reserves the shared budget before allocating; this check
            // also protects aggregation if a future command supplies output.
            if stdout
                .len()
                .saturating_add(stderr.len())
                .saturating_add(output.stdout.len())
                .saturating_add(output.stderr.len())
                > MAX_OUTPUT
            {
                join_error(
                    &mut errors,
                    &mut fatal,
                    job.line,
                    CommandError::LimitExceeded("background output exceeds 8 MiB combined limit"),
                );
            } else {
                stdout.push_str(&output.stdout);
                stderr.push_str(&output.stderr);
            }
            for (name, text) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
                if !text.is_empty()
                    && let Err(error) =
                        crate::engine::record_log(&mut state.log, &output_log(job.line, name, text))
                {
                    join_error(&mut errors, &mut fatal, job.line, error);
                }
            }
            match output.result {
                Ok(()) if job.status == Status::Failure => join_error(
                    &mut errors,
                    &mut fatal,
                    job.line,
                    failure("unexpected success"),
                ),
                Ok(()) => {}
                Err(CommandError::Failure(message))
                    if matches!(job.status, Status::Failure | Status::SuccessOrFailure) =>
                {
                    if let Err(error) = crate::engine::record_log(
                        &mut state.log,
                        &format!("line {}: expected failure: {message}", job.line),
                    ) {
                        join_error(&mut errors, &mut fatal, job.line, error);
                    }
                }
                Err(error) => join_error(&mut errors, &mut fatal, job.line, error),
            }
            if fatal {
                for job in pending_jobs.as_slice() {
                    if let Ok(pending) = &job.pending {
                        pending.cancellation.cancel();
                    }
                }
            }
        }
        self.budget = Arc::default();
        state.publish(stdout, stderr);
        if errors.is_empty() {
            Ok(Control::Continue)
        } else if fatal {
            Err(CommandError::BackgroundFailure(errors))
        } else {
            Err(CommandError::Failure(errors))
        }
    }
}
fn output_log(line: usize, name: &str, text: &str) -> String {
    let mut end = text.len().min(32_768);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let suffix = if end < text.len() {
        "\n[output log truncated]"
    } else {
        ""
    };
    format!(
        "line {line}: [{name}]\n{}{suffix}",
        text.get(..end).expect("UTF-8 boundary")
    )
}
fn join_error(errors: &mut String, fatal: &mut bool, line: usize, error: CommandError) {
    *fatal |= !matches!(error, CommandError::Failure(_));
    let message = format!("line {line}: {error}\n");
    if errors.len().saturating_add(message.len()) <= 60_000 {
        errors.push_str(&message);
    } else if !errors.ends_with("background diagnostics exceeded limit\n") {
        *fatal = true;
        errors.push_str("background diagnostics exceeded limit\n");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
    use std::{os::fd::AsRawFd, path::PathBuf, process::Stdio};
    use tokio::{
        io::{AsyncRead, AsyncReadExt},
        process::{Child, Command},
        sync::oneshot,
    };

    struct Process {
        child: Child,
        group: Option<Pid>,
    }
    impl Drop for Process {
        fn drop(&mut self) {
            if let Some(group) = self.group.take()
                && !matches!(
                    waitid(
                        WaitId::Pid(group),
                        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT
                    ),
                    Err(rustix::io::Errno::CHILD)
                )
            {
                let _ = kill_process_group(group, Signal::KILL);
                let _ = self.child.start_kill();
            }
        }
    }
    pub(super) fn launch(
        state: &State,
        args: &[String],
        options: &RunOptions,
        budget: Option<Arc<AtomicUsize>>,
    ) -> Result<Pending, CommandError> {
        let (program, arguments) = args
            .split_first()
            .ok_or_else(|| failure("exec requires a program"))?;
        let (directory, workspace) = state.process_directory()?;
        let cwd = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        // Resolve PATH ourselves: missing script PATH must not use a host default.
        let program = if program.contains('/') {
            let path = PathBuf::from(program);
            if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            }
        } else {
            let path = state.environment.get("PATH").ok_or_else(|| {
                failure("exec requires an explicit script PATH for bare program names")
            })?;
            path.split(':')
                .map(|part| {
                    let directory = PathBuf::from(part);
                    if directory.is_absolute() {
                        directory.join(program)
                    } else {
                        cwd.join(directory).join(program)
                    }
                })
                .find(|path| {
                    use std::os::unix::fs::PermissionsExt;
                    path.metadata().is_ok_and(|metadata| {
                        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                    })
                })
                .ok_or_else(|| failure("exec program was not found on script PATH"))?
        };
        let mut command = Command::new(program);
        command
            .args(arguments)
            .current_dir(&cwd)
            .env_clear()
            .envs(
                state
                    .environment
                    .iter()
                    .filter(|(name, _)| name.as_str() != "/" && name.as_str() != ":"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let child = command.spawn().map_err(failure)?;
        let pid = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(Pid::from_raw)
            .ok_or_else(|| failure("child has no process identity"))?;
        let process = Process {
            child,
            group: Some(pid),
        };
        let (sender, receiver) = oneshot::channel();
        let options = options.clone();
        let cancellation = Cancellation::default();
        let task_cancellation = cancellation.clone();
        let replay_cancelled = Arc::new(AtomicBool::new(false));
        let task_replay = replay_cancelled.clone();
        // This task owns the child even when the caller drops its run future.
        tokio::spawn(async move {
            let _directory = directory;
            let _workspace = workspace;
            supervise(process, pid, options, task_cancellation, task_replay, budget, sender).await;
        });
        Ok(Pending {
            receiver,
            cancellation,
            replay_cancelled,
        })
    }

    async fn read_output(
        mut stream: impl AsyncRead + Unpin,
        bytes: &mut Vec<u8>,
        budget: &Option<Arc<AtomicUsize>>,
    ) -> Result<(), CommandError> {
        let mut chunk = [0u8; 8192];
        loop {
            let count = stream.read(&mut chunk).await.map_err(failure)?;
            if count == 0 {
                return Ok(());
            }
            if bytes.len().saturating_add(count) > MAX_OUTPUT {
                return Err(CommandError::LimitExceeded(
                    "exec output exceeds 8 MiB per stream",
                ));
            }
            if let Some(budget) = budget {
                budget
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                        used.checked_add(count).filter(|total| *total <= MAX_OUTPUT)
                    })
                    .map_err(|_| {
                        CommandError::LimitExceeded(
                            "background output exceeds 8 MiB combined limit",
                        )
                    })?;
            }
            bytes.extend_from_slice(chunk.get(..count).expect("read count fits buffer"));
        }
    }

    async fn exited(pid: Pid) -> Result<(), CommandError> {
        loop {
            // Observe without reaping, reserving PID/PGID until all signals end.
            match waitid(
                WaitId::Pid(pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            ) {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => tokio::time::sleep(Duration::from_millis(5)).await,
                Err(error) if error == rustix::io::Errno::INTR => continue,
                Err(error) => return Err(failure(error)),
            }
        }
    }

    async fn interrupted(
        options: &RunOptions,
        cancellation: &Cancellation,
        replay_cancelled: &AtomicBool,
        sender: &mut oneshot::Sender<Output>,
    ) -> CommandError {
        tokio::select! {
            biased;
            _ = options.cancellation.cancelled() => CommandError::Cancelled,
            _ = tokio::time::sleep_until(options.deadline) => CommandError::Deadline,
            _ = cancellation.cancelled() => if replay_cancelled.load(Ordering::Relaxed) { CommandError::ReplayCancelled } else { CommandError::Cancelled },
            _ = sender.closed() => CommandError::Cancelled,
        }
    }

    fn preserve_capture_failure(result: &mut Result<(), CommandError>, error: CommandError) {
        if result.is_ok()
            || (matches!(result, Err(CommandError::ReplayCancelled))
                && !matches!(error, CommandError::Failure(_))) {
            *result = Err(error);
        }
    }

    async fn supervise(
        mut process: Process,
        pid: Pid,
        options: RunOptions,
        cancellation: Cancellation,
        replay_cancelled: Arc<AtomicBool>,
        budget: Option<Arc<AtomicUsize>>,
        mut sender: oneshot::Sender<Output>,
    ) {
        let Some(stdout_pipe) = process.child.stdout.take() else {
            return;
        };
        let Some(stderr_pipe) = process.child.stderr.take() else {
            return;
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut result;
        {
            let capture = async {
                tokio::try_join!(
                    read_output(stdout_pipe, &mut stdout, &budget),
                    read_output(stderr_pipe, &mut stderr, &budget)
                )
                .map(|_| ())
            };
            tokio::pin!(capture);
            let mut captured = false;
            result = tokio::select! {
                biased;
                error = interrupted(&options, &cancellation, &replay_cancelled, &mut sender) => Err(error),
                output = &mut capture => {
                    captured = true;
                    match output {
                        Err(error) => Err(error),
                        Ok(()) => tokio::select! {
                            biased;
                            error = interrupted(&options, &cancellation, &replay_cancelled, &mut sender) => Err(error),
                            exited = exited(pid) => exited,
                        },
                    }
                }
                exited = exited(pid) => exited,
            };
            // A foreign child reaper or SIGCHLD disposition may have consumed
            // ownership. Never signal a numeric process group after ECHILD.
            if matches!(
                waitid(
                    WaitId::Pid(pid),
                    WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT
                ),
                Err(rustix::io::Errno::CHILD)
            ) {
                process.group = None;
                result = Err(CommandError::ProcessOwnershipLost);
            }
            if result.is_err() && process.group.is_some() {
                let _ = kill_process_group(pid, Signal::INT);
                // Bound a caller-provided grace so dropping a future cannot
                // leave a detached cleanup task running indefinitely.
                tokio::time::sleep(options.grace.min(Duration::from_secs(5))).await;
            }
            // Leader remains unreaped: the group identifier cannot be reused.
            // Also remove descendants whose parent exited while pipes stayed open.
            if process.group.is_some() {
                // Repeat after grace: another reaper may have raced the wait.
                if matches!(
                    waitid(
                        WaitId::Pid(pid),
                        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT
                    ),
                    Err(rustix::io::Errno::CHILD)
                ) {
                    result = Err(CommandError::ProcessOwnershipLost);
                } else {
                    let _ = kill_process_group(pid, Signal::KILL);
                }
                process.group = None;
            }
            let status = process.child.wait().await.map_err(failure);
            if result.is_ok() {
                result = status.and_then(|status| {
                    if status.success() {
                        Ok(())
                    } else {
                        Err(failure(format!("process exited with {status}")))
                    }
                });
            }
            if !captured {
                match tokio::time::timeout(Duration::from_millis(100), &mut capture).await {
                    Ok(Err(error)) => preserve_capture_failure(&mut result, error),
                    Err(_) if result.is_ok() => {
                        result = Err(failure("child output pipes remained open after cleanup"))
                    }
                    _ => {}
                }
            }
        }
        let _ = sender.send(Output {
            stdout,
            stderr,
            result,
        });
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn fatal_capture_errors_override_internal_replay_cancellation() {
            let mut result = Err(CommandError::ReplayCancelled);
            preserve_capture_failure(&mut result, CommandError::LimitExceeded("output budget"));
            assert_eq!(result, Err(CommandError::LimitExceeded("output budget")));
            let mut result = Err(CommandError::ReplayCancelled);
            preserve_capture_failure(&mut result, failure("closed pipe"));
            assert_eq!(result, Err(CommandError::ReplayCancelled));
            let mut result = Err(CommandError::Deadline);
            preserve_capture_failure(&mut result, CommandError::LimitExceeded("output budget"));
            assert_eq!(result, Err(CommandError::Deadline));
        }
    }


}
