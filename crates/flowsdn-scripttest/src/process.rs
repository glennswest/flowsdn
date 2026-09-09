//! Foreground child supervision. Executables have the caller's OS permissions;
//! directory capabilities confine fixture operations, not arbitrary child code.
use crate::{CommandError, Control, State};
use std::time::Duration;
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
    async fn cancelled(&self) {
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
        linux::execute(state, args, options).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, args);
        Err(failure("foreground exec currently requires Linux"))
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
    struct Output {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        result: Result<(), CommandError>,
    }

    pub(super) async fn execute(
        state: &mut State,
        args: &[String],
        options: &RunOptions,
    ) -> Result<Control, CommandError> {
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
        // This task owns the child even when the caller drops its run future.
        tokio::spawn(async move {
            let _directory = directory;
            let _workspace = workspace;
            supervise(process, pid, options, sender).await;
        });
        let output = receiver
            .await
            .map_err(|_| failure("child supervisor terminated"))?;
        let stdout = String::from_utf8(output.stdout);
        let stderr = String::from_utf8(output.stderr);
        match (stdout, stderr) {
            (Ok(stdout), Ok(stderr)) => state.publish(stdout, stderr),
            _ => {
                // Cancellation and output limits must not become ordinary,
                // negatable failures just because partial UTF-8 was captured.
                output.result?;
                return Err(failure("exec output is not UTF-8"));
            }
        }
        output.result?;
        Ok(Control::Continue)
    }

    async fn read_output(
        mut stream: impl AsyncRead + Unpin,
        bytes: &mut Vec<u8>,
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
        sender: &mut oneshot::Sender<Output>,
    ) -> CommandError {
        tokio::select! {
            biased;
            _ = options.cancellation.cancelled() => CommandError::Cancelled,
            _ = tokio::time::sleep_until(options.deadline) => CommandError::Deadline,
            _ = sender.closed() => CommandError::Cancelled,
        }
    }

    async fn supervise(
        mut process: Process,
        pid: Pid,
        options: RunOptions,
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
                    read_output(stdout_pipe, &mut stdout),
                    read_output(stderr_pipe, &mut stderr)
                )
                .map(|_| ())
            };
            tokio::pin!(capture);
            let mut captured = false;
            result = tokio::select! {
                biased;
                error = interrupted(&options, &mut sender) => Err(error),
                output = &mut capture => {
                    captured = true;
                    match output {
                        Err(error) => Err(error),
                        Ok(()) => tokio::select! {
                            biased;
                            error = interrupted(&options, &mut sender) => Err(error),
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
                    Ok(Err(error)) if result.is_ok() => result = Err(error),
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
}
