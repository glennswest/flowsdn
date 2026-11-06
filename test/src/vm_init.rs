//! `/test` as PID 1 of `cargo xtask kernel-check`'s guest: the commit's suites
//! on a real kernel inside a build VM's qemu, where the job has no root of its
//! own (#292, #370). The initramfs is `/test`'s image tree and nothing mounts
//! it up: this sets up what a pod's runtime would have, runs the suite named
//! on the kernel command line as a child, and powers off. The result is the
//! line `@@FLOWSDN-EXIT <code>` on the console, since a guest's exit status
//! does not reach qemu's.
use nix::{
    mount::{MsFlags, mount},
    sys::{
        reboot::{RebootMode, reboot},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use std::{fs, path::Path, process::Command, thread, time::Duration};

/// A failed fixture's log is cut to its last lines on the console.
const LOG_TAIL: usize = 120;

/// `flowsdn.suite=<suite>` on a kernel command line, defaulting to medium.
pub fn suite_of(cmdline: &str) -> &str {
    cmdline
        .split_whitespace()
        .find_map(|word| word.strip_prefix("flowsdn.suite="))
        .unwrap_or("medium")
}

fn mount_fs(kind: &str, target: &str) {
    let _ = fs::create_dir_all(target);
    let flags = MsFlags::MS_NOSUID;
    if let Err(e) = mount(Some(kind), target, Some(kind), flags, None::<&str>) {
        println!("vm-init: mount {kind} on {target}: {e}");
    }
}

fn dump_logs(results: &Path) {
    let Ok(entries) = fs::read_dir(results) else {
        return;
    };
    let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let text = fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let skip = lines.len().saturating_sub(LOG_TAIL);
        println!("@@FLOWSDN-LOG {} ({} lines)", path.display(), lines.len());
        for line in lines.iter().skip(skip) {
            println!("{line}");
        }
    }
}

/// Wait for the suite while reaping whatever is orphaned to PID 1.
fn wait_for(suite: Pid) -> i32 {
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
            Ok(WaitStatus::Exited(pid, code)) if pid == suite => return code,
            Ok(WaitStatus::Signaled(pid, signal, _)) if pid == suite => {
                println!("vm-init: the suite died of {signal:?}");
                return 2;
            }
            Ok(_) => {}
            Err(e) => {
                println!("vm-init: waitpid: {e}");
                return 2;
            }
        }
    }
}

pub fn run() -> ! {
    mount_fs("proc", "/proc");
    mount_fs("sysfs", "/sys");
    mount_fs("devtmpfs", "/dev");
    mount_fs("bpf", "/sys/fs/bpf");
    mount_fs("cgroup2", "/sys/fs/cgroup");
    mount_fs("tmpfs", "/run");
    mount_fs("tmpfs", "/tmp");
    let _ = fs::create_dir_all("/results");
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let suite = suite_of(&cmdline);
    let code = match Command::new("/test")
        .arg(suite)
        .env("PATH", "/usr/sbin:/usr/bin")
        .env("TMPDIR", "/tmp")
        .spawn()
    {
        Ok(child) => {
            let pid = i32::try_from(child.id()).unwrap_or(-1);
            wait_for(Pid::from_raw(pid))
        }
        Err(e) => {
            println!("vm-init: cannot start the suite: {e}");
            2
        }
    };
    if code != 0 {
        dump_logs(Path::new("/results"));
        // A module that did not load is the usual cause of a failed setup.
        println!("@@FLOWSDN-LOG /proc/modules");
        println!(
            "{}",
            fs::read_to_string("/proc/modules").unwrap_or_default()
        );
    }
    println!("@@FLOWSDN-EXIT {code}");
    // Give the serial port's buffer a moment before the machine is gone.
    thread::sleep(Duration::from_millis(200));
    let _ = reboot(RebootMode::RB_POWER_OFF);
    // PID 1 may not exit: the kernel would panic over the result already sent.
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod tests {
    use super::suite_of;

    #[test]
    fn the_suite_comes_from_the_command_line() {
        assert_eq!(suite_of("console=ttyS0 flowsdn.suite=short quiet"), "short");
        assert_eq!(suite_of("console=ttyS0 quiet"), "medium");
        assert_eq!(suite_of(""), "medium");
    }
}
