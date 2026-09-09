//! Rust-only child process used by the harness integration tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]
use std::{
    io::{self, Write},
    time::Duration,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str).unwrap_or("") {
        "report" => {
            println!("cwd={}", std::env::current_dir().unwrap().display());
            println!(
                "value={}",
                std::env::var("FIXTURE_VALUE").unwrap_or_default()
            );
            println!("separator={}", std::env::var("/").is_ok());
            println!("path_separator={}", std::env::var(":").is_ok());
            println!("home={}", std::env::var("HOME").is_ok());
            println!(
                "args={}",
                args.iter().skip(1).cloned().collect::<Vec<_>>().join("|")
            );
            eprintln!("diagnostic");
        }
        "delayed-output" => {
            let delay = args.get(1).unwrap().parse::<u64>().unwrap();
            tokio::time::sleep(Duration::from_millis(delay)).await;
            println!("{}", args.get(2).unwrap());
            eprintln!("err:{}", args.get(2).unwrap());
        }
        "await-file" => {
            while !std::path::Path::new(args.get(1).unwrap()).exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        "bytes" => {
            let count = args.get(1).unwrap().parse::<usize>().unwrap();
            let chunk = [b'x'; 8192];
            for _ in 0..count {
                io::stdout().write_all(&chunk).unwrap();
            }
        }
        "exit" => std::process::exit(args.get(1).unwrap().parse().unwrap()),
        "sleep" => {
            std::fs::write(args.get(1).unwrap(), std::process::id().to_string()).unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        "interrupt" => {
            #[cfg(unix)]
            {
                let mut signal =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                        .unwrap();
                std::fs::write(args.get(1).unwrap(), std::process::id().to_string()).unwrap();
                signal.recv().await;
                std::fs::write(args.get(2).unwrap(), "interrupted").unwrap();
            }
        }
        "invalid-sleep" => {
            io::stdout().write_all(&[0xff]).unwrap();
            io::stdout().flush().unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        "spam" => {
            let chunk = [b'x'; 8192];
            for _ in 0..1025 {
                io::stdout().write_all(&chunk).unwrap();
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        "descendant" => {
            // Inherit output pipes and process group, then outlive the leader.
            #[allow(clippy::zombie_processes)]
            // Deliberate orphan exercised by the supervisor test.
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["sleep", args.get(1).unwrap()])
                .spawn()
                .unwrap();
            // This fixture intentionally exercises supervisor cleanup of a
            // descendant; the supervisor must kill it when this leader exits.
            drop(child);
            while !std::path::Path::new(args.get(1).unwrap()).exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        _ => std::process::exit(2),
    }
}
