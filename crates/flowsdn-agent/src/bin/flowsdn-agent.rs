const HELP: &str = "flowsdn-agent — initial endpoint API daemon

Usage: flowsdn-agent --config PATH
       flowsdn-agent --help
       flowsdn-agent --version

Options:
  --config PATH  Read the standalone agent JSON configuration
  -h, --help     Print this help and exit
  -V, --version  Print the package version and exit

The API listens on the Unix socket configured by socket-path.
GET /v1/healthz reports initial API availability after state restoration.
It does not report complete pod-network readiness. Kubernetes and policy
controllers, an operator service, and a Hubble observer/relay are not provided
by this daemon.
";

fn main() -> flowsdn_agent::state::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--help" || flag == "-h" => {
            print!("{HELP}");
            Ok(())
        }
        [flag] if flag == "--version" || flag == "-V" => {
            println!("flowsdn-agent {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [flag, path] if flag == "--config" => flowsdn_agent::api::run(std::path::Path::new(path)),
        _ => Err("usage: flowsdn-agent --config PATH (use --help for options)".into()),
    }
}
