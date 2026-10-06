const HELP: &str = "flowsdn-agent — initial endpoint API daemon

Usage: flowsdn-agent --config PATH
       flowsdn-agent cni install --source PATH
       flowsdn-agent --help
       flowsdn-agent --version

Options:
  --config PATH  Read the standalone agent JSON configuration
  -h, --help     Print this help and exit
  -V, --version  Print the package version and exit

CNI installation reads HOST_PREFIX (default /host), CNI_DIR (default
$HOST_PREFIX/opt/cni), OVERWRITE_PLUGIN (default true), and
OVERWRITE_LOOPBACK (default false). It installs flowsdn-cni, flowsdn
and loopback from the supplied Rust CNI executable.

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
        [cni, install, flag, source]
            if cni == "cni" && install == "install" && flag == "--source" =>
        {
            let options = flowsdn_cni::install::InstallOptions::from_env(
                source.into(),
                &std::env::vars_os().collect(),
            );
            let report = flowsdn_cni::install::install(&options)?;
            for warning in report.warnings {
                eprintln!("warning: {warning}");
            }
            Ok(())
        }
        [flag, path] if flag == "--config" => flowsdn_agent::api::run(std::path::Path::new(path)),
        _ => Err("usage: flowsdn-agent --config PATH (use --help for options)".into()),
    }
}
