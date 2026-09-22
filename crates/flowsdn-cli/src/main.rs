#![forbid(unsafe_code)]
#[cfg(unix)]
fn run()->Result<(),String> {
    let args=std::env::args().skip(1).collect::<Vec<_>>();
    if args.as_slice()==["--help"] {println!("flowsdn-cli clustermesh connect --bundle FILE --config-dir DIRECTORY [--replace] [--dry-run]\nImport a provisioned offline peer bundle; no Kubernetes access or TLS handshake.");return Ok(());}
    if args.first().map(String::as_str)!=Some("clustermesh") || args.get(1).map(String::as_str)!=Some("connect") {return Err("expected clustermesh connect (see --help)".into());}
    let mut bundle=None;let mut directory=None;let mut replace=false;let mut dry_run=false;
    let mut args=args.iter().skip(2);
    while let Some(arg)=args.next() {match arg.as_str() {
        "--bundle" if bundle.is_none()=>bundle=Some(args.next().ok_or("missing --bundle value")?),
        "--config-dir" if directory.is_none()=>directory=Some(args.next().ok_or("missing --config-dir value")?),
        "--replace" if !replace=>replace=true,"--dry-run" if !dry_run=>dry_run=true,
        _=>return Err("unknown or repeated option (see --help)".into()),
    }}
    let bundle=flowsdn_clustermesh::bootstrap::Bundle::read(std::path::Path::new(bundle.ok_or("--bundle is required")?)).map_err(|error|error.to_string())?;
    flowsdn_clustermesh::bootstrap::install(&bundle,std::path::Path::new(directory.ok_or("--config-dir is required")?),replace,dry_run).map_err(|error|error.to_string())?;
    println!("{} peer {}",if dry_run {"Validated"}else{"Installed"},bundle.cluster());Ok(())
}
#[cfg(not(unix))]
fn run()->Result<(),String>{Err("offline peer installation requires Unix filesystem permissions".into())}
fn main(){if let Err(error)=run(){eprintln!("flowsdn-cli: {error}");std::process::exit(1);}}
