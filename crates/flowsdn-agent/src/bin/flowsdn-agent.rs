fn main() -> flowsdn_agent::state::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag, path] if flag == "--config" => flowsdn_agent::api::run(std::path::Path::new(path)),
        _ => Err("usage: flowsdn-agent --config PATH".into()),
    }
}
