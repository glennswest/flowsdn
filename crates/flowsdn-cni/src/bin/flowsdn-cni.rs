use std::{collections::BTreeMap, io::Read};
fn main() {
    let env: BTreeMap<String, String> = std::env::vars().collect();
    let mut input = Vec::new();
    let result = std::io::stdin().take(1_048_577).read_to_end(&mut input)
        .map_err(|e| flowsdn_cni::CniError::internal(e.to_string()))
        .and_then(|_| {
            if input.len() > 1_048_576 { return Err(flowsdn_cni::CniError::internal("CNI configuration exceeds 1 MiB")); }
            flowsdn_cni::runtime::run(env.get("CNI_COMMAND").map(String::as_str).unwrap_or(""), &input, &env)
        });
    match result {
        Ok(Some(value)) => println!("{value}"),
        Ok(None) => {}
        Err(error) => {
            let conf: serde_json::Value = serde_json::from_slice(&input).unwrap_or_default();
            println!("{}", error.json(conf["cniVersion"].as_str().unwrap_or("1.1.0")));
            std::process::exit(1);
        }
    }
}
