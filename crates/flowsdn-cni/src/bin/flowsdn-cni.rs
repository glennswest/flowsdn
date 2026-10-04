use std::{collections::BTreeMap, io::Read};
fn main() {
    // `flowsdn-cni install`: a CNI runtime never passes arguments, so an
    // argument is the node installer (copy the plugin, write the conflist).
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("install")) {
        let outcome = std::env::current_exe().and_then(|source| {
            flowsdn_cni::install::install_node(source, &std::env::vars_os().collect())
        });
        match outcome {
            Ok((report, conf)) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "installed": true,
                        "conflist": conf,
                        "plugin_replaced": report.plugin_replaced,
                        "loopback_replaced": report.loopback_replaced,
                        "warnings": report.warnings,
                    })
                );
                return;
            }
            Err(error) => {
                eprintln!("flowsdn-cni install: {error}");
                std::process::exit(1);
            }
        }
    }
    let env: BTreeMap<String, String> = std::env::vars().collect();
    let mut input = Vec::new();
    let result = std::io::stdin()
        .take(1_048_577)
        .read_to_end(&mut input)
        .map_err(|e| flowsdn_cni::CniError::internal(e.to_string()))
        .and_then(|_| {
            if input.len() > 1_048_576 {
                return Err(flowsdn_cni::CniError::internal(
                    "CNI configuration exceeds 1 MiB",
                ));
            }
            flowsdn_cni::loopback::dispatch(
                std::env::args_os().next().as_deref().unwrap_or_default(),
                env.get("CNI_COMMAND").map(String::as_str).unwrap_or(""),
                &input,
                &env,
            )
        });
    match result {
        Ok(Some(value)) => println!("{value}"),
        Ok(None) => {}
        Err(error) => {
            let conf: serde_json::Value = serde_json::from_slice(&input).unwrap_or_default();
            println!(
                "{}",
                error.json(
                    conf.get("cniVersion")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("1.1.0")
                )
            );
            std::process::exit(1);
        }
    }
}
