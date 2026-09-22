use flowsdn_clustermesh::{principal::Bindings,prefixes::{Role,Rpc}};
fn bindings()->Bindings { Bindings::new("west",[("local-west".into(),Role::Local),("remote-east".into(),Role::Remote)]).expect("bindings") }
#[test]
fn verified_principals_bind_exactly_and_cannot_cross_authorities() {
    let own=bindings();
    for names in [vec![],vec!["unknown"],vec!["remote-east","local-west"],vec!["Remote-east"]] { assert!(own.bind_verified_certificate(&names).is_err()); }
    let remote=own.bind_verified_certificate(&["remote-east"]).expect("verified remote");
    assert!(own.permits(&remote,Rpc::Range,b"cilium/cluster-config/west",None));
    assert!(!own.permits(&remote,Rpc::Range,b"cilium/cache/west/a",None));
    assert!(!own.permits(&remote,Rpc::Range,b"cilium/cluster-config/east",None));
    assert!(!own.permits(&remote,Rpc::Range,b"cilium/state/a",Some(b"cilium/state1")));
    for rpc in [Rpc::Put,Rpc::Delete,Rpc::Txn,Rpc::Lease,Rpc::Auth,Rpc::Other] { assert!(!own.permits(&remote,rpc,b"cilium/state/a",None)); }
    assert!(!bindings().permits(&remote,Rpc::Range,b"cilium/state/a",None));
}
#[test]
fn binding_replacement_is_atomic_and_revokes_existing_sessions() {
    let mut own=bindings(); let local=own.bind_verified_certificate(&["local-west"]).expect("local");
    assert!(own.permits(&local,Rpc::Watch,b"cilium/cache/west/a",None));
    assert!(own.replace([("same".into(),Role::Local),("same".into(),Role::Remote)]).is_err());
    assert!(own.permits(&local,Rpc::Range,b"cilium/cache/west/a",None));
    own.replace([("remote-east".into(),Role::Remote)]).expect("remove local");
    assert!(!own.permits(&local,Rpc::Watch,b"cilium/cache/west/a",None));
}
