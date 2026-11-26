# flowsdn-kvstore

flowsdn's kvstore client (spec 20 §3.1–3.5, §5; #567).

- `Kvstore`: the client trait of §3.1, plus `txn` and `lease_for` for the cluster-config ownership claim (§12 decision 9).
- `memory::MemoryBackend`: an in-process store with etcd's revision and lease model. Several clients can share one
  `MemoryStore`. Unit tests and the scripttest harness use it.
- `etcd::EtcdBackend`: flowsdn's own etcd v3 client for the RPCs of §2.6.
  - Messages are hand-written `prost` structs with etcd's field numbers; there is no protoc and no generated code.
  - gRPC framing runs over `h2`. TLS uses Fedora system OpenSSL (ADR-0016), and the certificate files are re-read on
    every dial.
  - Also: rate limiter, key and lock leases with keepalive and loss observers, paginated list, watch with relist and
    resync, a client-side lock, and the status checker.
- `sync_store::SyncStore`: one-way export with synced canaries (§3.4.2).

`tests/fastetcd.rs` runs the etcd backend against a live fastetcd, in plain and mTLS mode, when `FASTETCD_BIN` names
the binary.

Not built: host aliases and Service resolution in the dialer, HTTP/2 keepalive pings, the remote-cluster status mode,
and the 30 s local-lock GC (see spec 20's #567 amendment).
