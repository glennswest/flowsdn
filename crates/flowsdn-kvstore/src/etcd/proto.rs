//! Hand-written etcd v3 messages for the RPCs of spec 20 §2.6, with etcd's
//! field numbers (`rpc.proto`, `kv.proto`). Enums are carried as `int32`
//! (wire-identical to proto3 enums); their values are the constants below.
//! No nested `Txn`, no sort orders, no revision filters (§2.6).

/// `Event.type`: PUT.
pub const EVENT_PUT: i32 = 0;
/// `Event.type`: DELETE.
pub const EVENT_DELETE: i32 = 1;

/// `Compare.result`: EQUAL.
pub const RESULT_EQUAL: i32 = 0;
/// `Compare.result`: GREATER.
pub const RESULT_GREATER: i32 = 1;
/// `Compare.result`: LESS.
pub const RESULT_LESS: i32 = 2;
/// `Compare.result`: NOT_EQUAL.
pub const RESULT_NOT_EQUAL: i32 = 3;

/// `Compare.target`: VERSION.
pub const TARGET_VERSION: i32 = 0;
/// `Compare.target`: CREATE.
pub const TARGET_CREATE: i32 = 1;
/// `Compare.target`: MOD.
pub const TARGET_MOD: i32 = 2;
/// `Compare.target`: VALUE.
pub const TARGET_VALUE: i32 = 3;
/// `Compare.target`: LEASE.
pub const TARGET_LEASE: i32 = 4;

/// `etcdserverpb.ResponseHeader`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ResponseHeader {
    #[prost(uint64, tag = "1")]
    pub cluster_id: u64,
    #[prost(uint64, tag = "2")]
    pub member_id: u64,
    #[prost(int64, tag = "3")]
    pub revision: i64,
    #[prost(uint64, tag = "4")]
    pub raft_term: u64,
}

/// `mvccpb.KeyValue`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct KeyValue {
    #[prost(bytes = "vec", tag = "1")]
    pub key: Vec<u8>,
    #[prost(int64, tag = "2")]
    pub create_revision: i64,
    #[prost(int64, tag = "3")]
    pub mod_revision: i64,
    #[prost(int64, tag = "4")]
    pub version: i64,
    #[prost(bytes = "vec", tag = "5")]
    pub value: Vec<u8>,
    #[prost(int64, tag = "6")]
    pub lease: i64,
}

/// `mvccpb.Event`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Event {
    /// [`EVENT_PUT`] or [`EVENT_DELETE`].
    #[prost(int32, tag = "1")]
    pub kind: i32,
    #[prost(message, optional, tag = "2")]
    pub kv: Option<KeyValue>,
    #[prost(message, optional, tag = "3")]
    pub prev_kv: Option<KeyValue>,
}

/// `etcdserverpb.RangeRequest` (no sort, no revision filters, §2.6).
#[derive(Clone, PartialEq, prost::Message)]
pub struct RangeRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub range_end: Vec<u8>,
    #[prost(int64, tag = "3")]
    pub limit: i64,
    #[prost(int64, tag = "4")]
    pub revision: i64,
    #[prost(int32, tag = "5")]
    pub sort_order: i32,
    #[prost(int32, tag = "6")]
    pub sort_target: i32,
    #[prost(bool, tag = "7")]
    pub serializable: bool,
    #[prost(bool, tag = "8")]
    pub keys_only: bool,
    #[prost(bool, tag = "9")]
    pub count_only: bool,
}

/// `etcdserverpb.RangeResponse`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RangeResponse {
    #[prost(message, optional, tag = "1")]
    pub header: Option<ResponseHeader>,
    #[prost(message, repeated, tag = "2")]
    pub kvs: Vec<KeyValue>,
    #[prost(bool, tag = "3")]
    pub more: bool,
    #[prost(int64, tag = "4")]
    pub count: i64,
}

/// `etcdserverpb.PutRequest`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PutRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
    #[prost(int64, tag = "3")]
    pub lease: i64,
    #[prost(bool, tag = "4")]
    pub prev_kv: bool,
    #[prost(bool, tag = "5")]
    pub ignore_value: bool,
    #[prost(bool, tag = "6")]
    pub ignore_lease: bool,
}

/// `etcdserverpb.PutResponse`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PutResponse {
    #[prost(message, optional, tag = "1")]
    pub header: Option<ResponseHeader>,
    #[prost(message, optional, tag = "2")]
    pub prev_kv: Option<KeyValue>,
}

/// `etcdserverpb.DeleteRangeRequest`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct DeleteRangeRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub range_end: Vec<u8>,
    #[prost(bool, tag = "3")]
    pub prev_kv: bool,
}

/// `etcdserverpb.DeleteRangeResponse`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct DeleteRangeResponse {
    #[prost(message, optional, tag = "1")]
    pub header: Option<ResponseHeader>,
    #[prost(int64, tag = "2")]
    pub deleted: i64,
    #[prost(message, repeated, tag = "3")]
    pub prev_kvs: Vec<KeyValue>,
}

/// `etcdserverpb.RequestOp` without `request_txn` (no nested Txn, §2.6).
#[derive(Clone, PartialEq, prost::Message)]
pub struct RequestOp {
    #[prost(oneof = "Request", tags = "1, 2, 3")]
    pub request: Option<Request>,
}

/// `RequestOp.request`.
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Request {
    #[prost(message, tag = "1")]
    Range(RangeRequest),
    #[prost(message, tag = "2")]
    Put(PutRequest),
    #[prost(message, tag = "3")]
    DeleteRange(DeleteRangeRequest),
}

impl RequestOp {
    /// A `request_range` op.
    pub fn range(request: RangeRequest) -> Self {
        Self {
            request: Some(Request::Range(request)),
        }
    }
    /// A `request_put` op.
    pub fn put(request: PutRequest) -> Self {
        Self {
            request: Some(Request::Put(request)),
        }
    }
    /// A `request_delete_range` op.
    pub fn delete(request: DeleteRangeRequest) -> Self {
        Self {
            request: Some(Request::DeleteRange(request)),
        }
    }
}

/// `etcdserverpb.ResponseOp` without `response_txn`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ResponseOp {
    #[prost(oneof = "Response", tags = "1, 2, 3")]
    pub response: Option<Response>,
}

/// `ResponseOp.response`.
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Response {
    #[prost(message, tag = "1")]
    Range(RangeResponse),
    #[prost(message, tag = "2")]
    Put(PutResponse),
    #[prost(message, tag = "3")]
    DeleteRange(DeleteRangeResponse),
}

/// `etcdserverpb.Compare`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Compare {
    /// One of the `RESULT_*` constants.
    #[prost(int32, tag = "1")]
    pub result: i32,
    /// One of the `TARGET_*` constants.
    #[prost(int32, tag = "2")]
    pub target: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub key: Vec<u8>,
    #[prost(oneof = "TargetUnion", tags = "4, 5, 6, 7, 8")]
    pub target_union: Option<TargetUnion>,
    #[prost(bytes = "vec", tag = "64")]
    pub range_end: Vec<u8>,
}

/// `Compare.target_union`.
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum TargetUnion {
    #[prost(int64, tag = "4")]
    Version(i64),
    #[prost(int64, tag = "5")]
    CreateRevision(i64),
    #[prost(int64, tag = "6")]
    ModRevision(i64),
    #[prost(bytes = "vec", tag = "7")]
    Value(Vec<u8>),
    #[prost(int64, tag = "8")]
    Lease(i64),
}

impl Compare {
    fn equal(key: &str, target: i32, value: TargetUnion) -> Self {
        Self {
            result: RESULT_EQUAL,
            target,
            key: key.as_bytes().to_vec(),
            target_union: Some(value),
            range_end: Vec::new(),
        }
    }
    /// `Version(key) == version`.
    pub fn version_equal(key: &str, version: i64) -> Self {
        Self::equal(key, TARGET_VERSION, TargetUnion::Version(version))
    }
    /// `CreateRevision(key) == revision` (the lock guard, §3.3.2).
    pub fn create_equal(key: &str, revision: i64) -> Self {
        Self::equal(key, TARGET_CREATE, TargetUnion::CreateRevision(revision))
    }
    /// `ModRevision(key) == revision`.
    pub fn mod_equal(key: &str, revision: i64) -> Self {
        Self::equal(key, TARGET_MOD, TargetUnion::ModRevision(revision))
    }
    /// `Value(key) == value`.
    pub fn value_equal(key: &str, value: Vec<u8>) -> Self {
        Self::equal(key, TARGET_VALUE, TargetUnion::Value(value))
    }
    /// `Lease(key) == lease`.
    pub fn lease_equal(key: &str, lease: i64) -> Self {
        Self::equal(key, TARGET_LEASE, TargetUnion::Lease(lease))
    }
}

/// `etcdserverpb.TxnRequest`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct TxnRequest {
    #[prost(message, repeated, tag = "1")]
    pub compare: Vec<Compare>,
    #[prost(message, repeated, tag = "2")]
    pub success: Vec<RequestOp>,
    #[prost(message, repeated, tag = "3")]
    pub failure: Vec<RequestOp>,
}

/// `etcdserverpb.TxnResponse`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct TxnResponse {
    #[prost(message, optional, tag = "1")]
    pub header: Option<ResponseHeader>,
    #[prost(bool, tag = "2")]
    pub succeeded: bool,
    #[prost(message, repeated, tag = "3")]
    pub responses: Vec<ResponseOp>,
}

impl TxnResponse {
    /// The first `response_range` (empty when there is none).
    pub fn first_range(self) -> RangeResponse {
        self.responses
            .into_iter()
            .find_map(|op| match op.response {
                Some(Response::Range(range)) => Some(range),
                _ => None,
            })
            .unwrap_or_default()
    }
}

/// `etcdserverpb.WatchRequest`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WatchRequest {
    #[prost(oneof = "RequestUnion", tags = "1, 2, 3")]
    pub request_union: Option<RequestUnion>,
}

/// `WatchRequest.request_union`.
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum RequestUnion {
    #[prost(message, tag = "1")]
    CreateRequest(WatchCreateRequest),
    #[prost(message, tag = "2")]
    CancelRequest(WatchCancelRequest),
    #[prost(message, tag = "3")]
    ProgressRequest(WatchProgressRequest),
}

impl WatchRequest {
    /// A `create_request`.
    pub fn create(request: WatchCreateRequest) -> Self {
        Self {
            request_union: Some(RequestUnion::CreateRequest(request)),
        }
    }
}

/// `etcdserverpb.WatchCreateRequest` (no fragmentation, §2.6).
#[derive(Clone, PartialEq, prost::Message)]
pub struct WatchCreateRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub range_end: Vec<u8>,
    #[prost(int64, tag = "3")]
    pub start_revision: i64,
    #[prost(bool, tag = "4")]
    pub progress_notify: bool,
    #[prost(int32, repeated, tag = "5")]
    pub filters: Vec<i32>,
    #[prost(bool, tag = "6")]
    pub prev_kv: bool,
    #[prost(int64, tag = "7")]
    pub watch_id: i64,
    #[prost(bool, tag = "8")]
    pub fragment: bool,
}

/// `etcdserverpb.WatchCancelRequest`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WatchCancelRequest {
    #[prost(int64, tag = "1")]
    pub watch_id: i64,
}

/// `etcdserverpb.WatchProgressRequest`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WatchProgressRequest {}

/// `etcdserverpb.WatchResponse`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WatchResponse {
    #[prost(message, optional, tag = "1")]
    pub header: Option<ResponseHeader>,
    #[prost(int64, tag = "2")]
    pub watch_id: i64,
    #[prost(bool, tag = "3")]
    pub created: bool,
    #[prost(bool, tag = "4")]
    pub canceled: bool,
    #[prost(int64, tag = "5")]
    pub compact_revision: i64,
    #[prost(string, tag = "6")]
    pub cancel_reason: String,
    #[prost(bool, tag = "7")]
    pub fragment: bool,
    #[prost(message, repeated, tag = "11")]
    pub events: Vec<Event>,
}

/// `etcdserverpb.LeaseGrantRequest`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LeaseGrantRequest {
    /// `TTL`, seconds.
    #[prost(int64, tag = "1")]
    pub ttl: i64,
    /// `ID`; 0 lets the server choose.
    #[prost(int64, tag = "2")]
    pub id: i64,
}

/// `etcdserverpb.LeaseGrantResponse`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LeaseGrantResponse {
    #[prost(message, optional, tag = "1")]
    pub header: Option<ResponseHeader>,
    #[prost(int64, tag = "2")]
    pub id: i64,
    #[prost(int64, tag = "3")]
    pub ttl: i64,
    #[prost(string, tag = "4")]
    pub error: String,
}

/// `etcdserverpb.LeaseRevokeRequest`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LeaseRevokeRequest {
    #[prost(int64, tag = "1")]
    pub id: i64,
}

/// `etcdserverpb.LeaseRevokeResponse`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LeaseRevokeResponse {
    #[prost(message, optional, tag = "1")]
    pub header: Option<ResponseHeader>,
}

/// `etcdserverpb.LeaseKeepAliveRequest`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LeaseKeepAliveRequest {
    #[prost(int64, tag = "1")]
    pub id: i64,
}

/// `etcdserverpb.LeaseKeepAliveResponse`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LeaseKeepAliveResponse {
    #[prost(message, optional, tag = "1")]
    pub header: Option<ResponseHeader>,
    #[prost(int64, tag = "2")]
    pub id: i64,
    #[prost(int64, tag = "3")]
    pub ttl: i64,
}

/// `etcdserverpb.StatusRequest`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct StatusRequest {}

/// `etcdserverpb.StatusResponse` (the fields §3.2.5 reads; later ones are
/// skipped as unknown).
#[derive(Clone, PartialEq, prost::Message)]
pub struct StatusResponse {
    #[prost(message, optional, tag = "1")]
    pub header: Option<ResponseHeader>,
    #[prost(string, tag = "2")]
    pub version: String,
    #[prost(int64, tag = "3")]
    pub db_size: i64,
    #[prost(uint64, tag = "4")]
    pub leader: u64,
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    use prost::Message;

    fn round_trip<M: Message + Default + PartialEq + std::fmt::Debug>(message: &M) {
        let bytes = message.encode_to_vec();
        let back = M::decode(bytes.as_slice()).unwrap();
        assert!(back == *message, "{message:?} != {back:?}");
    }

    fn kv() -> KeyValue {
        KeyValue {
            key: b"flowsdn/state/a".to_vec(),
            create_revision: 3,
            mod_revision: 7,
            version: 2,
            value: b"v".to_vec(),
            lease: 0x1234,
        }
    }

    #[test]
    fn requests_round_trip() {
        round_trip(&RangeRequest {
            key: b"a".to_vec(),
            range_end: b"b".to_vec(),
            limit: 256,
            revision: 9,
            ..Default::default()
        });
        round_trip(&PutRequest {
            key: b"k".to_vec(),
            value: vec![0, 1, 2],
            lease: 77,
            prev_kv: true,
            ..Default::default()
        });
        round_trip(&DeleteRangeRequest {
            key: b"k".to_vec(),
            range_end: b"l".to_vec(),
            prev_kv: false,
        });
        round_trip(&TxnRequest {
            compare: vec![
                Compare::version_equal("k", 0),
                Compare::create_equal("lock/1", 5),
                Compare::mod_equal("k", 6),
                Compare::value_equal("k", b"x".to_vec()),
                Compare::lease_equal("k", 8),
            ],
            success: vec![
                RequestOp::put(PutRequest {
                    key: b"k".to_vec(),
                    ..Default::default()
                }),
                RequestOp::range(RangeRequest::default()),
                RequestOp::delete(DeleteRangeRequest::default()),
            ],
            failure: vec![RequestOp::range(RangeRequest {
                key: b"lock/1".to_vec(),
                ..Default::default()
            })],
        });
        round_trip(&WatchRequest::create(WatchCreateRequest {
            key: b"p/".to_vec(),
            range_end: b"p0".to_vec(),
            start_revision: 11,
            filters: vec![1],
            ..Default::default()
        }));
        round_trip(&WatchRequest {
            request_union: Some(RequestUnion::CancelRequest(WatchCancelRequest {
                watch_id: 3,
            })),
        });
        round_trip(&LeaseGrantRequest { ttl: 25, id: 0 });
        round_trip(&LeaseRevokeRequest { id: 42 });
        round_trip(&LeaseKeepAliveRequest { id: 42 });
        round_trip(&StatusRequest {});
    }

    #[test]
    fn responses_round_trip() {
        let header = Some(ResponseHeader {
            cluster_id: 1,
            member_id: 2,
            revision: 3,
            raft_term: 4,
        });
        round_trip(&RangeResponse {
            header: header.clone(),
            kvs: vec![kv(), kv()],
            more: true,
            count: 9,
        });
        let txn = TxnResponse {
            header: header.clone(),
            succeeded: true,
            responses: vec![
                ResponseOp {
                    response: Some(Response::Put(PutResponse {
                        header: header.clone(),
                        prev_kv: Some(kv()),
                    })),
                },
                ResponseOp {
                    response: Some(Response::Range(RangeResponse {
                        kvs: vec![kv()],
                        ..Default::default()
                    })),
                },
            ],
        };
        round_trip(&txn);
        assert_eq!(txn.first_range().kvs, vec![kv()]);
        round_trip(&WatchResponse {
            header: header.clone(),
            watch_id: 1,
            canceled: true,
            compact_revision: 5,
            cancel_reason: "compacted".into(),
            events: vec![Event {
                kind: EVENT_DELETE,
                kv: Some(kv()),
                prev_kv: None,
            }],
            ..Default::default()
        });
        round_trip(&LeaseGrantResponse {
            header: header.clone(),
            id: 5,
            ttl: 25,
            error: String::new(),
        });
        round_trip(&LeaseKeepAliveResponse {
            header: header.clone(),
            id: 5,
            ttl: 25,
        });
        round_trip(&StatusResponse {
            header,
            version: "3.5.0".into(),
            db_size: 1,
            leader: 2,
        });
    }

    #[test]
    fn field_numbers_match_etcd() {
        // PutRequest{key: "k", lease: 1}: tag 1 (0x0a) len 1 'k', tag 3 (0x18) varint 1.
        let put = PutRequest {
            key: b"k".to_vec(),
            lease: 1,
            ..Default::default()
        };
        assert_eq!(put.encode_to_vec(), vec![0x0a, 1, b'k', 0x18, 1]);
        // Compare range_end is field 64: tag (64 << 3 | 2) = 0x82 0x04.
        let compare = Compare {
            range_end: b"z".to_vec(),
            ..Default::default()
        };
        assert_eq!(compare.encode_to_vec(), vec![0x82, 0x04, 1, b'z']);
        // WatchResponse.events is field 11 (0x5a).
        let watch = WatchResponse {
            events: vec![Event::default()],
            ..Default::default()
        };
        assert_eq!(watch.encode_to_vec(), vec![0x5a, 0]);
        assert_eq!(EVENT_PUT, 0);
        assert_eq!((RESULT_GREATER, RESULT_LESS, RESULT_NOT_EQUAL), (1, 2, 3));
    }
}
