//! Rust types of the flowsdn.io endpoint, identity and node kinds (#332):
//! FlowsdnEndpoint, FlowsdnEndpointSlice, FlowsdnIdentity, FlowsdnNode and
//! FlowsdnNodeConfig, `flowsdn.io/v1alpha1`.
//!
//! One field per schema property, named as the schema names it (serde
//! renames), optional unless the schema requires it, so a document
//! round-trips field for field. Unknown fields are ignored and enum-valued
//! fields are strings, so a newer server's additions do not fail a read.
//! `metadata` is the Kubernetes `ObjectMeta`. Structures the schema repeats
//! (an address pair, a named port, an identity tuple) are one type.
//! `tests/kinds.rs` checks each type against its CRD's schema (spec 13
//! T-CRD-3/4/5/7).
pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;

/// The group/version every kind here is served at.
pub const API_VERSION: &str = "flowsdn.io/v1alpha1";

/// A flowsdn.io kind: its names and REST paths.
pub trait Kind: Serialize + DeserializeOwned + Default {
    const KIND: &'static str;
    const PLURAL: &'static str;
    const NAMESPACED: bool;
    fn metadata(&self) -> &ObjectMeta;
    fn metadata_mut(&mut self) -> &mut ObjectMeta;
    /// A new object with `apiVersion`, `kind` and `metadata.name` set.
    fn named(name: &str) -> Self;
    /// The collection path (`namespace` is ignored for cluster kinds).
    fn collection(namespace: &str) -> String {
        if Self::NAMESPACED {
            format!(
                "/apis/{API_VERSION}/namespaces/{namespace}/{}",
                Self::PLURAL
            )
        } else {
            format!("/apis/{API_VERSION}/{}", Self::PLURAL)
        }
    }
    /// One object's path.
    fn path(namespace: &str, name: &str) -> String {
        format!("{}/{name}", Self::collection(namespace))
    }
}

macro_rules! kind {
    ($type:ident, $plural:literal, $namespaced:literal) => {
        impl Kind for $type {
            const KIND: &'static str = stringify!($type);
            const PLURAL: &'static str = $plural;
            const NAMESPACED: bool = $namespaced;
            fn metadata(&self) -> &ObjectMeta {
                &self.metadata
            }
            fn metadata_mut(&mut self) -> &mut ObjectMeta {
                &mut self.metadata
            }
            fn named(name: &str) -> Self {
                let mut object = Self {
                    api_version: API_VERSION.into(),
                    kind: Self::KIND.into(),
                    ..Self::default()
                };
                object.metadata.name = Some(name.into());
                object
            }
        }
    };
}
kind!(FlowsdnEndpoint, "flowsdnendpoints", true);
kind!(FlowsdnEndpointSlice, "flowsdnendpointslices", false);
kind!(FlowsdnIdentity, "flowsdnidentities", false);
kind!(FlowsdnNode, "flowsdnnodes", false);
kind!(FlowsdnNodeConfig, "flowsdnnodeconfigs", true);

/// FlowsdnEndpoint is the status of a flowsdn policy rule.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpoint {
    /// `apiVersion`: flowsdn.io/v1alpha1 (empty: not written).
    #[serde(
        rename = "apiVersion",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub api_version: String,
    /// `kind`: the kind name (empty: not written).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
    /// EndpointStatus is the status of a flowsdn endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<FlowsdnEndpointStatus>,
}

/// EndpointStatus is the status of a flowsdn endpoint.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointStatus {
    /// Controllers is the list of failing controllers for this endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controllers: Option<Vec<FlowsdnEndpointStatusController>>,
    /// Encryption is the encryption configuration of the node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionSpec>,
    /// ExternalIdentifiers is a set of identifiers to identify the endpoint apart from the pod
    /// name. This includes container runtime IDs.
    #[serde(
        rename = "external-identifiers",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_identifiers: Option<FlowsdnEndpointStatusExternalIdentifiers>,
    /// Health is the overall endpoint & subcomponent health.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<FlowsdnEndpointStatusHealth>,
    /// ID is the flowsdn-agent-local ID of the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// Identity is the security identity associated with the endpoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<FlowsdnEndpointStatusIdentity>,
    /// Log is the list of the last few warning and error log entries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<Vec<FlowsdnEndpointStatusLogItem>>,
    /// NamedPorts List of named Layer 4 port and protocol pairs which will be used in Network
    /// Policy specs.
    #[serde(
        rename = "named-ports",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub named_ports: Option<Vec<NamedPort>>,
    /// Networking is the networking properties of the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub networking: Option<FlowsdnEndpointStatusNetworking>,
    /// EndpointPolicy represents the endpoint's policy by listing all allowed ingress and egress
    /// identities in combination with L4 port and protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<FlowsdnEndpointStatusPolicy>,
    /// ServiceAccount is the service account associated with the endpoint
    #[serde(
        rename = "service-account",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub service_account: Option<String>,
    /// State is the state of the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// ControllerStatus is the status of a failing controller.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointStatusController {
    /// Configuration is the controller configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<FlowsdnEndpointStatusControllerConfiguration>,
    /// Name is the name of the controller
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Status is the status of the controller
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<FlowsdnEndpointStatusControllerStatus>,
    /// UUID is the UUID of the controller
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
}

/// Configuration is the controller configuration
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointStatusControllerConfiguration {
    /// Retry on error
    #[serde(
        rename = "error-retry",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub error_retry: Option<bool>,
    /// Base error retry back-off time Format: duration
    #[serde(
        rename = "error-retry-base",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub error_retry_base: Option<i64>,
    /// Regular synchronization interval Format: duration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<i64>,
}

/// Status is the status of the controller
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointStatusControllerStatus {
    #[serde(
        rename = "consecutive-failure-count",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub consecutive_failure_count: Option<i64>,
    #[serde(
        rename = "failure-count",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub failure_count: Option<i64>,
    #[serde(
        rename = "last-failure-msg",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_failure_msg: Option<String>,
    #[serde(
        rename = "last-failure-timestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_failure_timestamp: Option<String>,
    #[serde(
        rename = "last-success-timestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_success_timestamp: Option<String>,
    #[serde(
        rename = "success-count",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub success_count: Option<i64>,
}

/// ExternalIdentifiers is a set of identifiers to identify the endpoint apart from the pod name.
/// This includes container runtime IDs.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointStatusExternalIdentifiers {
    /// ID assigned to this attachment by container runtime
    #[serde(
        rename = "cni-attachment-id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cni_attachment_id: Option<String>,
    /// ID assigned by container runtime (deprecated, may not be unique)
    #[serde(
        rename = "container-id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub container_id: Option<String>,
    /// Name assigned to container (deprecated, may not be unique)
    #[serde(
        rename = "container-name",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub container_name: Option<String>,
    /// Docker endpoint ID
    #[serde(
        rename = "docker-endpoint-id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub docker_endpoint_id: Option<String>,
    /// Docker network ID
    #[serde(
        rename = "docker-network-id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub docker_network_id: Option<String>,
    /// K8s namespace for this endpoint (deprecated, may not be unique)
    #[serde(
        rename = "k8s-namespace",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub k8s_namespace: Option<String>,
    /// K8s pod name for this endpoint (deprecated, may not be unique)
    #[serde(
        rename = "k8s-pod-name",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub k8s_pod_name: Option<String>,
    /// K8s pod for this endpoint (deprecated, may not be unique)
    #[serde(rename = "pod-name", default, skip_serializing_if = "Option::is_none")]
    pub pod_name: Option<String>,
}

/// Health is the overall endpoint & subcomponent health.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointStatusHealth {
    /// bpf
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bpf: Option<String>,
    /// Is this endpoint reachable
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    /// overall health
    #[serde(
        rename = "overallHealth",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub overall_health: Option<String>,
    /// policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

/// Identity is the security identity associated with the endpoint
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointStatusIdentity {
    /// ID is the numeric identity of the endpoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// Labels is the list of labels associated with the identity
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
}

/// EndpointStatusChange Indication of a change of status
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointStatusLogItem {
    /// Code indicate type of status change Enum: ["ok","failed"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Status message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Timestamp when status change occurred
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// Networking is the networking properties of the endpoint.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointStatusNetworking {
    /// IP4/6 addresses assigned to this Endpoint
    pub addressing: Vec<AddressPair>,
    /// NodeIP is the IP of the node the endpoint is running on. The IP must be reachable between
    /// nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
}

/// EndpointPolicy represents the endpoint's policy by listing all allowed ingress and egress
/// identities in combination with L4 port and protocol.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointStatusPolicy {
    /// EndpointPolicyDirection is the list of allowed identities per direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<FlowsdnEndpointStatusPolicyDirection>,
    /// EndpointPolicyDirection is the list of allowed identities per direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<FlowsdnEndpointStatusPolicyDirection>,
}

/// EndpointPolicyDirection is the list of allowed identities per direction.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointStatusPolicyDirection {
    /// Deprecated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adding: Option<Vec<IdentityTuple>>,
    /// AllowedIdentityList is a list of IdentityTuples that species peers that are allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<IdentityTuple>>,
    /// DenyIdentityList is a list of IdentityTuples that species peers that are denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied: Option<Vec<IdentityTuple>>,
    pub enforcing: bool,
    /// Deprecated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removing: Option<Vec<IdentityTuple>>,
    /// EndpointPolicyState defines the state of the Policy mode: "enforcing", "non-enforcing",
    /// "disabled"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}


/// FlowsdnEndpointSlice contains a group of Coreflowsdnendpoints.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointSlice {
    /// `apiVersion`: flowsdn.io/v1alpha1 (empty: not written).
    #[serde(
        rename = "apiVersion",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub api_version: String,
    /// Endpoints is a list of coreCEPs packed in a FlowsdnEndpointSlice
    pub endpoints: Vec<FlowsdnEndpointSliceEndpoint>,
    /// `kind`: the kind name (empty: not written).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
    /// Namespace indicate as FlowsdnEndpointSlice namespace. All the FlowsdnEndpoints within the
    /// same namespace are put together in FlowsdnEndpointSlice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// CoreFlowsdnEndpoint is slim version of status of FlowsdnEndpoint.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointSliceEndpoint {
    /// EncryptionSpec defines the encryption relevant configuration of a node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionSpec>,
    /// IdentityID is the numeric identity of the endpoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// Name indicate as FlowsdnEndpoint name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// NamedPorts List of named Layer 4 port and protocol pairs which will be used in Network
    /// Policy specs.
    #[serde(
        rename = "named-ports",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub named_ports: Option<Vec<NamedPort>>,
    /// EndpointNetworking is the addressing information of an endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub networking: Option<FlowsdnEndpointSliceEndpointNetworking>,
    /// PodUID is the UID of the Pod that owns this endpoint.
    #[serde(rename = "pod-uid", default, skip_serializing_if = "Option::is_none")]
    pub pod_uid: Option<String>,
    /// ServiceAccount is the service account of the endpoint.
    #[serde(
        rename = "service-account",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub service_account: Option<String>,
}

/// EndpointNetworking is the addressing information of an endpoint.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnEndpointSliceEndpointNetworking {
    /// IP4/6 addresses assigned to this Endpoint
    pub addressing: Vec<AddressPair>,
    /// NodeIP is the IP of the node the endpoint is running on. The IP must be reachable between
    /// nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
}

/// FlowsdnIdentity is a CRD that represents an identity managed by flowsdn. It is intended as a
/// backing store for identity allocation, acting as the global coordination backend, and can be
/// used in place of a KVStore (such as etcd). The name of the CRD is the numeric identity and the
/// labels on the CRD object are the kubernetes sourced labels seen by flowsdn. This is currently
/// the only label source possible when running under kubernetes. Non-kubernetes labels are filtered
/// but all labels, from all sources, are places in the SecurityLabels field. These also include the
/// source and are used to define the identity. The labels under metav1.ObjectMeta can be used when
/// searching for FlowsdnIdentity instances that include particular labels. This can be done with
/// invocations such as:
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnIdentity {
    /// `apiVersion`: flowsdn.io/v1alpha1 (empty: not written).
    #[serde(
        rename = "apiVersion",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub api_version: String,
    /// `kind`: the kind name (empty: not written).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
    /// SecurityLabels is the source-of-truth set of labels for this identity.
    #[serde(rename = "security-labels")]
    pub security_labels: BTreeMap<String, String>,
}

/// FlowsdnNode represents a node managed by flowsdn. It contains a specification to control various
/// node specific configuration aspects and a status section to represent the status of the node.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNode {
    /// `apiVersion`: flowsdn.io/v1alpha1 (empty: not written).
    #[serde(
        rename = "apiVersion",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub api_version: String,
    /// `kind`: the kind name (empty: not written).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
    /// Spec defines the desired specification/configuration of the node.
    pub spec: FlowsdnNodeSpec,
    /// Status defines the realized specification/configuration and status of the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<FlowsdnNodeStatus>,
}

/// Spec defines the desired specification/configuration of the node.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeSpec {
    /// Addresses is the list of all node addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<FlowsdnNodeSpecAddress>>,
    /// AlibabaCloud is the AlibabaCloud IPAM specific configuration.
    #[serde(
        rename = "alibaba-cloud",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub alibaba_cloud: Option<FlowsdnNodeSpecAlibabaCloud>,
    /// Azure is the Azure IPAM specific configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<FlowsdnNodeSpecAzure>,
    /// BootID is a unique node identifier generated on boot
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootid: Option<String>,
    /// Encryption is the encryption configuration of the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionSpec>,
    /// ENI is the AWS ENI specific configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eni: Option<FlowsdnNodeSpecEni>,
    /// HealthAddressing is the addressing information for health connectivity checking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<AddressPair>,
    /// IngressAddressing is the addressing information for Ingress listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<AddressPair>,
    /// InstanceID is the identifier of the node. This is different from the node name which is
    /// typically the FQDN of the node. The InstanceID typically refers to the identifier used by
    /// the cloud provider or some other means of identification.
    #[serde(
        rename = "instance-id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub instance_id: Option<String>,
    /// IPAM is the address management specification. This section can be populated by a user or it
    /// can be automatically populated by an IPAM operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipam: Option<FlowsdnNodeSpecIpam>,
}

/// NodeAddress is a node address.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeSpecAddress {
    /// IP is an IP of a node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Type is the type of the node address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

/// AlibabaCloud is the AlibabaCloud IPAM specific configuration.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeSpecAlibabaCloud {
    /// AvailabilityZone is the availability zone to use when allocating ENIs.
    #[serde(
        rename = "availability-zone",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub availability_zone: Option<String>,
    /// CIDRBlock is vpc ipv4 CIDR
    #[serde(
        rename = "cidr-block",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cidr_block: Option<String>,
    /// InstanceType is the ECS instance type, e.g. "ecs.g6.2xlarge"
    #[serde(
        rename = "instance-type",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub instance_type: Option<String>,
    /// SecurityGroupTags is the list of tags to use when evaluating which security groups to use
    /// for the ENI.
    #[serde(
        rename = "security-group-tags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_group_tags: Option<BTreeMap<String, String>>,
    /// SecurityGroups is the list of security groups to attach to any ENI that is created and
    /// attached to the instance.
    #[serde(
        rename = "security-groups",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_groups: Option<Vec<String>>,
    /// VPCID is the VPC ID to use when allocating ENIs.
    #[serde(rename = "vpc-id", default, skip_serializing_if = "Option::is_none")]
    pub vpc_id: Option<String>,
    /// VSwitchTags is the list of tags to use when evaluating which vSwitch to use for the ENI.
    #[serde(
        rename = "vswitch-tags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub vswitch_tags: Option<BTreeMap<String, String>>,
    /// VSwitches is the ID of vSwitch available for ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vswitches: Option<Vec<String>>,
}

/// Azure is the Azure IPAM specific configuration.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeSpecAzure {
    /// InterfaceName is the name of the interface the flowsdn-operator will use to allocate all the
    /// IPs on
    #[serde(
        rename = "interface-name",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub interface_name: Option<String>,
}

/// ENI is the AWS ENI specific configuration.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeSpecEni {
    /// AvailabilityZone is the availability zone to use when allocating ENIs.
    #[serde(
        rename = "availability-zone",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub availability_zone: Option<String>,
    /// DeleteOnTermination defines that the ENI should be deleted when the associated instance is
    /// terminated. If the parameter is not set the default behavior is to delete the ENI on
    /// instance termination.
    #[serde(
        rename = "delete-on-termination",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub delete_on_termination: Option<bool>,
    /// DisablePrefixDelegation determines whether ENI prefix delegation should be disabled on this
    /// node.
    #[serde(
        rename = "disable-prefix-delegation",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_prefix_delegation: Option<bool>,
    /// ExcludeInterfaceTags is the list of tags to use when excluding ENIs for flowsdn IP
    /// allocation. Any interface matching this set of tags will not be managed by flowsdn.
    #[serde(
        rename = "exclude-interface-tags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_interface_tags: Option<BTreeMap<String, String>>,
    /// FirstInterfaceIndex is the index of the first ENI to use for IP allocation, e.g. if the node
    /// has eth0, eth1, eth2 and FirstInterfaceIndex is set to 1, then only eth1 and eth2 will be
    /// used for IP allocation, eth0 will be ignored for PodIP allocation.
    #[serde(
        rename = "first-interface-index",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub first_interface_index: Option<i64>,
    /// InstanceType is the AWS EC2 instance type, e.g. "m5.large"
    #[serde(
        rename = "instance-type",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub instance_type: Option<String>,
    /// NodeSubnetID is the subnet of the primary ENI the instance was brought up with. It is used
    /// as a sensible default subnet to create ENIs in.
    #[serde(
        rename = "node-subnet-id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub node_subnet_id: Option<String>,
    /// SecurityGroupTags is the list of tags to use when evaliating what AWS security groups to use
    /// for the ENI.
    #[serde(
        rename = "security-group-tags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_group_tags: Option<BTreeMap<String, String>>,
    /// SecurityGroups is the list of security groups to attach to any ENI that is created and
    /// attached to the instance.
    #[serde(
        rename = "security-groups",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_groups: Option<Vec<String>>,
    /// SubnetIDs is the list of subnet ids to use when evaluating what AWS subnets to use for ENI
    /// and IP allocation.
    #[serde(
        rename = "subnet-ids",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub subnet_ids: Option<Vec<String>>,
    /// SubnetTags is the list of tags to use when evaluating what AWS subnets to use for ENI and IP
    /// allocation.
    #[serde(
        rename = "subnet-tags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub subnet_tags: Option<BTreeMap<String, String>>,
    /// UsePrimaryAddress determines whether an ENI's primary address should be available for
    /// allocations on the node
    #[serde(
        rename = "use-primary-address",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub use_primary_address: Option<bool>,
    /// VpcID is the VPC ID to use when allocating ENIs.
    #[serde(rename = "vpc-id", default, skip_serializing_if = "Option::is_none")]
    pub vpc_id: Option<String>,
}

/// IPAM is the address management specification. This section can be populated by a user or it can
/// be automatically populated by an IPAM operator.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeSpecIpam {
    /// IPv6Pool is the list of IPv6 addresses available to the node for allocation. When an IPv6
    /// address is used, it will remain on this list but will be added to Status.IPAM.IPv6Used
    #[serde(rename = "ipv6-pool", default, skip_serializing_if = "Option::is_none")]
    pub ipv6_pool: Option<BTreeMap<String, AllocationIp>>,
    /// MaxAboveWatermark is the maximum number of addresses to allocate beyond the addresses needed
    /// to reach the PreAllocate watermark. Going above the watermark can help reduce the number of
    /// API calls to allocate IPs, e.g. when a new ENI is allocated, as many secondary IPs as
    /// possible are allocated. Limiting the amount can help reduce waste of IPs.
    #[serde(
        rename = "max-above-watermark",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_above_watermark: Option<i64>,
    /// MaxAllocate is the maximum number of IPs that can be allocated to the node. When the current
    /// amount of allocated IPs will approach this value, the considered value for PreAllocate will
    /// decrease down to 0 in order to not attempt to allocate more addresses than defined.
    #[serde(
        rename = "max-allocate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_allocate: Option<i64>,
    /// MinAllocate is the minimum number of IPs that must be allocated when the node is first
    /// bootstrapped. It defines the minimum base socket of addresses that must be available. After
    /// reaching this watermark, the PreAllocate and MaxAboveWatermark logic takes over to continue
    /// allocating IPs.
    #[serde(
        rename = "min-allocate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub min_allocate: Option<i64>,
    /// PodCIDRs is the list of CIDRs available to the node for allocation. When an IP is used, the
    /// IP will be added to Status.IPAM.Used
    #[serde(rename = "podCIDRs", default, skip_serializing_if = "Option::is_none")]
    pub pod_cidrs: Option<Vec<String>>,
    /// Pool is the list of IPv4 addresses available to the node for allocation. When an IPv4
    /// address is used, it will remain on this list but will be added to Status.IPAM.Used
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<BTreeMap<String, AllocationIp>>,
    /// Pools contains the list of assigned IPAM pools for this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pools: Option<FlowsdnNodeSpecIpamPools>,
    /// PreAllocate defines the number of IP addresses that must be available for allocation in the
    /// IPAMSpec. It defines the buffer of addresses available immediately without requiring
    /// flowsdn-operator to get involved.
    #[serde(
        rename = "pre-allocate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_allocate: Option<i64>,
    /// StaticIPTags are used to determine the pool of IPs from which to attribute a static IP to
    /// the node. For example in AWS this is used to filter Elastic IP Addresses.
    #[serde(
        rename = "static-ip-tags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub static_ip_tags: Option<BTreeMap<String, String>>,
}

/// Pools contains the list of assigned IPAM pools for this node.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeSpecIpamPools {
    /// Allocated contains the list of pooled CIDR assigned to this node. The operator will add new
    /// pod CIDRs to this field, whereas the agent will remove CIDRs it has released.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocated: Option<Vec<FlowsdnNodeSpecIpamPoolsAllocatedItem>>,
    /// Requested contains a list of IPAM pool requests, i.e. indicates how many addresses this node
    /// requests out of each pool listed here. This field is owned and written to by flowsdn-agent
    /// and read by the operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<Vec<FlowsdnNodeSpecIpamPoolsRequestedItem>>,
}

/// IPAMPoolAllocation describes an allocation of an IPAM pool from the operator to the node. It
/// contains the assigned PodCIDRs allocated from this pool
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeSpecIpamPoolsAllocatedItem {
    /// AllowFirstIP allows the first IP of each allocated CIDR to be used.
    #[serde(
        rename = "allowFirstIP",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_first_ip: Option<bool>,
    /// AllowLastIP allows the last IP of each allocated CIDR to be used.
    #[serde(
        rename = "allowLastIP",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_last_ip: Option<bool>,
    /// CIDRs contains a list of pod CIDRs currently allocated from this pool
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidrs: Option<Vec<String>>,
    /// Pool is the name of the IPAM pool backing this allocation
    pub pool: String,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeSpecIpamPoolsRequestedItem {
    /// Needed indicates how many IPs out of the above Pool this node requests from the operator.
    /// The operator runs a reconciliation loop to ensure each node always has enough PodCIDRs
    /// allocated in each pool to fulfill the requested number of IPs here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needed: Option<FlowsdnNodeSpecIpamPoolsRequestedItemNeeded>,
    /// Pool is the name of the IPAM pool backing this request
    pub pool: String,
}

/// Needed indicates how many IPs out of the above Pool this node requests from the operator. The
/// operator runs a reconciliation loop to ensure each node always has enough PodCIDRs allocated in
/// each pool to fulfill the requested number of IPs here.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeSpecIpamPoolsRequestedItemNeeded {
    /// IPv4Addrs contains the number of requested IPv4 addresses out of a given pool
    #[serde(
        rename = "ipv4-addrs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ipv4_addrs: Option<i64>,
    /// IPv6Addrs contains the number of requested IPv6 addresses out of a given pool
    #[serde(
        rename = "ipv6-addrs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ipv6_addrs: Option<i64>,
}

/// Status defines the realized specification/configuration and status of the node.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatus {
    /// AlibabaCloud is the AlibabaCloud specific status of the node.
    #[serde(
        rename = "alibaba-cloud",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub alibaba_cloud: Option<FlowsdnNodeStatusAlibabaCloud>,
    /// Azure is the Azure specific status of the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<FlowsdnNodeStatusAzure>,
    /// ENI is the AWS ENI specific status of the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eni: Option<FlowsdnNodeStatusEni>,
    /// IPAM is the IPAM status of the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipam: Option<FlowsdnNodeStatusIpam>,
}

/// AlibabaCloud is the AlibabaCloud specific status of the node.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusAlibabaCloud {
    /// ENIs is the list of ENIs on the node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enis: Option<BTreeMap<String, FlowsdnNodeStatusAlibabaCloudEnisValue>>,
}

/// ENI represents an AlibabaCloud Elastic Network Interface
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusAlibabaCloudEnisValue {
    /// InstanceID is the InstanceID using this ENI
    #[serde(
        rename = "instance-id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub instance_id: Option<String>,
    /// MACAddress is the mac address of the ENI
    #[serde(
        rename = "mac-address",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub mac_address: Option<String>,
    /// NetworkInterfaceID is the ENI id
    #[serde(
        rename = "network-interface-id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub network_interface_id: Option<String>,
    /// PrimaryIPAddress is the primary IP on ENI
    #[serde(
        rename = "primary-ip-address",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub primary_ip_address: Option<String>,
    /// PrivateIPSets is the list of all IPs on the ENI, including PrimaryIPAddress
    #[serde(
        rename = "private-ipsets",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub private_ipsets: Option<Vec<FlowsdnNodeStatusAlibabaCloudEnisValuePrivateIpset>>,
    /// SecurityGroupIDs is the security group ids used by this ENI
    #[serde(
        rename = "security-groupids",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_groupids: Option<Vec<String>>,
    /// Tags is the tags on this ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
    /// Type is the ENI type Primary or Secondary
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// VPC is the vpc to which the ENI belongs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc: Option<FlowsdnNodeStatusAlibabaCloudEnisValueVpc>,
    /// VSwitch is the vSwitch the ENI is using
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vswitch: Option<FlowsdnNodeStatusAlibabaCloudEnisValueVswitch>,
    /// ZoneID is the zone to which the ENI belongs
    #[serde(rename = "zone-id", default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
}

/// PrivateIPSet is a nested struct in ecs response
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusAlibabaCloudEnisValuePrivateIpset {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(
        rename = "private-ip-address",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub private_ip_address: Option<String>,
}

/// VPC is the vpc to which the ENI belongs
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusAlibabaCloudEnisValueVpc {
    /// CIDRBlock is the VPC IPv4 CIDR
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// IPv6CIDRBlock is the VPC IPv6 CIDR
    #[serde(rename = "ipv6-cidr", default, skip_serializing_if = "Option::is_none")]
    pub ipv6_cidr: Option<String>,
    /// SecondaryCIDRs is the list of Secondary CIDRs associated with the VPC
    #[serde(
        rename = "secondary-cidrs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub secondary_cidrs: Option<Vec<String>>,
    /// VPCID is the vpc to which the ENI belongs
    #[serde(rename = "vpc-id", default, skip_serializing_if = "Option::is_none")]
    pub vpc_id: Option<String>,
}

/// VSwitch is the vSwitch the ENI is using
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusAlibabaCloudEnisValueVswitch {
    /// CIDRBlock is the vSwitch IPv4 CIDR
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// IPv6CIDRBlock is the vSwitch IPv6 CIDR
    #[serde(rename = "ipv6-cidr", default, skip_serializing_if = "Option::is_none")]
    pub ipv6_cidr: Option<String>,
    /// VSwitchID is the vSwitch to which the ENI belongs
    #[serde(
        rename = "vswitch-id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub vswitch_id: Option<String>,
}

/// Azure is the Azure specific status of the node.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusAzure {
    /// Interfaces is the list of interfaces on the node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interfaces: Option<Vec<FlowsdnNodeStatusAzureInterface>>,
}

/// AzureInterface represents an Azure Interface
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusAzureInterface {
    /// Addresses is the list of secondary IPs associated with the interface. The primary IP is
    /// tracked separately in the IP field, but is also included here when the operator is
    /// configured to expose it for allocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<FlowsdnNodeStatusAzureInterfaceAddress>>,
    /// CIDR is the range that the interface belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Gateway is the interface's subnet's default route
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// ID is the identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// IP is the primary IP of the interface
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// MAC is the mac address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Name is the name of the interface
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// SecurityGroup is the security group associated with the interface
    #[serde(
        rename = "security-group",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_group: Option<String>,
    /// State is the provisioning state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Subnet is the subnet the interface is attached to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<CloudSubnet>,
}

/// AzureAddress is an IP address assigned to an AzureInterface
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusAzureInterfaceAddress {
    /// IP is the ip address of the address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// State is the provisioning state of the address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Subnet is the subnet the address belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
}

/// ENI is the AWS ENI specific status of the node.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusEni {
    /// ENIs is the list of ENIs on the node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enis: Option<BTreeMap<String, FlowsdnNodeStatusEniEnisValue>>,
}

/// ENI represents an AWS Elastic Network Interface
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusEniEnisValue {
    /// Addresses is the list of all secondary IPs associated with the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<String>>,
    /// AvailabilityZone is the availability zone of the ENI
    #[serde(
        rename = "availability-zone",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub availability_zone: Option<String>,
    /// Description is the description field of the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// ID is the ENI ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// IP is the primary IP of the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// IPv6Prefixes is the list of all IPv6 /80 delegated prefixes associated with the ENI
    #[serde(
        rename = "ipv6-prefixes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ipv6_prefixes: Option<Vec<String>>,
    /// MAC is the mac address of the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Number is the interface index, it used in combination with FirstInterfaceIndex
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<i64>,
    /// Prefixes is the list of all IPv4 /28 delegated prefixes associated with the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefixes: Option<Vec<String>>,
    /// PublicIP is the public IP associated with the ENI
    #[serde(rename = "public-ip", default, skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    /// SecurityGroups are the security groups associated with the ENI
    #[serde(
        rename = "security-groups",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_groups: Option<Vec<String>>,
    /// Subnet is the subnet the ENI is associated with
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<CloudSubnet>,
    /// Tags is the set of tags of the ENI. Used to detect ENIs which should not be managed by
    /// flowsdn
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
    /// VPC is the VPC information to which the ENI is attached to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc: Option<FlowsdnNodeStatusEniEnisValueVpc>,
}

/// VPC is the VPC information to which the ENI is attached to
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusEniEnisValueVpc {
    /// CIDRs is the list of CIDR ranges associated with the VPC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidrs: Option<Vec<String>>,
    /// / ID is the ID of a VPC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// PrimaryCIDR is the primary CIDR of the VPC
    #[serde(
        rename = "primary-cidr",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub primary_cidr: Option<String>,
}

/// IPAM is the IPAM status of the node.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusIpam {
    /// AssignedStaticIP is the static IP assigned to the node (ex: public Elastic IP address in
    /// AWS)
    #[serde(
        rename = "assigned-static-ip",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub assigned_static_ip: Option<String>,
    /// IPv6Used lists all IPv6 addresses out of Spec.IPAM.IPv6Pool which have been allocated and
    /// are in use.
    #[serde(rename = "ipv6-used", default, skip_serializing_if = "Option::is_none")]
    pub ipv6_used: Option<BTreeMap<String, AllocationIp>>,
    /// Operator is the Operator status of the node
    #[serde(
        rename = "operator-status",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub operator_status: Option<FlowsdnNodeStatusIpamOperatorStatus>,
    /// PodCIDRs lists the status of each pod CIDR allocated to this node.
    #[serde(rename = "pod-cidrs", default, skip_serializing_if = "Option::is_none")]
    pub pod_cidrs: Option<BTreeMap<String, FlowsdnNodeStatusIpamPodCidrsValue>>,
    /// ReleaseIPs tracks the state for every IPv4 address considered for release. The value can be
    /// one of the following strings: * marked-for-release : Set by operator as possible candidate
    /// for IP * ready-for-release  : Acknowledged as safe to release by agent * do-not-release
    /// : IP already in use / not owned by the node. Set by agent * released           : IP
    /// successfully released. Set by operator
    #[serde(
        rename = "release-ips",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub release_ips: Option<BTreeMap<String, String>>,
    /// ReleaseIPv6s tracks the state for every IPv6 address considered for release. The value can
    /// be one of the following strings: * marked-for-release : Set by operator as possible
    /// candidate for IP * ready-for-release  : Acknowledged as safe to release by agent * do-not-
    /// release     : IP already in use / not owned by the node. Set by agent * released           :
    /// IP successfully released. Set by operator
    #[serde(
        rename = "release-ipv6s",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub release_ipv6s: Option<BTreeMap<String, String>>,
    /// Used lists all IPv4 addresses out of Spec.IPAM.Pool which have been allocated and are in
    /// use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<BTreeMap<String, AllocationIp>>,
}

/// Operator is the Operator status of the node
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusIpamOperatorStatus {
    /// Error is the error message set by flowsdn-operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeStatusIpamPodCidrsValue {
    /// Status describes the status of a pod CIDR
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// FlowsdnNodeConfig is a list of configuration key-value pairs. It is applied to nodes indicated
/// by a label selector.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeConfig {
    /// `apiVersion`: flowsdn.io/v1alpha1 (empty: not written).
    #[serde(
        rename = "apiVersion",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub api_version: String,
    /// `kind`: the kind name (empty: not written).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
    /// Spec is the desired flowsdn configuration overrides for a given node
    pub spec: FlowsdnNodeConfigSpec,
}

/// Spec is the desired flowsdn configuration overrides for a given node
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeConfigSpec {
    /// Defaults is treated the same as the flowsdn-config ConfigMap - a set of key-value pairs
    /// parsed by the agent and operator processes. Each key must be a valid config-map data field
    /// (i.e. a-z, A-Z, -, _, and .)
    pub defaults: BTreeMap<String, String>,
    /// NodeSelector is a label selector that determines to which nodes this configuration applies.
    /// If not supplied, then this config applies to no nodes. If empty, then it applies to all
    /// nodes.
    #[serde(rename = "nodeSelector")]
    pub node_selector: FlowsdnNodeConfigSpecNodeSelector,
}

/// NodeSelector is a label selector that determines to which nodes this configuration applies. If
/// not supplied, then this config applies to no nodes. If empty, then it applies to all nodes.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeConfigSpecNodeSelector {
    /// matchExpressions is a list of label selector requirements. The requirements are ANDed.
    #[serde(
        rename = "matchExpressions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub match_expressions: Option<Vec<FlowsdnNodeConfigSpecNodeSelectorMatchExpression>>,
    /// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is
    /// equivalent to an element of matchExpressions, whose key field is "key", the operator is
    /// "In", and the values array contains only "value". The requirements are ANDed.
    #[serde(
        rename = "matchLabels",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub match_labels: Option<BTreeMap<String, String>>,
}

/// A label selector requirement is a selector that contains values, a key, and an operator that
/// relates the key and values.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct FlowsdnNodeConfigSpecNodeSelectorMatchExpression {
    /// key is the label key that the selector applies to.
    pub key: String,
    /// operator represents a key's relationship to a set of values. Valid operators are In, NotIn,
    /// Exists and DoesNotExist.
    pub operator: String,
    /// values is an array of string values. If the operator is In or NotIn, the values array must
    /// be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty.
    /// This array is replaced during a strategic merge patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// IdentityTuple specifies a peer by identity, destination port and protocol.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct IdentityTuple {
    #[serde(rename = "dest-port", default, skip_serializing_if = "Option::is_none")]
    pub dest_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<i64>,
    #[serde(
        rename = "identity-labels",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<i64>,
}

/// Encryption is the encryption configuration of the node
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct EncryptionSpec {
    /// Key is the index to the key to use for encryption or 0 if encryption is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<i64>,
}

/// Port Layer 4 port / protocol pair
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct NamedPort {
    /// Optional layer 4 port name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Layer 4 port number
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
    /// Layer 4 protocol Enum: ["TCP","UDP","SCTP","ICMP","ICMPV6","ANY"]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// AddressPair is a pair of IPv4 and/or IPv6 address.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct AddressPair {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
}

/// AllocationIP is an IP which is available for allocation, or already has been allocated
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct AllocationIp {
    /// Owner is the owner of the IP. This field is set if the IP has been allocated. It will be set
    /// to the pod name or another identifier representing the usage of the IP
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Resource is set for both available and allocated IPs, it represents what resource the IP is
    /// associated with, e.g. in combination with AWS ENI, this will refer to the ID of the ENI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// Subnet is the subnet the interface is attached to.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct CloudSubnet {
    /// CIDR is the CIDR range associated with the subnet
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// ID is the resource ID of the subnet
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
