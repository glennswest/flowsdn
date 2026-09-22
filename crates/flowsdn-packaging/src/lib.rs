//! Deployment and CI policy from specifications 19/22. Pure plans: no mounts,
//! certificate issuance, Helm rendering, artifact uploads or runner dispatch.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Masquerade {
    pub ipv4: bool,
    pub ipv6: bool,
    pub bpf: bool,
}
impl Masquerade {
    pub fn validate(self) -> Result<(), &'static str> {
        if (self.ipv4 || self.ipv6) && !self.bpf {
            Err("masquerade requires bpf.masquerade; no iptables fallback exists")
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyEffect {
    IgnoredWithWarning,
    NftablesNotrack,
    Unsupported,
}
/// Warning-only compatibility keys are not silently interpreted as iptables
/// behavior. Kube-proxy coexistence is a separate routing validation contract.
pub fn legacy_key(key: &str) -> LegacyEffect {
    match key {
        "installNoConntrackIptablesRules" => LegacyEffect::NftablesNotrack,
        "iptablesLockTimeout"
        | "iptablesRandomFully"
        | "disableIptablesFeederRules"
        | "prependIptablesChains"
        | "enableXTSocketFallback"
        | "egressMasqueradeInterfaces"
        | "cni.iptablesRemoveAWSRules" => LegacyEffect::IgnoredWithWarning,
        _ => LegacyEffect::Unsupported,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Filesystem {
    Bpffs,
    Cgroup2,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountPlan {
    UseVerifiedHost,
    RunInitThenVerify,
    NotRequired,
}
/// Observed filesystem must come from statfs, never directory existence.
/// Host-managed mode never schedules a mount as a fallback.
pub fn mount_plan(
    required: bool,
    host_managed: bool,
    auto_mount: bool,
    expected: Filesystem,
    observed: Option<Filesystem>,
) -> Result<MountPlan, &'static str> {
    if !required {
        return Ok(MountPlan::NotRequired);
    }
    if observed == Some(expected) {
        return Ok(MountPlan::UseVerifiedHost);
    }
    if host_managed || !auto_mount {
        return Err("required filesystem is absent or has the wrong type");
    }
    Ok(MountPlan::RunInitThenVerify)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMethod {
    Helm,
    CertManager,
    CronJob,
    ProvidedSecret,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateOwner {
    Helm,
    CertManager,
    UpstreamCertgen,
    User,
}
pub const fn certificate_owner(method: TlsMethod) -> CertificateOwner {
    match method {
        TlsMethod::Helm => CertificateOwner::Helm,
        TlsMethod::CertManager => CertificateOwner::CertManager,
        TlsMethod::CronJob => CertificateOwner::UpstreamCertgen,
        TlsMethod::ProvidedSecret => CertificateOwner::User,
    }
}
pub const DEFAULT_TLS_METHOD: TlsMethod = TlsMethod::Helm;
/// Images must be digest-pinned by the renderer; this helper does not select a
/// moving tag or issue certificates. All issuers obey the same SAN contract.
pub fn hubble_wildcard(cluster: &str) -> Result<String, &'static str> {
    if cluster.is_empty()
        || cluster.len() > 63
        || !cluster
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || cluster.starts_with('-')
        || cluster.ends_with('-')
    {
        return Err("cluster must be a DNS label");
    }
    Ok(format!("*.{cluster}.hubble-grpc.cilium.io"))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Distribution {
    pub release_archives: bool,
    pub configured_registry: bool,
    pub ghcr_mirror: bool,
    pub oci_chart: bool,
    pub pages_chart: bool,
}
pub const fn distribution(public_repository: bool) -> Distribution {
    Distribution {
        release_archives: true,
        configured_registry: true,
        ghcr_mirror: public_repository,
        oci_chart: true,
        pages_chart: public_repository,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lane {
    PullRequest,
    Nightly,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Retention {
    pub full_dump: bool,
    pub quick_bytes: u64,
    pub full_bytes: u64,
    pub flow_capacity: u32,
    pub days: u16,
}
pub const fn retention(lane: Lane, failed: bool) -> Retention {
    Retention {
        full_dump: failed,
        quick_bytes: 10_000_000,
        full_bytes: 2_147_483_648,
        flow_capacity: match lane {
            Lane::PullRequest => 1_000_000,
            Lane::Nightly => 100_000,
        },
        days: if failed { 14 } else { 7 },
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Push,
    PullRequest,
    PullRequestTarget,
    WorkflowDispatch,
}
/// Only a trusted main-branch dispatcher may select the privileged lane. A
/// dispatcher must not subsequently checkout arbitrary fork refs or user input.
/// Fork contributions run on hosted runners; this is a policy, not a sandbox.
pub fn privileged_allowed(
    event: Event,
    repository: &str,
    source_repository: &str,
    reference: &str,
    approved: bool,
) -> bool {
    !repository.is_empty()
        && repository == source_repository
        && reference == "refs/heads/main"
        && event == Event::WorkflowDispatch
        && approved
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_implicit_iptables_fallback() {
        for ipv4 in [false, true] {
            for ipv6 in [false, true] {
                for bpf in [false, true] {
                    assert_eq!(
                        Masquerade { ipv4, ipv6, bpf }.validate().is_ok(),
                        bpf || !(ipv4 || ipv6)
                    );
                }
            }
        }
        assert_eq!(
            legacy_key("installNoConntrackIptablesRules"),
            LegacyEffect::NftablesNotrack
        );
        assert_eq!(
            legacy_key("iptablesRandomFully"),
            LegacyEffect::IgnoredWithWarning
        );
        assert_eq!(legacy_key("unknown"), LegacyEffect::Unsupported);
    }
    #[test]
    fn host_mount_contract_fails_closed_and_init_requires_verification() {
        for fs in [Filesystem::Bpffs, Filesystem::Cgroup2] {
            assert_eq!(
                mount_plan(true, true, true, fs, Some(fs)),
                Ok(MountPlan::UseVerifiedHost)
            );
            assert!(mount_plan(true, true, true, fs, None).is_err());
            assert!(mount_plan(true, false, false, fs, None).is_err());
            assert_eq!(
                mount_plan(true, false, true, fs, None),
                Ok(MountPlan::RunInitThenVerify)
            );
        }
        assert!(
            mount_plan(
                true,
                true,
                true,
                Filesystem::Bpffs,
                Some(Filesystem::Cgroup2)
            )
            .is_err()
        );
        assert_eq!(
            mount_plan(false, true, false, Filesystem::Cgroup2, None),
            Ok(MountPlan::NotRequired)
        );
    }
    #[test]
    fn tls_ownership_keeps_names_and_distribution_is_visibility_gated() {
        assert_eq!(
            certificate_owner(DEFAULT_TLS_METHOD),
            CertificateOwner::Helm
        );
        assert_eq!(
            certificate_owner(TlsMethod::CronJob),
            CertificateOwner::UpstreamCertgen
        );
        assert_eq!(
            certificate_owner(TlsMethod::CertManager),
            CertificateOwner::CertManager
        );
        assert_eq!(
            certificate_owner(TlsMethod::ProvidedSecret),
            CertificateOwner::User
        );
        assert_eq!(
            hubble_wildcard("cluster-1"),
            Ok("*.cluster-1.hubble-grpc.cilium.io".into())
        );
        for invalid in ["", "a.b", "A", "-a", "a-", "a/b"] {
            assert!(hubble_wildcard(invalid).is_err());
        }
        assert!(!distribution(false).ghcr_mirror && !distribution(false).pages_chart);
        assert!(distribution(true).ghcr_mirror && distribution(true).pages_chart);
    }
    #[test]
    fn artifacts_preserve_failure_evidence_without_full_success_dumps() {
        assert!(!retention(Lane::Nightly, false).full_dump);
        assert_eq!(retention(Lane::Nightly, true).flow_capacity, 100_000);
        let failure = retention(Lane::PullRequest, true);
        assert!(failure.full_dump);
        assert_eq!(failure.flow_capacity, 1_000_000);
        assert_eq!(failure.quick_bytes, 10_000_000);
        assert_eq!(failure.days, 14);
    }
    #[test]
    fn privileged_runner_rejects_forks_untrusted_refs_and_automatic_events() {
        assert!(privileged_allowed(
            Event::WorkflowDispatch,
            "org/repo",
            "org/repo",
            "refs/heads/main",
            true
        ));
        for event in [Event::Push, Event::PullRequest, Event::PullRequestTarget] {
            assert!(!privileged_allowed(
                event,
                "org/repo",
                "org/repo",
                "refs/heads/main",
                true
            ));
        }
        assert!(!privileged_allowed(
            Event::WorkflowDispatch,
            "org/repo",
            "fork/repo",
            "refs/heads/main",
            true
        ));
        assert!(!privileged_allowed(
            Event::WorkflowDispatch,
            "org/repo",
            "org/repo",
            "refs/heads/topic",
            true
        ));
        assert!(!privileged_allowed(
            Event::WorkflowDispatch,
            "org/repo",
            "org/repo",
            "refs/heads/main",
            false
        ));
    }
}

/// Native Kubernetes PodCIDR allocation is the supported GKE integration.
/// This validates chart inputs; discovery and provider networking remain external.
pub fn validate_gke(
    ipam: &str,
    routing: &str,
    endpoint_routes: bool,
    native_cidr: Option<&str>,
) -> Result<(), &'static str> {
    if ipam != "kubernetes" || routing != "native" || !endpoint_routes {
        return Err("GKE requires Kubernetes IPAM, native routing and endpoint routes");
    }
    let cidr = native_cidr.ok_or("GKE requires the cluster IPv4 native routing CIDR")?;
    let (ip, prefix) = cidr.split_once('/').ok_or("invalid IPv4 CIDR")?;
    let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| "invalid IPv4 CIDR")?;
    let prefix: u32 = prefix.parse().map_err(|_| "invalid IPv4 prefix")?;
    if prefix > 32 {
        return Err("invalid IPv4 prefix");
    }
    let mask = u32::MAX
        .checked_shl(32_u32.saturating_sub(prefix))
        .unwrap_or(0);
    if u32::from(ip) & !mask != 0 {
        return Err("native routing CIDR must be canonical");
    }
    Ok(())
}

/// Migration preflight never deletes foreign-owned objects. Both iptables-nft
/// and legacy backends require the operator's reviewed cleanup before handoff.
pub fn reference_chain_blocks_handoff(chain: &str) -> bool {
    chain.starts_with("CILIUM_") || chain.starts_with("OLD_CILIUM_")
}

/// Preserve encryption, overlay and proxy magic; otherwise set host identity
/// while retaining all unrelated mark bits. The host rule is always present.
pub fn host_identity_mark(mark: u32) -> u32 {
    let magic = mark & 0xf00;
    if matches!(magic, 0xd00 | 0xe00 | 0x400) || matches!(mark & 0xe00, 0xa00 | 0x800) {
        mark
    } else {
        (mark & 0xffff_f0ff) | 0xc00
    }
}
#[cfg(test)]
mod routing_contract_tests {
    use super::*;
    #[test]
    fn gke_rejects_implicit_provider_and_noncanonical_ranges() {
        assert!(validate_gke("kubernetes", "native", true, Some("10.0.0.0/16")).is_ok());
        for cidr in ["10.0.0.1/16", "::/0", "10.0.0.0/33"] {
            assert!(validate_gke("kubernetes", "native", true, Some(cidr)).is_err());
        }
        assert!(validate_gke("gke", "native", true, Some("10.0.0.0/16")).is_err());
        assert!(validate_gke("kubernetes", "tunnel", true, Some("10.0.0.0/16")).is_err());
        assert!(validate_gke("kubernetes", "native", true, None).is_err());
    }
    #[test]
    fn foreign_cleanup_is_explicit_and_mark_preserves_special_sources() {
        assert!(reference_chain_blocks_handoff("CILIUM_POST_nat"));
        assert!(reference_chain_blocks_handoff("OLD_CILIUM_POST_nat"));
        assert!(!reference_chain_blocks_handoff("MY_CILIUM_TABLE"));
        for magic in [0xd00, 0xe00, 0x400, 0xa00, 0xb00, 0x800, 0x900] {
            assert_eq!(host_identity_mark(0x1234_0000 | magic), 0x1234_0000 | magic);
        }
        assert_eq!(host_identity_mark(0x1234_007f), 0x1234_0c7f);
    }
}
