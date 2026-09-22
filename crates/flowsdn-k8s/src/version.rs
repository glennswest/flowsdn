//! Version classification is not evidence that a server implements required APIs.
use crate::Error;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Version { pub major: u32, pub minor: u32, pub patch: u32 }
impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}
pub const MINIMUM: Version = Version { major: 1, minor: 26, patch: 0 };
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Band {
    /// Inside the reference's documented test range, not a flowsdn test result.
    ReferenceRange,
    OlderUntested,
    NewerUntested,
}
impl Version {
    pub fn detect(git_version: &str, major: &str, minor: &str) -> Result<Self, Error> {
        Self::parse_git(git_version).or_else(|| Some(Self {
            major: fallback_number(major)?, minor: fallback_number(minor)?, patch: 0,
        })).ok_or_else(|| Error("cannot parse Kubernetes version from gitVersion or major/minor".into()))
    }
    fn parse_git(value: &str) -> Option<Self> {
        let value = value.strip_prefix('v').unwrap_or(value);
        let (without_build, build) = value.split_once('+').map_or((value, None), |(base, suffix)| (base, Some(suffix)));
        if build.is_some_and(|value| !identifiers(value, false)) { return None; }
        let (core, prerelease) = without_build.split_once('-').map_or((without_build, None), |(base, suffix)| (base, Some(suffix)));
        if prerelease.is_some_and(|value| !identifiers(value, true)) { return None; }
        let mut parts = core.split('.');
        let result = Self { major: number(parts.next()?)?, minor: number(parts.next()?)?, patch: number(parts.next()?)? };
        if parts.next().is_some() { None } else { Some(result) }
    }
    /// Spec 13 compares the numeric release components; suffixes are retained by
    /// the calling status layer if it needs the original distribution string.
    pub fn classify(self) -> Result<Band, Error> {
        if self < MINIMUM { return Err(Error(format!("Kubernetes {self} is below the required {MINIMUM}"))); }
        Ok(if self.major == 1 && (33..=36).contains(&self.minor) { Band::ReferenceRange }
            else if self.major == 1 && self.minor < 33 { Band::OlderUntested } else { Band::NewerUntested })
    }
}
fn number(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) || (value.len() > 1 && value.starts_with('0')) { return None; }
    value.parse().ok()
}
fn fallback_number(value: &str) -> Option<u32> {
    let value = value.trim_end_matches(|character: char| !character.is_ascii_digit());
    number(value)
}
fn identifiers(value: &str, numeric_no_leading_zero: bool) -> bool {
    value.split('.').all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && (!numeric_no_leading_zero || !part.bytes().all(|byte| byte.is_ascii_digit()) || part.len() == 1 || !part.starts_with('0')))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Probe { Supported, Unsupported, Unknown }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePatchMode { StrategicMerge, GuardedJson }
/// Only explicit capability evidence selects the fallback. Authentication,
/// transport and ambiguous probe failures must not masquerade as unsupported.
pub fn node_patch_mode(strategic: Probe, json_test: Probe) -> Result<NodePatchMode, Error> {
    match (strategic, json_test) {
        (Probe::Supported, _) => Ok(NodePatchMode::StrategicMerge),
        (Probe::Unsupported, Probe::Supported) => Ok(NodePatchMode::GuardedJson),
        _ => Err(Error("node patch capabilities are unsupported or unverified".into())),
    }
}
/// Required CRD capabilities stay explicit even on an acceptable version.
/// This is a bounded prerequisite check, not the complete C1–C36 conformance suite.
pub fn crd_prerequisites(cel: Probe, multiple_served_versions: Probe) -> Result<(), Error> {
    if cel != Probe::Supported { return Err(Error("server CEL validation (C3) is unsupported or unverified; no client CEL substitute".into())); }
    if multiple_served_versions != Probe::Supported { return Err(Error("multiple served CRD versions (C10) are unsupported or unverified; versions must not be stripped".into())); }
    Ok(())
}
