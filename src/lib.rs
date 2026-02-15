//! stix-rs: STIX 2.1 types and helpers

// MIME Type Constants for STIX and TAXII
/// STIX 2.1 JSON media type for HTTP Content-Type headers
pub const MEDIA_TYPE_STIX: &str = "application/stix+json;version=2.1";

/// TAXII 2.1 JSON media type for HTTP Content-Type headers
pub const MEDIA_TYPE_TAXII: &str = "application/taxii+json;version=2.1";

/// Generic STIX JSON media type (without version)
pub const MEDIA_TYPE_STIX_GENERIC: &str = "application/stix+json";

/// Generic TAXII JSON media type (without version)
pub const MEDIA_TYPE_TAXII_GENERIC: &str = "application/taxii+json";

pub mod common;
pub mod sdos;
pub mod sros;
pub mod observables;
pub mod vocab;
pub mod bundle;
pub mod objects;
pub mod pattern;

pub use common::{
    CommonProperties, ExtensionDefinition, ExternalReference, GranularMarking, LanguageContent,
    MarkingDefinition, StixObject, extract_type_from_id, generate_stix_id, is_valid_ref_for_type,
    is_valid_stix_id,
};
pub use objects::*;
pub use observables::*;
pub use sdos::*;
pub use sros::Relationship;
pub use vocab::*;
pub use bundle::*;
pub use pattern::{validate_pattern, PatternBuilder, PatternError};

use uuid::Uuid;
const SCO_NAMESPACE: Uuid = Uuid::from_u128(0x00abedb4_aa42_466c_9c01_def7442f5a74);

fn generate_sco_id(object_type: &str, data: &str) -> String {
    let id_part = Uuid::new_v5(&SCO_NAMESPACE, data.as_bytes());
    format!("{}--{}", object_type, id_part)
}
use serde::{Deserialize, Serialize};
use serde::de::Deserializer;
use serde_json::Value;

/// A wrapper enum for STIX objects. Deserializes based on the `type` field.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum StixObjectEnum {
    Identity(Identity),
    Malware(Malware),
    Indicator(Indicator),
    ObservedData(ObservedData),
    MalwareAnalysis(MalwareAnalysis),
    Sighting(Sighting),
    Relationship(Relationship),
    File(File),
    Incident(Incident),
    Location(Location),
    NetworkTraffic(NetworkTraffic),
    DomainName(DomainName),
    #[serde(rename = "ipv4-addr")]
    IPv4Addr(IPv4Addr),
    Url(Url),
    Process(Process),
    Artifact(Artifact),
    #[serde(rename = "ipv6-addr")]
    IPv6Addr(IPv6Addr),
    MacAddr(MacAddr),
    Software(Software),
    UserAccount(UserAccount),
    EmailAddr(EmailAddr),
    EmailMessage(EmailMessage),
    SocketAddr(SocketAddr),
    AutonomousSystem(AutonomousSystem),
    SoftwarePackage(SoftwarePackage),
    Directory(Directory),
    Mutex(Mutex),
    WindowsRegistryKey(WindowsRegistryKey),
    X509Certificate(X509Certificate),
    AttackPattern(AttackPattern),
    Campaign(Campaign),
    ThreatActor(ThreatActor),
    Tool(Tool),
    Vulnerability(Vulnerability),
    CourseOfAction(CourseOfAction),
    IntrusionSet(IntrusionSet),
    Infrastructure(Infrastructure),
    Report(Report),
    Note(Note),
    Opinion(Opinion),
    Grouping(Grouping),
    MarkingDefinition(MarkingDefinition),
    LanguageContent(LanguageContent),
    ExtensionDefinition(ExtensionDefinition),
    Custom(serde_json::Value),
}

impl StixObjectEnum {
    /// Get the ID of the wrapped object
    pub fn name(&self) -> Option<&str> {
        match self {
            StixObjectEnum::Identity(o) => Some(&o.name),
            StixObjectEnum::Malware(o) => Some(&o.name),
            StixObjectEnum::ThreatActor(o) => Some(&o.name),
            StixObjectEnum::AttackPattern(o) => Some(&o.name),
            StixObjectEnum::Campaign(o) => Some(&o.name),
            StixObjectEnum::Tool(o) => Some(&o.name),
            StixObjectEnum::Vulnerability(o) => Some(&o.name),
            StixObjectEnum::CourseOfAction(o) => Some(&o.name),
            StixObjectEnum::Infrastructure(o) => Some(&o.name),
            StixObjectEnum::Report(o) => Some(&o.name),
            _ => None,
        }
    }

    pub fn created(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            StixObjectEnum::Indicator(o) => o.common.created,
            StixObjectEnum::Malware(o) => o.common.created,
            StixObjectEnum::ThreatActor(o) => o.common.created,
            StixObjectEnum::Identity(o) => o.common.created,
            StixObjectEnum::IntrusionSet(o) => o.common.created,
            StixObjectEnum::Campaign(o) => o.common.created,
            StixObjectEnum::Relationship(o) => o.common.created,
            StixObjectEnum::Custom(v) => v.get("created").and_then(|c| c.as_str()).and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)).unwrap_or_else(chrono::Utc::now),
            _ => chrono::Utc::now(),
        }
    }

    pub fn labels(&self) -> Option<&Vec<String>> {
        match self {
            StixObjectEnum::Indicator(o) => o.common.labels.as_ref(),
            StixObjectEnum::Malware(o) => o.common.labels.as_ref(),
            StixObjectEnum::ThreatActor(o) => o.common.labels.as_ref(),
            StixObjectEnum::Identity(o) => o.common.labels.as_ref(),
            StixObjectEnum::IntrusionSet(o) => o.common.labels.as_ref(),
            StixObjectEnum::Campaign(o) => o.common.labels.as_ref(),
            _ => None,
        }
    }

    pub fn id(&self) -> String {
        match self {
            StixObjectEnum::Identity(o) => o.id().to_string(),
            StixObjectEnum::Malware(o) => o.id().to_string(),
            StixObjectEnum::Indicator(o) => o.id().to_string(),
            StixObjectEnum::ObservedData(o) => o.id().to_string(),
            StixObjectEnum::MalwareAnalysis(o) => o.id().to_string(),
            StixObjectEnum::Sighting(o) => o.id().to_string(),
            StixObjectEnum::Relationship(o) => o.id().to_string(),
            StixObjectEnum::File(o) => {
                if let Some(hashes) = &o.hashes {
                    if let Some(h) = hashes.get("SHA-256").or(hashes.get("MD5")) {
                        return generate_sco_id("file", h);
                    }
                }
                generate_sco_id("file", o.name.as_deref().unwrap_or("unknown"))
            },
            StixObjectEnum::Incident(o) => o.id().to_string(),
            StixObjectEnum::Location(o) => o.id().to_string(),
            StixObjectEnum::NetworkTraffic(_) => generate_sco_id("network-traffic", "unknown"),
            StixObjectEnum::DomainName(o) => generate_sco_id("domain-name", &o.value),
            StixObjectEnum::IPv4Addr(o) => generate_sco_id("ipv4-addr", &o.value),
            StixObjectEnum::Url(o) => generate_sco_id("url", &o.value),
            StixObjectEnum::Process(_) => generate_sco_id("process", "unknown"),
            StixObjectEnum::Artifact(_) => generate_sco_id("artifact", "unknown"),
            StixObjectEnum::IPv6Addr(o) => generate_sco_id("ipv6-addr", &o.value),
            StixObjectEnum::MacAddr(o) => generate_sco_id("mac-addr", &o.value),
            StixObjectEnum::Software(o) => generate_sco_id("software", o.name.as_deref().unwrap_or("unknown")),
            StixObjectEnum::UserAccount(o) => generate_sco_id("user-account", o.user_id.as_deref().unwrap_or("unknown")),
            StixObjectEnum::EmailAddr(o) => generate_sco_id("email-addr", &o.value),
            StixObjectEnum::EmailMessage(_) => generate_sco_id("email-message", "unknown"),
            StixObjectEnum::SocketAddr(_) => generate_sco_id("socket-addr", "unknown"),
            StixObjectEnum::AutonomousSystem(o) => generate_sco_id("autonomous-system", &o.number.map(|n| n.to_string()).unwrap_or_else(|| "unknown".to_string())),
            StixObjectEnum::SoftwarePackage(_) => generate_sco_id("software-package", "unknown"),
            StixObjectEnum::Directory(o) => generate_sco_id("directory", o.path.as_deref().unwrap_or("unknown")),
            StixObjectEnum::Mutex(o) => generate_sco_id("mutex", o.name.as_deref().unwrap_or("unknown")),
            StixObjectEnum::WindowsRegistryKey(o) => generate_sco_id("windows-registry-key", o.key.as_deref().unwrap_or("unknown")),
            StixObjectEnum::X509Certificate(_) => generate_sco_id("x509-certificate", "unknown"),
            StixObjectEnum::AttackPattern(o) => o.id().to_string(),
            StixObjectEnum::Campaign(o) => o.id().to_string(),
            StixObjectEnum::ThreatActor(o) => o.id().to_string(),
            StixObjectEnum::Tool(o) => o.id().to_string(),
            StixObjectEnum::Vulnerability(o) => o.id().to_string(),
            StixObjectEnum::CourseOfAction(o) => o.id().to_string(),
            StixObjectEnum::IntrusionSet(o) => o.id().to_string(),
            StixObjectEnum::Infrastructure(o) => o.id().to_string(),
            StixObjectEnum::Report(o) => o.id().to_string(),
            StixObjectEnum::Note(o) => o.id().to_string(),
            StixObjectEnum::Opinion(o) => o.id().to_string(),
            StixObjectEnum::Grouping(o) => o.id().to_string(),
            StixObjectEnum::MarkingDefinition(o) => o.id().to_string(),
            StixObjectEnum::LanguageContent(o) => o.id().to_string(),
            StixObjectEnum::ExtensionDefinition(o) => o.id().to_string(),
            StixObjectEnum::Custom(v) => v.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string()),
        }
    }

    /// Get the type of the wrapped object
    pub fn type_(&self) -> &str {
        match self {
            StixObjectEnum::Identity(o) => o.type_(),
            StixObjectEnum::Malware(o) => o.type_(),
            StixObjectEnum::Indicator(o) => o.type_(),
            StixObjectEnum::ObservedData(o) => o.type_(),
            StixObjectEnum::MalwareAnalysis(o) => o.type_(),
            StixObjectEnum::Sighting(o) => o.type_(),
            StixObjectEnum::Relationship(o) => o.type_(),
            StixObjectEnum::File(_) => "file",
            StixObjectEnum::Incident(o) => o.type_(),
            StixObjectEnum::Location(o) => o.type_(),
            StixObjectEnum::NetworkTraffic(_) => "network-traffic",
            StixObjectEnum::DomainName(_) => "domain-name",
            StixObjectEnum::IPv4Addr(_) => "ipv4-addr",
            StixObjectEnum::Url(_) => "url",
            StixObjectEnum::Process(_) => "process",
            StixObjectEnum::Artifact(_) => "artifact",
            StixObjectEnum::IPv6Addr(_) => "ipv6-addr",
            StixObjectEnum::MacAddr(_) => "mac-addr",
            StixObjectEnum::Software(_) => "software",
            StixObjectEnum::UserAccount(_) => "user-account",
            StixObjectEnum::EmailAddr(_) => "email-addr",
            StixObjectEnum::EmailMessage(_) => "email-message",
            StixObjectEnum::SocketAddr(_) => "socket-addr",
            StixObjectEnum::AutonomousSystem(_) => "autonomous-system",
            StixObjectEnum::SoftwarePackage(_) => "software-package",
            StixObjectEnum::Directory(_) => "directory",
            StixObjectEnum::Mutex(_) => "mutex",
            StixObjectEnum::WindowsRegistryKey(_) => "windows-registry-key",
            StixObjectEnum::X509Certificate(_) => "x509-certificate",
            StixObjectEnum::AttackPattern(o) => o.type_(),
            StixObjectEnum::Campaign(o) => o.type_(),
            StixObjectEnum::ThreatActor(o) => o.type_(),
            StixObjectEnum::Tool(o) => o.type_(),
            StixObjectEnum::Vulnerability(o) => o.type_(),
            StixObjectEnum::CourseOfAction(o) => o.type_(),
            StixObjectEnum::IntrusionSet(o) => o.type_(),
            StixObjectEnum::Infrastructure(o) => o.type_(),
            StixObjectEnum::Report(o) => o.type_(),
            StixObjectEnum::Note(o) => o.type_(),
            StixObjectEnum::Opinion(o) => o.type_(),
            StixObjectEnum::Grouping(o) => o.type_(),
            StixObjectEnum::MarkingDefinition(o) => o.type_(),
            StixObjectEnum::LanguageContent(o) => o.type_(),
            StixObjectEnum::ExtensionDefinition(o) => o.type_(),
            StixObjectEnum::Custom(v) => v.get("type").and_then(|t| t.as_str()).unwrap_or("unknown"),
        }
    }
}

// Custom Deserialize impl: internal tag combined with flattened `type` fields in
// the inner structs requires us to inspect the `type` field first and then
// deserialize the whole value into the appropriate struct (including its
// own `type` field via the flattened `CommonProperties`).
impl<'de> Deserialize<'de> for StixObjectEnum {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = Value::deserialize(deserializer).map_err(serde::de::Error::custom)?;
        let t = v
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("missing or invalid `type` field"))?;
        match t {
            "identity" => Ok(StixObjectEnum::Identity(serde_json::from_value(v).map_err(serde::de::Error::custom)?)),
            "malware" => Ok(StixObjectEnum::Malware(serde_json::from_value(v).map_err(serde::de::Error::custom)?)),
            "indicator" => Ok(StixObjectEnum::Indicator(serde_json::from_value(v).map_err(serde::de::Error::custom)?)),
            "observed-data" => Ok(StixObjectEnum::ObservedData(serde_json::from_value(v).map_err(serde::de::Error::custom)?)),
            "file" => Ok(StixObjectEnum::File(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "network-traffic" => Ok(StixObjectEnum::NetworkTraffic(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "domain-name" => Ok(StixObjectEnum::DomainName(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "ipv4-addr" => Ok(StixObjectEnum::IPv4Addr(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "ipv6-addr" => Ok(StixObjectEnum::IPv6Addr(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "url" => Ok(StixObjectEnum::Url(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "process" => Ok(StixObjectEnum::Process(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "artifact" => Ok(StixObjectEnum::Artifact(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "mac-addr" => Ok(StixObjectEnum::MacAddr(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "software" => Ok(StixObjectEnum::Software(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "user-account" => Ok(StixObjectEnum::UserAccount(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "email-addr" => Ok(StixObjectEnum::EmailAddr(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "email-message" => Ok(StixObjectEnum::EmailMessage(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "socket-addr" => Ok(StixObjectEnum::SocketAddr(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "autonomous-system" => Ok(StixObjectEnum::AutonomousSystem(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "software-package" => Ok(StixObjectEnum::SoftwarePackage(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "directory" => Ok(StixObjectEnum::Directory(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "mutex" => Ok(StixObjectEnum::Mutex(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "windows-registry-key" => Ok(StixObjectEnum::WindowsRegistryKey(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "x509-certificate" => Ok(StixObjectEnum::X509Certificate(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "malware-analysis" => Ok(StixObjectEnum::MalwareAnalysis(serde_json::from_value(v).map_err(serde::de::Error::custom)?)),
            "sighting" => Ok(StixObjectEnum::Sighting(serde_json::from_value(v).map_err(serde::de::Error::custom)?)),
            "grouping" => Ok(StixObjectEnum::Grouping(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "incident" => Ok(StixObjectEnum::Incident(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "location" => Ok(StixObjectEnum::Location(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "opinion" => Ok(StixObjectEnum::Opinion(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "relationship" => Ok(StixObjectEnum::Relationship(serde_json::from_value(v).map_err(serde::de::Error::custom)?)),
            "marking-definition" => Ok(StixObjectEnum::MarkingDefinition(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "language-content" => Ok(StixObjectEnum::LanguageContent(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "extension-definition" => Ok(StixObjectEnum::ExtensionDefinition(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            other if other.starts_with("x-") => Ok(StixObjectEnum::Custom(v.clone())),
            "attack-pattern" => Ok(StixObjectEnum::AttackPattern(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "campaign" => Ok(StixObjectEnum::Campaign(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "threat-actor" => Ok(StixObjectEnum::ThreatActor(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "tool" => Ok(StixObjectEnum::Tool(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "vulnerability" => Ok(StixObjectEnum::Vulnerability(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "course-of-action" => Ok(StixObjectEnum::CourseOfAction(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "intrusion-set" => Ok(StixObjectEnum::IntrusionSet(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "infrastructure" => Ok(StixObjectEnum::Infrastructure(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "report" => Ok(StixObjectEnum::Report(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            "note" => Ok(StixObjectEnum::Note(serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?)),
            other => Err(serde::de::Error::custom(format!("unknown type: {}", other))),
        }
    }
}

