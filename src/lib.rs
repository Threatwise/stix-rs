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
    IPv4Addr(IPv4Addr),
    Url(Url),
    Process(Process),
    Artifact(Artifact),
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
}

impl StixObjectEnum {
    /// Get the ID of the wrapped object
    pub fn id(&self) -> &str {
        match self {
            StixObjectEnum::Identity(o) => o.id(),
            StixObjectEnum::Malware(o) => o.id(),
            StixObjectEnum::Indicator(o) => o.id(),
            StixObjectEnum::ObservedData(o) => o.id(),
            StixObjectEnum::MalwareAnalysis(o) => o.id(),
            StixObjectEnum::Sighting(o) => o.id(),
            StixObjectEnum::Relationship(o) => o.id(),
            StixObjectEnum::File(_) => "",
            StixObjectEnum::Incident(o) => o.id(),
            StixObjectEnum::Location(o) => o.id(),
            StixObjectEnum::NetworkTraffic(_) => "",
            StixObjectEnum::DomainName(_) => "",
            StixObjectEnum::IPv4Addr(_) => "",
            StixObjectEnum::Url(_) => "",
            StixObjectEnum::Process(_) => "",
            StixObjectEnum::Artifact(_) => "",
            StixObjectEnum::IPv6Addr(_) => "",
            StixObjectEnum::MacAddr(_) => "",
            StixObjectEnum::Software(_) => "",
            StixObjectEnum::UserAccount(_) => "",
            StixObjectEnum::EmailAddr(_) => "",
            StixObjectEnum::EmailMessage(_) => "",
            StixObjectEnum::SocketAddr(_) => "",
            StixObjectEnum::AutonomousSystem(_) => "",
            StixObjectEnum::SoftwarePackage(_) => "",
            StixObjectEnum::Directory(_) => "",
            StixObjectEnum::Mutex(_) => "",
            StixObjectEnum::WindowsRegistryKey(_) => "",
            StixObjectEnum::X509Certificate(_) => "",
            StixObjectEnum::AttackPattern(o) => o.id(),
            StixObjectEnum::Campaign(o) => o.id(),
            StixObjectEnum::ThreatActor(o) => o.id(),
            StixObjectEnum::Tool(o) => o.id(),
            StixObjectEnum::Vulnerability(o) => o.id(),
            StixObjectEnum::CourseOfAction(o) => o.id(),
            StixObjectEnum::IntrusionSet(o) => o.id(),
            StixObjectEnum::Infrastructure(o) => o.id(),
            StixObjectEnum::Report(o) => o.id(),
            StixObjectEnum::Note(o) => o.id(),
            StixObjectEnum::Opinion(o) => o.id(),
            StixObjectEnum::Grouping(o) => o.id(),
            StixObjectEnum::MarkingDefinition(o) => o.id(),
            StixObjectEnum::LanguageContent(o) => o.id(),
            StixObjectEnum::ExtensionDefinition(o) => o.id(),
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
            other => Err(serde::de::Error::custom(format!("unknown type: {}", other))),
        }
    }
}

