//! Vocabulary / enumerations for STIX

use serde::{Deserialize, Serialize};

/// Identity class vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityClass {
    Individual,
    Group,
    System,
    Organization,
    Class,
    Unspecified,
}

/// Indicator pattern types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndicatorPatternType {
    Stix,
    Pcre,
    Snort,
    Suricata,
    Yara,
}

/// Hash algorithm vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    #[serde(rename = "md5")]
    Md5,

    #[serde(rename = "sha-1")]
    Sha1,

    #[serde(rename = "sha-256")]
    Sha256,

    #[serde(rename = "sha-512")]
    Sha512,
}

/// Relationship types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationshipType {
    Targets,
    Uses,
    LocatedAt,
    AttributedTo,
    Indicates,
    VariantOf,
}

/// Implementation Language vocabulary (for malware, tools, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImplementationLanguage {
    Applescript,
    Bash,
    C,
    #[serde(rename = "c++")]
    Cpp,
    #[serde(rename = "c#")]
    Csharp,
    Go,
    Java,
    Javascript,
    Lua,
    #[serde(rename = "objective-c")]
    ObjectiveC,
    Perl,
    Php,
    Powershell,
    Python,
    Ruby,
    Scala,
    Swift,
    #[serde(rename = "typescript")]
    TypeScript,
    #[serde(rename = "visual-basic")]
    VisualBasic,
    #[serde(rename = "x86-32")]
    X8632,
    #[serde(rename = "x86-64")]
    X8664,
}

/// Indicator Type vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndicatorType {
    AnomalousActivity,
    Anonymization,
    Benign,
    Compromised,
    MaliciousActivity,
    Attribution,
    Unknown,
}

/// Malware Type vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MalwareType {
    Adware,
    Backdoor,
    Bot,
    Bootkit,
    #[serde(rename = "ddos")]
    Ddos,
    Downloader,
    Dropper,
    #[serde(rename = "exploit-kit")]
    ExploitKit,
    Keylogger,
    Ransomware,
    #[serde(rename = "remote-access-trojan")]
    RemoteAccessTrojan,
    ResourceExploitation,
    Rogue,
    Rootkit,
    #[serde(rename = "screen-capture")]
    ScreenCapture,
    Spyware,
    Trojan,
    Virus,
    Webshell,
    Wiper,
    Worm,
}

/// Threat Actor Type vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatActorType {
    Activist,
    Competitor,
    #[serde(rename = "crime-syndicate")]
    CrimeSyndicate,
    Criminal,
    Hacker,
    #[serde(rename = "insider-accidental")]
    InsiderAccidental,
    #[serde(rename = "insider-disgruntled")]
    InsiderDisgruntled,
    #[serde(rename = "nation-state")]
    NationState,
    Sensationalist,
    Spy,
    Terrorist,
    Unknown,
}

/// Threat Actor Role vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatActorRole {
    Agent,
    Director,
    Independent,
    Infrastructor,
    Sponsor,
}

/// Threat Actor Sophistication vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatActorSophistication {
    None,
    Minimal,
    Intermediate,
    Advanced,
    Expert,
    Innovator,
    Strategic,
}

/// Attack Motivation vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttackMotivation {
    Accidental,
    Coercion,
    Dominance,
    Ideology,
    #[serde(rename = "notoriety")]
    Notoriety,
    #[serde(rename = "organizational-gain")]
    OrganizationalGain,
    #[serde(rename = "personal-gain")]
    PersonalGain,
    #[serde(rename = "personal-satisfaction")]
    PersonalSatisfaction,
    Revenge,
    Unpredictable,
}

/// Attack Resource Level vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttackResourceLevel {
    Individual,
    Club,
    Contest,
    Team,
    Organization,
    Government,
}

/// Tool Type vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolType {
    #[serde(rename = "denial-of-service")]
    DenialOfService,
    Exploitation,
    #[serde(rename = "information-gathering")]
    InformationGathering,
    #[serde(rename = "network-capture")]
    NetworkCapture,
    #[serde(rename = "credential-exploitation")]
    CredentialExploitation,
    #[serde(rename = "remote-access")]
    RemoteAccess,
    #[serde(rename = "vulnerability-scanning")]
    VulnerabilityScanning,
    Unknown,
}

/// Infrastructure Type vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InfrastructureType {
    #[serde(rename = "amplification")]
    Amplification,
    #[serde(rename = "anonymization")]
    Anonymization,
    #[serde(rename = "botnet")]
    Botnet,
    #[serde(rename = "command-and-control")]
    CommandAndControl,
    #[serde(rename = "exfiltration")]
    Exfiltration,
    #[serde(rename = "hosting-malware")]
    HostingMalware,
    #[serde(rename = "hosting-target-lists")]
    HostingTargetLists,
    #[serde(rename = "phishing")]
    Phishing,
    #[serde(rename = "reconnaissance")]
    Reconnaissance,
    #[serde(rename = "staging")]
    Staging,
    Unknown,
}

/// Report Type vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportType {
    #[serde(rename = "attack-pattern")]
    AttackPattern,
    Campaign,
    Identity,
    Indicator,
    Intrusion,
    Malware,
    #[serde(rename = "observed-data")]
    ObservedData,
    #[serde(rename = "threat-actor")]
    ThreatActor,
    #[serde(rename = "threat-report")]
    ThreatReport,
    Tool,
    Vulnerability,
}

/// Industry Sector vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndustrySector {
    Agriculture,
    Aerospace,
    Automotive,
    Chemical,
    Commercial,
    Communications,
    Construction,
    Defense,
    Education,
    Energy,
    Entertainment,
    #[serde(rename = "financial-services")]
    FinancialServices,
    Government,
    #[serde(rename = "government-emergency-services")]
    GovernmentEmergencyServices,
    #[serde(rename = "government-local")]
    GovernmentLocal,
    #[serde(rename = "government-national")]
    GovernmentNational,
    #[serde(rename = "government-public-services")]
    GovernmentPublicServices,
    #[serde(rename = "government-regional")]
    GovernmentRegional,
    Healthcare,
    #[serde(rename = "hospitality-leisure")]
    HospitalityLeisure,
    Infrastructure,
    #[serde(rename = "infrastructure-dams")]
    InfrastructureDams,
    #[serde(rename = "infrastructure-nuclear")]
    InfrastructureNuclear,
    #[serde(rename = "infrastructure-water")]
    InfrastructureWater,
    Insurance,
    Manufacturing,
    Mining,
    #[serde(rename = "non-profit")]
    NonProfit,
    Petroleum,
    Pharmaceuticals,
    Retail,
    Technology,
    Telecommunications,
    Transportation,
    Utilities,
}

/// Encryption Algorithm vocabulary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EncryptionAlgorithm {
    #[serde(rename = "AES-256-GCM")]
    Aes256Gcm,
    #[serde(rename = "ChaCha20-Poly1305")]
    ChaCha20Poly1305,
    #[serde(rename = "AES-128-GCM")]
    Aes128Gcm,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn identity_class_serializes() {
        let j = serde_json::to_string(&IdentityClass::System).unwrap();
        assert_eq!(j, "\"system\"");

        let j2 = serde_json::to_string(&IdentityClass::Unspecified).unwrap();
        assert_eq!(j2, "\"unspecified\"");
    }

    #[test]
    fn indicator_pattern_serializes() {
        let j = serde_json::to_string(&IndicatorPatternType::Stix).unwrap();
        assert_eq!(j, "\"stix\"");

        let j2 = serde_json::to_string(&IndicatorPatternType::Yara).unwrap();
        assert_eq!(j2, "\"yara\"");
    }

    #[test]
    fn hash_algorithm_serializes() {
        assert_eq!(
            serde_json::to_string(&HashAlgorithm::Md5).unwrap(),
            "\"md5\""
        );
        assert_eq!(
            serde_json::to_string(&HashAlgorithm::Sha1).unwrap(),
            "\"sha-1\""
        );
        assert_eq!(
            serde_json::to_string(&HashAlgorithm::Sha256).unwrap(),
            "\"sha-256\""
        );
        assert_eq!(
            serde_json::to_string(&HashAlgorithm::Sha512).unwrap(),
            "\"sha-512\""
        );
    }

    #[test]
    fn relationship_type_serializes() {
        assert_eq!(
            serde_json::to_string(&RelationshipType::Targets).unwrap(),
            "\"targets\""
        );
        assert_eq!(
            serde_json::to_string(&RelationshipType::LocatedAt).unwrap(),
            "\"located-at\""
        );
        assert_eq!(
            serde_json::to_string(&RelationshipType::AttributedTo).unwrap(),
            "\"attributed-to\""
        );
    }

    #[test]
    fn implementation_language_serializes() {
        assert_eq!(
            serde_json::to_string(&ImplementationLanguage::Python).unwrap(),
            "\"python\""
        );
        assert_eq!(
            serde_json::to_string(&ImplementationLanguage::Cpp).unwrap(),
            "\"c++\""
        );
        assert_eq!(
            serde_json::to_string(&ImplementationLanguage::Csharp).unwrap(),
            "\"c#\""
        );
        assert_eq!(
            serde_json::to_string(&ImplementationLanguage::Javascript).unwrap(),
            "\"javascript\""
        );
    }

    #[test]
    fn indicator_type_serializes() {
        assert_eq!(
            serde_json::to_string(&IndicatorType::MaliciousActivity).unwrap(),
            "\"malicious-activity\""
        );
        assert_eq!(
            serde_json::to_string(&IndicatorType::AnomalousActivity).unwrap(),
            "\"anomalous-activity\""
        );
        assert_eq!(
            serde_json::to_string(&IndicatorType::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    #[test]
    fn malware_type_serializes() {
        assert_eq!(
            serde_json::to_string(&MalwareType::Ransomware).unwrap(),
            "\"ransomware\""
        );
        assert_eq!(
            serde_json::to_string(&MalwareType::RemoteAccessTrojan).unwrap(),
            "\"remote-access-trojan\""
        );
        assert_eq!(
            serde_json::to_string(&MalwareType::Backdoor).unwrap(),
            "\"backdoor\""
        );
    }

    #[test]
    fn threat_actor_type_serializes() {
        assert_eq!(
            serde_json::to_string(&ThreatActorType::NationState).unwrap(),
            "\"nation-state\""
        );
        assert_eq!(
            serde_json::to_string(&ThreatActorType::Criminal).unwrap(),
            "\"criminal\""
        );
    }

    #[test]
    fn tool_type_serializes() {
        assert_eq!(
            serde_json::to_string(&ToolType::RemoteAccess).unwrap(),
            "\"remote-access\""
        );
        assert_eq!(
            serde_json::to_string(&ToolType::Exploitation).unwrap(),
            "\"exploitation\""
        );
    }

    #[test]
    fn infrastructure_type_serializes() {
        assert_eq!(
            serde_json::to_string(&InfrastructureType::CommandAndControl).unwrap(),
            "\"command-and-control\""
        );
        assert_eq!(
            serde_json::to_string(&InfrastructureType::Botnet).unwrap(),
            "\"botnet\""
        );
    }
}
