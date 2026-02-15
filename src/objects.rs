use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};
use crate::vocab::{IdentityClass, IndicatorPatternType};
fn default_pattern_type() -> IndicatorPatternType { IndicatorPatternType::Stix }
fn default_valid_from() -> DateTime<Utc> { Utc::now() }
use crate::pattern::validate_pattern;

// Re-export BuilderError from sdos to avoid duplication
pub use crate::sdos::BuilderError;

/// A kill chain phase (used by Malware and Indicator)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, )]
#[serde(rename_all = "snake_case")]
pub struct KillChainPhase {
    #[serde(rename = "kill_chain_name")]
    pub name: String,

    #[serde(rename = "phase_name")]
    pub phase_name: String,
}

/// Identity Domain Object
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, )]
#[serde(rename_all = "snake_case")]
pub struct Identity {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: String,

    pub identity_class: Option<IdentityClass>,

    pub sectors: Option<Vec<String>>,
}

impl Identity {
    pub fn builder() -> IdentityBuilder {
        IdentityBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct IdentityBuilder {
    name: Option<String>,
    identity_class: Option<IdentityClass>,
    sectors: Option<Vec<String>>,
    created_by_ref: Option<String>,
    custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl IdentityBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set identity class (e.g., System, Organization)
    pub fn identity_class(mut self, identity_class: IdentityClass) -> Self {
        self.identity_class = Some(identity_class);
        self
    }

    // Backwards-compatible alias
    pub fn class(self, identity_class: IdentityClass) -> Self {
        self.identity_class(identity_class)
    }

    pub fn sectors(mut self, sectors: Vec<String>) -> Self {
        self.sectors = Some(sectors);
        self
    }

    /// Add a custom/stix extension property (e.g., x_my_tag)
    pub fn property(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.custom_properties.insert(key.into(), value.into());
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(mut self) -> Result<Identity, BuilderError> {
        let name = self.name.ok_or(BuilderError::MissingField("name"))?;
        let identity_class = self.identity_class;

        let mut common = CommonProperties::new("identity", self.created_by_ref);
        // Attach any custom properties provided by the builder
        if !self.custom_properties.is_empty() {
            common.custom_properties.extend(self.custom_properties.drain());
        }

        Ok(Identity {
            common,
            name,
            identity_class,
            sectors: self.sectors,
        })
    }
}

impl StixObject for Identity {
    fn id(&self) -> &str {
        &self.common.id
    }

    fn type_(&self) -> &str {
        &self.common.r#type
    }

    fn created(&self) -> DateTime<Utc> {
        self.common.created
    }
}

// Allow converting domain objects into the StixObjectEnum for easy bundling
impl From<Identity> for crate::StixObjectEnum {
    fn from(i: Identity) -> Self {
        crate::StixObjectEnum::Identity(i)
    }
}
/// Malware Domain Object
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, )]
#[serde(rename_all = "snake_case")]
pub struct Malware {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: String,

    pub description: Option<String>,

        #[serde(default)]
    pub malware_types: Vec<String>,

        #[serde(default)]
    pub is_family: bool,

    pub aliases: Option<Vec<String>>,

    pub kill_chain_phases: Option<Vec<KillChainPhase>>,

    pub first_seen: Option<DateTime<Utc>>,

    pub last_seen: Option<DateTime<Utc>>,

    pub operating_system_refs: Option<Vec<String>>,

    pub architecture_execution_envs: Option<Vec<String>>,

    pub implementation_languages: Option<Vec<String>>,

    pub capabilities: Option<Vec<String>>,

    pub sample_refs: Option<Vec<String>>,
}

impl Malware {
    pub fn builder() -> MalwareBuilder {
        MalwareBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct MalwareBuilder {
    name: Option<String>,
    description: Option<String>,
    is_family: Option<bool>,
    malware_types: Option<Vec<String>>,
    aliases: Option<Vec<String>>,
    kill_chain_phases: Option<Vec<KillChainPhase>>,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    operating_system_refs: Option<Vec<String>>,
    architecture_execution_envs: Option<Vec<String>>,
    implementation_languages: Option<Vec<String>>,
    capabilities: Option<Vec<String>>,
    sample_refs: Option<Vec<String>>,
    created_by_ref: Option<String>,
}

impl MalwareBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn is_family(mut self, is_family: bool) -> Self {
        self.is_family = Some(is_family);
        self
    }

    pub fn malware_types(mut self, types: Vec<String>) -> Self {
        self.malware_types = Some(types);
        self
    }

    pub fn aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = Some(aliases);
        self
    }

    pub fn kill_chain_phases(mut self, phases: Vec<KillChainPhase>) -> Self {
        self.kill_chain_phases = Some(phases);
        self
    }

    pub fn first_seen(mut self, t: DateTime<Utc>) -> Self {
        self.first_seen = Some(t);
        self
    }

    pub fn last_seen(mut self, t: DateTime<Utc>) -> Self {
        self.last_seen = Some(t);
        self
    }

    pub fn operating_system_refs(mut self, refs: Vec<String>) -> Self {
        self.operating_system_refs = Some(refs);
        self
    }

    pub fn architecture_execution_envs(mut self, envs: Vec<String>) -> Self {
        self.architecture_execution_envs = Some(envs);
        self
    }

    pub fn implementation_languages(mut self, langs: Vec<String>) -> Self {
        self.implementation_languages = Some(langs);
        self
    }

    pub fn capabilities(mut self, caps: Vec<String>) -> Self {
        self.capabilities = Some(caps);
        self
    }

    pub fn sample_refs(mut self, refs: Vec<String>) -> Self {
        self.sample_refs = Some(refs);
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<Malware, BuilderError> {
        let name = self.name.ok_or(BuilderError::MissingField("name"))?;
        let is_family = self.is_family.unwrap_or(false);
        let malware_types = self.malware_types.unwrap_or_default();

        let common = CommonProperties::new("malware", self.created_by_ref);

        Ok(Malware {
            common,
            name,
            description: self.description,
            malware_types,
            is_family,
            aliases: self.aliases,
            kill_chain_phases: self.kill_chain_phases,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            operating_system_refs: self.operating_system_refs,
            architecture_execution_envs: self.architecture_execution_envs,
            implementation_languages: self.implementation_languages,
            capabilities: self.capabilities,
            sample_refs: self.sample_refs,
        })
    }
}

impl StixObject for Malware {
    fn id(&self) -> &str {
        &self.common.id
    }

    fn type_(&self) -> &str {
        &self.common.r#type
    }

    fn created(&self) -> DateTime<Utc> {
        self.common.created
    }
}

/// Indicator Domain Object
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, )]
#[serde(rename_all = "snake_case")]
pub struct Indicator {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: Option<String>,

    pub description: Option<String>,

    pub indicator_types: Option<Vec<String>>,

    pub pattern: String,

    #[serde(default = "default_pattern_type")]
    pub pattern_type: IndicatorPatternType,

    pub pattern_version: Option<String>,

    #[serde(default = "default_valid_from")]
    pub valid_from: DateTime<Utc>,

    pub valid_until: Option<DateTime<Utc>>,

    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
}

impl Indicator {
    pub fn builder() -> IndicatorBuilder {
        IndicatorBuilder::default()
    }

    /// Validate the pattern syntax
    pub fn validate_pattern(&self) -> Result<(), crate::pattern::PatternError> {
        if self.pattern_type == IndicatorPatternType::Stix {
            validate_pattern(&self.pattern)
        } else {
            // Other pattern types (PCRE, Snort, etc.) aren't validated
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
pub struct IndicatorBuilder {
    name: Option<String>,
    description: Option<String>,
    indicator_types: Option<Vec<String>>,
    pattern: Option<String>,
    pattern_type: Option<IndicatorPatternType>,
    pattern_version: Option<String>,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    kill_chain_phases: Option<Vec<KillChainPhase>>,
    created_by_ref: Option<String>,
    validate_pattern: bool,
}

impl IndicatorBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn indicator_types(mut self, types: Vec<String>) -> Self {
        self.indicator_types = Some(types);
        self
    }

    pub fn pattern(mut self, pattern: impl Into<String>) -> Self {
        self.pattern = Some(pattern.into());
        self
    }

    pub fn pattern_type(mut self, pt: IndicatorPatternType) -> Self {
        self.pattern_type = Some(pt);
        self
    }

    pub fn pattern_version(mut self, version: impl Into<String>) -> Self {
        self.pattern_version = Some(version.into());
        self
    }

    pub fn valid_from(mut self, t: DateTime<Utc>) -> Self {
        self.valid_from = Some(t);
        self
    }

    pub fn valid_until(mut self, t: DateTime<Utc>) -> Self {
        self.valid_until = Some(t);
        self
    }

    pub fn kill_chain_phases(mut self, phases: Vec<KillChainPhase>) -> Self {
        self.kill_chain_phases = Some(phases);
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    /// Enable pattern validation (default: false)
    pub fn validate_pattern(mut self, validate: bool) -> Self {
        self.validate_pattern = validate;
        self
    }

    pub fn build(self) -> Result<Indicator, BuilderError> {
        let pattern = self.pattern.ok_or(BuilderError::MissingField("pattern"))?;
        let pattern_type = self.pattern_type.ok_or(BuilderError::MissingField("pattern_type"))?;
        let valid_from = self.valid_from.ok_or(BuilderError::MissingField("valid_from"))?;

        // Optionally validate STIX patterns
        if self.validate_pattern && pattern_type == IndicatorPatternType::Stix {
            validate_pattern(&pattern)
                .map_err(|_| BuilderError::MissingField("invalid pattern"))?;
        }

        let common = CommonProperties::new("indicator", self.created_by_ref);

        Ok(Indicator {
            common,
            name: self.name,
            description: self.description,
            indicator_types: self.indicator_types,
            pattern,
            pattern_type,
            pattern_version: self.pattern_version,
            valid_from,
            valid_until: self.valid_until,
            kill_chain_phases: self.kill_chain_phases,
        })
    }
}

impl StixObject for Indicator {
    fn id(&self) -> &str {
        &self.common.id
    }

    fn type_(&self) -> &str {
        &self.common.r#type
    }

    fn created(&self) -> DateTime<Utc> {
        self.common.created
    }
}

impl From<Indicator> for crate::StixObjectEnum {
    fn from(i: Indicator) -> Self {
        crate::StixObjectEnum::Indicator(i)
    }
}

impl From<Malware> for crate::StixObjectEnum {
    fn from(m: Malware) -> Self {
        crate::StixObjectEnum::Malware(m)
    }
}

/// Sighting Domain Object
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, )]
#[serde(rename_all = "snake_case")]
pub struct Sighting {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub count: u32,

    pub sighting_of_ref: String,

    pub where_sighted_refs: Vec<String>,
}

impl Sighting {
    pub fn builder() -> SightingBuilder {
        SightingBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct SightingBuilder {
    count: Option<u32>,
    sighting_of_ref: Option<String>,
    where_sighted_refs: Option<Vec<String>>,
    created_by_ref: Option<String>,
}

impl SightingBuilder {
    pub fn count(mut self, count: u32) -> Self {
        self.count = Some(count);
        self
    }

    pub fn sighting_of_ref(mut self, r: impl Into<String>) -> Self {
        self.sighting_of_ref = Some(r.into());
        self
    }

    pub fn where_sighted_refs(mut self, refs: Vec<String>) -> Self {
        self.where_sighted_refs = Some(refs);
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<Sighting, BuilderError> {
        let count = self.count.ok_or(BuilderError::MissingField("count"))?;
        let sighting_of_ref = self.sighting_of_ref.ok_or(BuilderError::MissingField("sighting_of_ref"))?;
        let where_sighted_refs = self.where_sighted_refs.ok_or(BuilderError::MissingField("where_sighted_refs"))?;

        let common = CommonProperties::new("sighting", self.created_by_ref);

        Ok(Sighting {
            common,
            count,
            sighting_of_ref,
            where_sighted_refs,
        })
    }
}

impl StixObject for Sighting {
    fn id(&self) -> &str {
        &self.common.id
    }

    fn type_(&self) -> &str {
        &self.common.r#type
    }

    fn created(&self) -> DateTime<Utc> {
        self.common.created
    }
}

impl From<Sighting> for crate::StixObjectEnum {
    fn from(s: Sighting) -> Self {
        crate::StixObjectEnum::Sighting(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vocab::{IdentityClass, IndicatorPatternType};
fn default_pattern_type() -> IndicatorPatternType { IndicatorPatternType::Stix }
fn default_valid_from() -> DateTime<Utc> { Utc::now() }
    use serde_json::Value;

    #[test]
    fn identity_builder_and_serialize() {
        let idty = Identity::builder()
            .name("ACME")
            .class(IdentityClass::Organization)
            .sectors(vec!["technology".into()])
            .build()
            .unwrap();

        let s = serde_json::to_string(&idty).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v.get("type").and_then(Value::as_str).unwrap(), "identity");
        assert_eq!(v.get("identity-class").and_then(Value::as_str).unwrap(), "organization");
        let id_field = v.get("id").and_then(Value::as_str).unwrap();
        assert!(id_field.starts_with("identity--"));
    }

    #[test]
    fn malware_builder_and_serialize() {
        let mw = Malware::builder()
            .name("BadWare")
            .is_family(true)
            .malware_types(vec!["ransomware".into()])
            .build()
            .unwrap();

        let s = serde_json::to_string(&mw).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v.get("type").and_then(Value::as_str).unwrap(), "malware");
        assert_eq!(v.get("is-family").and_then(Value::as_bool).unwrap(), true);
    }

    #[test]
    fn indicator_builder_and_serialize() {
        let ind = Indicator::builder()
            .name("Test")
            .pattern("[file:hashes.'SHA-256' = '...']")
            .pattern_type(IndicatorPatternType::Stix)
            .valid_from(Utc::now())
            .build()
            .unwrap();

        let s = serde_json::to_string(&ind).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v.get("type").and_then(Value::as_str).unwrap(), "indicator");
        assert_eq!(v.get("pattern-type").and_then(Value::as_str).unwrap(), "stix");
    }

    #[test]
    fn sighting_builder_and_serialize() {
        let s = Sighting::builder()
            .count(2)
            .sighting_of_ref("malware--1111")
            .where_sighted_refs(vec!["sensor--1".into()])
            .build()
            .unwrap();

        let j = serde_json::to_string(&s).unwrap();
        let v: Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v.get("type").and_then(Value::as_str).unwrap(), "sighting");
        assert_eq!(v.get("sighting-of-ref").and_then(Value::as_str).unwrap(), "malware--1111");
    }

    #[test]
    fn missing_required_field_errors() {
        let r = Identity::builder().name("No Class").build();
        assert!(r.is_err());

        let r2 = Malware::builder().is_family(false).build();
        assert!(r2.is_err());
    }
}
