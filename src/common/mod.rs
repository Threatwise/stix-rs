use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// Trait implemented by STIX objects for basic accessors
pub trait StixObject {
    fn id(&self) -> &str;
    fn type_(&self) -> &str;
    fn created(&self) -> DateTime<Utc>;
}

/// Granular Marking - for marking specific portions of objects
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GranularMarking {
    pub marking_ref: Option<String>,
    pub selectors: Vec<String>,
    pub lang: Option<String>,
}

/// Common STIX properties shared by STIX domain objects
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CommonProperties {
    #[serde(rename = "type")]
    pub r#type: String,

    pub id: String,

    #[serde(rename = "spec_version")]
    pub spec_version: Option<String>,

    pub created: DateTime<Utc>,

    pub modified: DateTime<Utc>,

    pub created_by_ref: Option<String>,

    pub revoked: Option<bool>,

    pub labels: Option<Vec<String>>,

    pub confidence: Option<u8>,

    pub lang: Option<String>,

    pub external_references: Option<Vec<ExternalReference>>,

    pub object_marking_refs: Option<Vec<String>>,

    pub granular_markings: Option<Vec<GranularMarking>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<HashMap<String, Value>>,

    #[serde(flatten)]
    pub custom_properties: HashMap<String, Value>,
}

impl Default for CommonProperties {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            r#type: String::new(),
            id: generate_stix_id("object"),
            spec_version: Some("2.1".to_string()),
            created: now,
            modified: now,
            created_by_ref: None,
            revoked: None,
            labels: None,
            confidence: None,
            lang: None,
            external_references: None,
            object_marking_refs: None,
            granular_markings: None,
            extensions: None,
            custom_properties: HashMap::new(),
        }
    }
}

impl CommonProperties {
    pub fn new(object_type: impl Into<String>, created_by_ref: Option<String>) -> Self {
        let object_type = object_type.into();
        let mut cp = Self::default();
        cp.r#type = object_type.clone();
        cp.id = generate_stix_id(&object_type);
        cp.created_by_ref = created_by_ref;
        cp
    }

    /// Creates a new version of this object by updating the modified timestamp
    ///
    /// In STIX, when you update an object, you keep the same ID and created timestamp
    /// but update the modified timestamp to indicate a new version.
    ///
    /// # Examples
    ///
    /// ```
    /// use stix_rs::Malware;
    /// use chrono::Utc;
    ///
    /// let mut malware = Malware::builder()
    ///     .name("BadWare")
    ///     .malware_types(vec!["trojan".into()])
    ///     .build()
    ///     .unwrap();
    ///
    /// let original_modified = malware.common.modified;
    /// std::thread::sleep(std::time::Duration::from_millis(10));
    ///
    /// malware.common.new_version();
    /// assert!(malware.common.modified > original_modified);
    /// ```
    pub fn new_version(&mut self) {
        self.modified = Utc::now();
    }
}

impl StixObject for CommonProperties {
    fn id(&self) -> &str {
        &self.id
    }

    fn type_(&self) -> &str {
        &self.r#type
    }

    fn created(&self) -> DateTime<Utc> {
        self.created
    }
}

pub fn generate_stix_id(object_type: &str) -> String {
    format!("{}--{}", object_type, Uuid::new_v4())
}

/// Validates that a string is a valid STIX identifier
///
/// STIX IDs must follow the format: `object-type--<uuid>`
///
/// # Examples
///
/// ```
/// use stix_rs::common::is_valid_stix_id;
///
/// assert!(is_valid_stix_id("malware--12345678-1234-1234-1234-123456789abc"));
/// assert!(is_valid_stix_id("indicator--550e8400-e29b-41d4-a716-446655440000"));
/// assert!(!is_valid_stix_id("invalid"));
/// assert!(!is_valid_stix_id("malware-bad-uuid"));
/// ```
pub fn is_valid_stix_id(id: &str) -> bool {
    let parts: Vec<&str> = id.split("--").collect();
    if parts.len() != 2 {
        return false;
    }

    // Validate the UUID part
    Uuid::parse_str(parts[1]).is_ok()
}

/// Extracts the object type from a STIX ID
///
/// # Examples
///
/// ```
/// use stix_rs::common::extract_type_from_id;
///
/// assert_eq!(
///     extract_type_from_id("malware--12345678-1234-1234-1234-123456789abc"),
///     Some("malware")
/// );
/// assert_eq!(extract_type_from_id("invalid"), None);
/// ```
pub fn extract_type_from_id(id: &str) -> Option<&str> {
    let parts: Vec<&str> = id.split("--").collect();
    if parts.len() == 2 && Uuid::parse_str(parts[1]).is_ok() {
        Some(parts[0])
    } else {
        None
    }
}

/// Validates that a reference ID matches the expected object type
///
/// # Examples
///
/// ```
/// use stix_rs::common::is_valid_ref_for_type;
///
/// assert!(is_valid_ref_for_type(
///     "malware--12345678-1234-1234-1234-123456789abc",
///     "malware"
/// ));
/// assert!(!is_valid_ref_for_type(
///     "indicator--12345678-1234-1234-1234-123456789abc",
///     "malware"
/// ));
/// ```
pub fn is_valid_ref_for_type(id: &str, expected_type: &str) -> bool {
    extract_type_from_id(id).map(|t| t == expected_type).unwrap_or(false)
}

// Common objects: ExternalReference, MarkingDefinition, ExtensionDefinition, LanguageContent

/// External Reference - Links to external resources (CVEs, ATT&CK, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExternalReference {
    pub source_name: String,
    pub description: Option<String>,
    pub url: Option<String>,
    pub external_id: Option<String>,
    pub hashes: Option<HashMap<String, String>>,
}

impl ExternalReference {
    pub fn new(source_name: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            description: None,
            url: None,
            external_id: None,
            hashes: None,
        }
    }

    pub fn builder() -> ExternalReferenceBuilder {
        ExternalReferenceBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct ExternalReferenceBuilder {
    source_name: Option<String>,
    description: Option<String>,
    url: Option<String>,
    external_id: Option<String>,
    hashes: Option<HashMap<String, String>>,
}

impl ExternalReferenceBuilder {
    pub fn source_name(mut self, name: impl Into<String>) -> Self {
        self.source_name = Some(name.into());
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    pub fn external_id(mut self, id: impl Into<String>) -> Self {
        self.external_id = Some(id.into());
        self
    }

    pub fn hashes(mut self, hashes: HashMap<String, String>) -> Self {
        self.hashes = Some(hashes);
        self
    }

    pub fn build(self) -> Result<ExternalReference, &'static str> {
        let source_name = self.source_name.ok_or("missing source_name")?;
        Ok(ExternalReference {
            source_name,
            description: self.description,
            url: self.url,
            external_id: self.external_id,
            hashes: self.hashes,
        })
    }
}

/// Marking Definition - For data markings like TLP (Traffic Light Protocol)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MarkingDefinition {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub definition_type: String,
    pub definition: serde_json::Value,
    pub name: Option<String>,
}

impl MarkingDefinition {
    pub fn new(definition_type: impl Into<String>, definition: serde_json::Value) -> Self {
        Self {
            common: CommonProperties::new("marking-definition", None),
            definition_type: definition_type.into(),
            definition,
            name: None,
        }
    }

    pub fn builder() -> MarkingDefinitionBuilder {
        MarkingDefinitionBuilder::default()
    }

    /// Create a TLP marking definition
    pub fn tlp(level: impl Into<String>) -> Self {
        let level = level.into();
        let definition = serde_json::json!({
            "tlp": level.to_lowercase()
        });
        Self {
            common: CommonProperties::new("marking-definition", None),
            definition_type: "tlp".to_string(),
            definition,
            name: Some(format!("TLP:{}", level.to_uppercase())),
        }
    }
}

#[derive(Debug, Default)]
pub struct MarkingDefinitionBuilder {
    definition_type: Option<String>,
    definition: Option<serde_json::Value>,
    name: Option<String>,
    created_by_ref: Option<String>,
}

impl MarkingDefinitionBuilder {
    pub fn definition_type(mut self, dt: impl Into<String>) -> Self {
        self.definition_type = Some(dt.into());
        self
    }

    pub fn definition(mut self, def: serde_json::Value) -> Self {
        self.definition = Some(def);
        self
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<MarkingDefinition, &'static str> {
        let definition_type = self.definition_type.ok_or("missing definition_type")?;
        let definition = self.definition.ok_or("missing definition")?;
        Ok(MarkingDefinition {
            common: CommonProperties::new("marking-definition", self.created_by_ref),
            definition_type,
            definition,
            name: self.name,
        })
    }
}

impl StixObject for MarkingDefinition {
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

/// Language Content - For internationalization support
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LanguageContent {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub object_ref: String,
    pub object_modified: DateTime<Utc>,
    pub contents: HashMap<String, HashMap<String, String>>,
}

impl LanguageContent {
    pub fn builder() -> LanguageContentBuilder {
        LanguageContentBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct LanguageContentBuilder {
    object_ref: Option<String>,
    object_modified: Option<DateTime<Utc>>,
    contents: Option<HashMap<String, HashMap<String, String>>>,
    created_by_ref: Option<String>,
}

impl LanguageContentBuilder {
    pub fn object_ref(mut self, r: impl Into<String>) -> Self {
        self.object_ref = Some(r.into());
        self
    }

    pub fn object_modified(mut self, t: DateTime<Utc>) -> Self {
        self.object_modified = Some(t);
        self
    }

    pub fn contents(mut self, c: HashMap<String, HashMap<String, String>>) -> Self {
        self.contents = Some(c);
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<LanguageContent, &'static str> {
        let object_ref = self.object_ref.ok_or("missing object_ref")?;
        let object_modified = self.object_modified.ok_or("missing object_modified")?;
        let contents = self.contents.ok_or("missing contents")?;
        Ok(LanguageContent {
            common: CommonProperties::new("language-content", self.created_by_ref),
            object_ref,
            object_modified,
            contents,
        })
    }
}

impl StixObject for LanguageContent {
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

/// Extension Definition - For custom STIX extensions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExtensionDefinition {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: String,
    pub description: Option<String>,
    pub schema: String,
    pub version: String,
    pub extension_types: Vec<String>,
}

impl ExtensionDefinition {
    pub fn builder() -> ExtensionDefinitionBuilder {
        ExtensionDefinitionBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct ExtensionDefinitionBuilder {
    name: Option<String>,
    description: Option<String>,
    schema: Option<String>,
    version: Option<String>,
    extension_types: Option<Vec<String>>,
    created_by_ref: Option<String>,
}

impl ExtensionDefinitionBuilder {
    pub fn name(mut self, n: impl Into<String>) -> Self {
        self.name = Some(n.into());
        self
    }

    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    pub fn schema(mut self, s: impl Into<String>) -> Self {
        self.schema = Some(s.into());
        self
    }

    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into());
        self
    }

    pub fn extension_types(mut self, t: Vec<String>) -> Self {
        self.extension_types = Some(t);
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<ExtensionDefinition, &'static str> {
        let name = self.name.ok_or("missing name")?;
        let schema = self.schema.ok_or("missing schema")?;
        let version = self.version.ok_or("missing version")?;
        let extension_types = self.extension_types.ok_or("missing extension_types")?;
        Ok(ExtensionDefinition {
            common: CommonProperties::new("extension-definition", self.created_by_ref),
            name,
            description: self.description,
            schema,
            version,
            extension_types,
        })
    }
}

impl StixObject for ExtensionDefinition {
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
