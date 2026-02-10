use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Artifact {
    pub value: Option<String>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl Artifact {
    pub fn builder() -> ArtifactBuilder { ArtifactBuilder::default() }
}

#[derive(Debug, Default)]
pub struct ArtifactBuilder { value: Option<String>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl ArtifactBuilder {
    pub fn value(mut self, v: impl Into<String>) -> Self { self.value = Some(v.into()); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> Artifact { Artifact { value: self.value, custom_properties: self.custom_properties } }
}

impl From<Artifact> for crate::StixObjectEnum { fn from(a: Artifact) -> Self { crate::StixObjectEnum::Artifact(a) } }
