use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Directory {
    pub path: Option<String>,
    pub path_enc: Option<String>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl Directory { pub fn builder() -> DirectoryBuilder { DirectoryBuilder::default() } }

#[derive(Debug, Default)]
pub struct DirectoryBuilder { path: Option<String>, path_enc: Option<String>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl DirectoryBuilder {
    pub fn path(mut self, p: impl Into<String>) -> Self { self.path = Some(p.into()); self }
    pub fn path_enc(mut self, p: impl Into<String>) -> Self { self.path_enc = Some(p.into()); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> Directory { Directory { path: self.path, path_enc: self.path_enc, custom_properties: self.custom_properties } }
}

impl From<Directory> for crate::StixObjectEnum { fn from(d: Directory) -> Self { crate::StixObjectEnum::Directory(d) } }
