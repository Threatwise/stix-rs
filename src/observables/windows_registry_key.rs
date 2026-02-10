use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WindowsRegistryKey {
    pub key: Option<String>,
    pub values: Option<std::collections::HashMap<String, String>>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl WindowsRegistryKey { pub fn builder() -> WindowsRegistryKeyBuilder { WindowsRegistryKeyBuilder::default() } }

#[derive(Debug, Default)]
pub struct WindowsRegistryKeyBuilder { key: Option<String>, values: Option<std::collections::HashMap<String, String>>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl WindowsRegistryKeyBuilder {
    pub fn key(mut self, k: impl Into<String>) -> Self { self.key = Some(k.into()); self }
    pub fn values(mut self, v: std::collections::HashMap<String, String>) -> Self { self.values = Some(v); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> WindowsRegistryKey { WindowsRegistryKey { key: self.key, values: self.values, custom_properties: self.custom_properties } }
}

impl From<WindowsRegistryKey> for crate::StixObjectEnum { fn from(w: WindowsRegistryKey) -> Self { crate::StixObjectEnum::WindowsRegistryKey(w) } }
