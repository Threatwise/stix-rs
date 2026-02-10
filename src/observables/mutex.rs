use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Mutex {
    pub name: Option<String>,
    pub currently_owned: Option<bool>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl Mutex { pub fn builder() -> MutexBuilder { MutexBuilder::default() } }

#[derive(Debug, Default)]
pub struct MutexBuilder { name: Option<String>, currently_owned: Option<bool>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl MutexBuilder {
    pub fn name(mut self, n: impl Into<String>) -> Self { self.name = Some(n.into()); self }
    pub fn currently_owned(mut self, v: bool) -> Self { self.currently_owned = Some(v); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> Mutex { Mutex { name: self.name, currently_owned: self.currently_owned, custom_properties: self.custom_properties } }
}

impl From<Mutex> for crate::StixObjectEnum { fn from(m: Mutex) -> Self { crate::StixObjectEnum::Mutex(m) } }
