use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IPv4Addr {
    pub value: String,
    pub resolves_to_refs: Option<Vec<String>>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl IPv4Addr {
    pub fn builder() -> IPv4AddrBuilder { IPv4AddrBuilder::default() }
}

#[derive(Debug, Default)]
pub struct IPv4AddrBuilder { value: Option<String>, resolves_to_refs: Option<Vec<String>>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl IPv4AddrBuilder {
    pub fn value(mut self, v: impl Into<String>) -> Self { self.value = Some(v.into()); self }
    pub fn resolves_to_refs(mut self, r: Vec<String>) -> Self { self.resolves_to_refs = Some(r); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> IPv4Addr { IPv4Addr { value: self.value.unwrap_or_default(), resolves_to_refs: self.resolves_to_refs, custom_properties: self.custom_properties } }
}

impl From<IPv4Addr> for crate::StixObjectEnum { fn from(i: IPv4Addr) -> Self { crate::StixObjectEnum::IPv4Addr(i) } }
