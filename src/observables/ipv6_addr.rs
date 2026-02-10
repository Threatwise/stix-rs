use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct IPv6Addr {
    pub value: String,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl IPv6Addr {
    pub fn builder() -> IPv6AddrBuilder { IPv6AddrBuilder::default() }
}

#[derive(Debug, Default)]
pub struct IPv6AddrBuilder { value: Option<String>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl IPv6AddrBuilder {
    pub fn value(mut self, v: impl Into<String>) -> Self { self.value = Some(v.into()); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> IPv6Addr { IPv6Addr { value: self.value.unwrap_or_default(), custom_properties: self.custom_properties } }
}

impl From<IPv6Addr> for crate::StixObjectEnum { fn from(i: IPv6Addr) -> Self { crate::StixObjectEnum::IPv6Addr(i) } }
