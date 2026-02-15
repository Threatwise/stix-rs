use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MacAddr {
    pub value: String,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl MacAddr {
    pub fn builder() -> MacAddrBuilder { MacAddrBuilder::default() }
}

#[derive(Debug, Default)]
pub struct MacAddrBuilder { value: Option<String>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl MacAddrBuilder {
    pub fn value(mut self, v: impl Into<String>) -> Self { self.value = Some(v.into()); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> MacAddr { MacAddr { value: self.value.unwrap_or_default(), custom_properties: self.custom_properties } }
}

impl From<MacAddr> for crate::StixObjectEnum { fn from(m: MacAddr) -> Self { crate::StixObjectEnum::MacAddr(m) } }
