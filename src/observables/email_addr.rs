use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct EmailAddr {
    pub value: String,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl EmailAddr { pub fn builder() -> EmailAddrBuilder { EmailAddrBuilder::default() } }

#[derive(Debug, Default)]
pub struct EmailAddrBuilder { value: Option<String>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl EmailAddrBuilder {
    pub fn value(mut self, v: impl Into<String>) -> Self { self.value = Some(v.into()); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> EmailAddr { EmailAddr { value: self.value.unwrap_or_default(), custom_properties: self.custom_properties } }
}

impl From<EmailAddr> for crate::StixObjectEnum { fn from(e: EmailAddr) -> Self { crate::StixObjectEnum::EmailAddr(e) } }
