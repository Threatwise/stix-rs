use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutonomousSystem {
    pub number: Option<u32>,
    pub name: Option<String>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl AutonomousSystem { pub fn builder() -> AutonomousSystemBuilder { AutonomousSystemBuilder::default() } }

#[derive(Debug, Default)]
pub struct AutonomousSystemBuilder { number: Option<u32>, name: Option<String>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl AutonomousSystemBuilder {
    pub fn number(mut self, n: u32) -> Self { self.number = Some(n); self }
    pub fn name(mut self, s: impl Into<String>) -> Self { self.name = Some(s.into()); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> AutonomousSystem { AutonomousSystem { number: self.number, name: self.name, custom_properties: self.custom_properties } }
}

impl From<AutonomousSystem> for crate::StixObjectEnum { fn from(a: AutonomousSystem) -> Self { crate::StixObjectEnum::AutonomousSystem(a) } }
