use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Process {
    pub name: Option<String>,
    pub pid: Option<u32>,
    pub command_line: Option<String>,
    pub created: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl Process {
    pub fn builder() -> ProcessBuilder { ProcessBuilder::default() }
}

#[derive(Debug, Default)]
pub struct ProcessBuilder { name: Option<String>, pid: Option<u32>, command_line: Option<String>, created: Option<DateTime<Utc>>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl ProcessBuilder {
    pub fn name(mut self, n: impl Into<String>) -> Self { self.name = Some(n.into()); self }
    pub fn pid(mut self, p: u32) -> Self { self.pid = Some(p); self }
    pub fn command_line(mut self, c: impl Into<String>) -> Self { self.command_line = Some(c.into()); self }
    pub fn created(mut self, t: DateTime<Utc>) -> Self { self.created = Some(t); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> Process { Process { name: self.name, pid: self.pid, command_line: self.command_line, created: self.created, custom_properties: self.custom_properties } }
}

impl From<Process> for crate::StixObjectEnum { fn from(p: Process) -> Self { crate::StixObjectEnum::Process(p) } }
