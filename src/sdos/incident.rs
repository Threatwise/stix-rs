use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};

/// Incident SDO (STIX 2.1 minimal stub)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Incident {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: String,
    pub description: Option<String>,
}

impl Incident { pub fn builder() -> IncidentBuilder { IncidentBuilder::default() } }

#[derive(Debug, Default)]
pub struct IncidentBuilder { name: Option<String>, description: Option<String>, created_by_ref: Option<String> }

impl IncidentBuilder {
    pub fn name(mut self, n: impl Into<String>) -> Self { self.name = Some(n.into()); self }
    pub fn description(mut self, d: impl Into<String>) -> Self { self.description = Some(d.into()); self }
    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self { self.created_by_ref = Some(r.into()); self }

    pub fn build(self) -> Result<Incident, super::BuilderError> {
        let name = self.name.ok_or(super::BuilderError::MissingField("name"))?;
        let common = CommonProperties::new("incident", self.created_by_ref);
        Ok(Incident{ common, name, description: self.description })
    }
}

impl StixObject for Incident { fn id(&self) -> &str { &self.common.id } fn type_(&self) -> &str { &self.common.r#type } fn created(&self) -> DateTime<Utc> { self.common.created } }

impl From<Incident> for crate::StixObjectEnum { fn from(i: Incident) -> Self { crate::StixObjectEnum::Incident(i) } }

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn incident_builder_and_serialize() {
        let inc = Incident::builder().name("Test Incident").description("desc").build().unwrap();
        let s = serde_json::to_string(&inc).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v.get("type").and_then(Value::as_str).unwrap(), "incident");
        assert_eq!(v.get("name").and_then(Value::as_str).unwrap(), "Test Incident");
    }
}
