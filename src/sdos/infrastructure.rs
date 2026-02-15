use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};
use crate::sdos::BuilderError;

/// Infrastructure SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Infrastructure {
    #[serde(flatten)]
    pub common: CommonProperties,
    pub name: String,
    pub description: Option<String>,
    pub infrastructure_types: Option<Vec<String>>,
}

impl Infrastructure {
    pub fn builder() -> InfrastructureBuilder {
        InfrastructureBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct InfrastructureBuilder {
    name: Option<String>,
    description: Option<String>,
    infrastructure_types: Option<Vec<String>>,
    created_by_ref: Option<String>,
}

impl InfrastructureBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    pub fn infrastructure_types(mut self, t: Vec<String>) -> Self {
        self.infrastructure_types = Some(t);
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<Infrastructure, BuilderError> {
        let name = self.name.ok_or(BuilderError::MissingField("name"))?;
        let common = CommonProperties::new("infrastructure", self.created_by_ref);
        Ok(Infrastructure {
            common,
            name,
            description: self.description,
            infrastructure_types: self.infrastructure_types,
        })
    }
}

impl StixObject for Infrastructure {
    fn id(&self) -> &str {
        &self.common.id
    }

    fn type_(&self) -> &str {
        &self.common.r#type
    }

    fn created(&self) -> DateTime<Utc> {
        self.common.created
    }
}

impl From<Infrastructure> for crate::StixObjectEnum {
    fn from(i: Infrastructure) -> Self {
        crate::StixObjectEnum::Infrastructure(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infrastructure_builder() {
        let infra = Infrastructure::builder()
            .name("C2 Server")
            .description("Command and control infrastructure")
            .infrastructure_types(vec!["command-and-control".into()])
            .build()
            .unwrap();

        assert_eq!(infra.name, "C2 Server");
        assert_eq!(infra.common.r#type, "infrastructure");
    }

    #[test]
    fn infrastructure_serialize() {
        let infra = Infrastructure::builder()
            .name("Malicious Domain")
            .build()
            .unwrap();

        let json = serde_json::to_string(&infra).unwrap();
        assert!(json.contains("\"type\":\"infrastructure\""));
        assert!(json.contains("\"name\":\"Malicious Domain\""));
    }
}
