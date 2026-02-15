use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};
use crate::sdos::BuilderError;

/// Threat Actor SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ThreatActor {
    #[serde(flatten)]
    pub common: CommonProperties,
    pub name: String,
    pub description: Option<String>,
    pub threat_actor_types: Option<Vec<String>>,
}

impl ThreatActor {
    pub fn builder() -> ThreatActorBuilder {
        ThreatActorBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct ThreatActorBuilder {
    name: Option<String>,
    description: Option<String>,
    threat_actor_types: Option<Vec<String>>,
    created_by_ref: Option<String>,
}

impl ThreatActorBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    pub fn threat_actor_types(mut self, t: Vec<String>) -> Self {
        self.threat_actor_types = Some(t);
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<ThreatActor, BuilderError> {
        let name = self.name.ok_or(BuilderError::MissingField("name"))?;
        let common = CommonProperties::new("threat-actor", self.created_by_ref);
        Ok(ThreatActor {
            common,
            name,
            description: self.description,
            threat_actor_types: self.threat_actor_types,
        })
    }
}

impl StixObject for ThreatActor {
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

impl From<ThreatActor> for crate::StixObjectEnum {
    fn from(t: ThreatActor) -> Self {
        crate::StixObjectEnum::ThreatActor(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_actor_builder() {
        let ta = ThreatActor::builder()
            .name("APT28")
            .description("Advanced persistent threat group")
            .threat_actor_types(vec!["nation-state".into()])
            .build()
            .unwrap();

        assert_eq!(ta.name, "APT28");
        assert_eq!(ta.common.r#type, "threat-actor");
    }

    #[test]
    fn threat_actor_serialize() {
        let ta = ThreatActor::builder().name("APT28").build().unwrap();

        let json = serde_json::to_string(&ta).unwrap();
        assert!(json.contains("\"type\":\"threat-actor\""));
        assert!(json.contains("\"name\":\"APT28\""));
    }
}
