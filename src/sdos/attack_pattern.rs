use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};

/// Attack Pattern SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AttackPattern {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: String,
    pub description: Option<String>,
}

impl AttackPattern {
    pub fn builder() -> AttackPatternBuilder {
        AttackPatternBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct AttackPatternBuilder {
    name: Option<String>,
    description: Option<String>,
    created_by_ref: Option<String>,
}

impl AttackPatternBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }
    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<AttackPattern, super::BuilderError> {
        let name = self.name.ok_or(super::BuilderError::MissingField("name"))?;
        let common = CommonProperties::new("attack-pattern", self.created_by_ref);
        Ok(AttackPattern {
            common,
            name,
            description: self.description,
        })
    }
}

impl StixObject for AttackPattern {
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

impl From<AttackPattern> for crate::StixObjectEnum {
    fn from(a: AttackPattern) -> Self {
        crate::StixObjectEnum::AttackPattern(a)
    }
}
