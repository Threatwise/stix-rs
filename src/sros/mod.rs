use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::CommonProperties;
use crate::common::StixObject;

/// Sighting Domain Object
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Sighting {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub count: u32,

    pub sighting_of_ref: String,

    pub where_sighted_refs: Vec<String>,
}

impl Sighting {
    pub fn builder() -> crate::SightingBuilder {
        crate::SightingBuilder::default()
    }
}

impl StixObject for Sighting {
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

/// Relationship
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Relationship {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub source_ref: String,
    pub target_ref: String,
    pub relationship_type: String,
}

impl Relationship {
    pub fn new(
        source_ref: impl Into<String>,
        target_ref: impl Into<String>,
        relationship_type: impl Into<String>,
    ) -> Self {
        Self {
            common: CommonProperties::new("relationship", None),
            source_ref: source_ref.into(),
            target_ref: target_ref.into(),
            relationship_type: relationship_type.into(),
        }
    }
}

impl StixObject for Relationship {
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

impl From<Relationship> for crate::StixObjectEnum {
    fn from(r: Relationship) -> Self {
        crate::StixObjectEnum::Relationship(r)
    }
}
