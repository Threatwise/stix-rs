use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};

/// Campaign SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Campaign {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: String,
    pub description: Option<String>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

impl Campaign {
    pub fn builder() -> CampaignBuilder {
        CampaignBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct CampaignBuilder {
    name: Option<String>,
    description: Option<String>,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    created_by_ref: Option<String>,
}

impl CampaignBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }
    pub fn first_seen(mut self, t: DateTime<Utc>) -> Self {
        self.first_seen = Some(t);
        self
    }
    pub fn last_seen(mut self, t: DateTime<Utc>) -> Self {
        self.last_seen = Some(t);
        self
    }
    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }
    pub fn build(self) -> Result<Campaign, super::BuilderError> {
        let name = self.name.ok_or(super::BuilderError::MissingField("name"))?;
        let common = CommonProperties::new("campaign", self.created_by_ref);
        Ok(Campaign {
            common,
            name,
            description: self.description,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
        })
    }
}

impl StixObject for Campaign {
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
impl From<Campaign> for crate::StixObjectEnum {
    fn from(c: Campaign) -> Self {
        crate::StixObjectEnum::Campaign(c)
    }
}
