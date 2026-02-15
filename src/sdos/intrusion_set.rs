use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};
use crate::sdos::BuilderError;

/// Intrusion Set SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IntrusionSet {
    #[serde(flatten)]
    pub common: CommonProperties,
    pub name: String,
    pub description: Option<String>,
}

impl IntrusionSet {
    pub fn builder() -> IntrusionSetBuilder {
        IntrusionSetBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct IntrusionSetBuilder {
    name: Option<String>,
    description: Option<String>,
    created_by_ref: Option<String>,
}

impl IntrusionSetBuilder {
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

    pub fn build(self) -> Result<IntrusionSet, BuilderError> {
        let name = self.name.ok_or(BuilderError::MissingField("name"))?;
        let common = CommonProperties::new("intrusion-set", self.created_by_ref);
        Ok(IntrusionSet {
            common,
            name,
            description: self.description,
        })
    }
}

impl StixObject for IntrusionSet {
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

impl From<IntrusionSet> for crate::StixObjectEnum {
    fn from(i: IntrusionSet) -> Self {
        crate::StixObjectEnum::IntrusionSet(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intrusion_set_builder() {
        let iset = IntrusionSet::builder()
            .name("Lazarus Group")
            .description("North Korean APT group")
            .build()
            .unwrap();

        assert_eq!(iset.name, "Lazarus Group");
        assert_eq!(iset.common.r#type, "intrusion-set");
    }

    #[test]
    fn intrusion_set_serialize() {
        let iset = IntrusionSet::builder().name("Fancy Bear").build().unwrap();

        let json = serde_json::to_string(&iset).unwrap();
        assert!(json.contains("\"type\":\"intrusion-set\""));
        assert!(json.contains("\"name\":\"Fancy Bear\""));
    }
}
