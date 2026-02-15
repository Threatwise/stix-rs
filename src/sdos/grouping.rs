use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};

/// Grouping SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Grouping {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: Option<String>,
    pub description: Option<String>,
    pub context: String,
    pub object_refs: Vec<String>,
}

impl Grouping {
    pub fn builder() -> GroupingBuilder {
        GroupingBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct GroupingBuilder {
    name: Option<String>,
    description: Option<String>,
    context: Option<String>,
    object_refs: Option<Vec<String>>,
    created_by_ref: Option<String>,
}

impl GroupingBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }
    pub fn context(mut self, c: impl Into<String>) -> Self {
        self.context = Some(c.into());
        self
    }
    pub fn object_refs(mut self, o: Vec<String>) -> Self {
        self.object_refs = Some(o);
        self
    }
    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<Grouping, super::BuilderError> {
        let context = self
            .context
            .ok_or(super::BuilderError::MissingField("context"))?;
        let object_refs = self
            .object_refs
            .ok_or(super::BuilderError::MissingField("object_refs"))?;
        let common = CommonProperties::new("grouping", self.created_by_ref);
        Ok(Grouping {
            common,
            name: self.name,
            description: self.description,
            context,
            object_refs,
        })
    }
}

impl StixObject for Grouping {
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

impl From<Grouping> for crate::StixObjectEnum {
    fn from(g: Grouping) -> Self {
        crate::StixObjectEnum::Grouping(g)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn grouping_builder_and_serialize() {
        let g = Grouping::builder()
            .context("suspicious-activity")
            .object_refs(vec!["file--1234".into()])
            .build()
            .unwrap();

        let s = serde_json::to_string(&g).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v.get("type").and_then(Value::as_str).unwrap(), "grouping");
        assert!(v.get("object-refs").is_some());
    }
}
