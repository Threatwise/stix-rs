use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};

/// Opinion SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Opinion {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub explanation: Option<String>,
    pub authors: Option<Vec<String>>,
    pub object_refs: Vec<String>,
    pub opinion: String,
}

impl Opinion {
    pub fn builder() -> OpinionBuilder {
        OpinionBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct OpinionBuilder {
    explanation: Option<String>,
    authors: Option<Vec<String>>,
    object_refs: Option<Vec<String>>,
    opinion: Option<String>,
    created_by_ref: Option<String>,
}

impl OpinionBuilder {
    pub fn explanation(mut self, e: impl Into<String>) -> Self {
        self.explanation = Some(e.into());
        self
    }
    pub fn authors(mut self, a: Vec<String>) -> Self {
        self.authors = Some(a);
        self
    }
    pub fn object_refs(mut self, o: Vec<String>) -> Self {
        self.object_refs = Some(o);
        self
    }
    pub fn opinion(mut self, o: impl Into<String>) -> Self {
        self.opinion = Some(o.into());
        self
    }
    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<Opinion, super::BuilderError> {
        let object_refs = self
            .object_refs
            .ok_or(super::BuilderError::MissingField("object_refs"))?;
        let opinion = self
            .opinion
            .ok_or(super::BuilderError::MissingField("opinion"))?;
        let common = CommonProperties::new("opinion", self.created_by_ref);
        Ok(Opinion {
            common,
            explanation: self.explanation,
            authors: self.authors,
            object_refs,
            opinion,
        })
    }
}

impl StixObject for Opinion {
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

impl From<Opinion> for crate::StixObjectEnum {
    fn from(o: Opinion) -> Self {
        crate::StixObjectEnum::Opinion(o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn opinion_builder_and_serialize() {
        let op = Opinion::builder()
            .opinion("agree")
            .object_refs(vec!["report--1234".into()])
            .build()
            .unwrap();

        let s = serde_json::to_string(&op).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v.get("type").and_then(Value::as_str).unwrap(), "opinion");
        assert!(v.get("object-refs").is_some());
    }
}
