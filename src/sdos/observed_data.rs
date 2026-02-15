use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};
use crate::sdos::BuilderError;

/// Observed Data SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ObservedData {
    #[serde(flatten)]
    pub common: CommonProperties,
    pub first_observed: DateTime<Utc>,
    pub last_observed: DateTime<Utc>,
    pub number_observed: u32,
    pub object_refs: Vec<String>,
}

impl ObservedData {
    pub fn builder() -> ObservedDataBuilder {
        ObservedDataBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct ObservedDataBuilder {
    first_observed: Option<DateTime<Utc>>,
    last_observed: Option<DateTime<Utc>>,
    number_observed: Option<u32>,
    object_refs: Option<Vec<String>>,
    created_by_ref: Option<String>,
}

impl ObservedDataBuilder {
    pub fn first_observed(mut self, t: DateTime<Utc>) -> Self {
        self.first_observed = Some(t);
        self
    }

    pub fn last_observed(mut self, t: DateTime<Utc>) -> Self {
        self.last_observed = Some(t);
        self
    }

    pub fn number_observed(mut self, n: u32) -> Self {
        self.number_observed = Some(n);
        self
    }

    pub fn object_refs(mut self, refs: Vec<String>) -> Self {
        self.object_refs = Some(refs);
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<ObservedData, BuilderError> {
        let first = self
            .first_observed
            .ok_or(BuilderError::MissingField("first_observed"))?;
        let last = self
            .last_observed
            .ok_or(BuilderError::MissingField("last_observed"))?;
        let num = self
            .number_observed
            .ok_or(BuilderError::MissingField("number_observed"))?;
        let objs = self
            .object_refs
            .ok_or(BuilderError::MissingField("object_refs"))?;
        let common = CommonProperties::new("observed-data", self.created_by_ref);
        Ok(ObservedData {
            common,
            first_observed: first,
            last_observed: last,
            number_observed: num,
            object_refs: objs,
        })
    }
}

impl StixObject for ObservedData {
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

impl From<ObservedData> for crate::StixObjectEnum {
    fn from(o: ObservedData) -> Self {
        crate::StixObjectEnum::ObservedData(o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::Value;

    #[test]
    fn observed_data_builder() {
        let od = ObservedData::builder()
            .first_observed(Utc::now())
            .last_observed(Utc::now())
            .number_observed(1)
            .object_refs(vec!["file--1234".into()])
            .build()
            .unwrap();

        assert_eq!(od.number_observed, 1);
        assert_eq!(od.common.r#type, "observed-data");
    }

    #[test]
    fn observed_data_serialize() {
        let od = ObservedData::builder()
            .first_observed(Utc::now())
            .last_observed(Utc::now())
            .number_observed(1)
            .object_refs(vec!["file--1234".into()])
            .build()
            .unwrap();

        let s = serde_json::to_string(&od).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(
            v.get("type").and_then(Value::as_str).unwrap(),
            "observed-data"
        );
        assert!(v.get("object_refs").is_some());
    }
}
