use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};

/// Generic Relationship Object
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, )]
#[serde(rename_all = "snake_case")]
pub struct Relationship {
    #[serde(flatten)]
    pub common: CommonProperties,

        #[serde(default)]
    pub source_ref: String,

        #[serde(default)]
    pub target_ref: String,

        #[serde(default)]
    pub relationship_type: String,
}

impl Relationship {
    pub fn new(source_ref: impl Into<String>, target_ref: impl Into<String>, relationship_type: impl Into<String>) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn relationship_new_and_serialize() {
        let r = Relationship::new("indicator--a", "malware--b", "related-to");
        let j = serde_json::to_string(&r).unwrap();
        let v: Value = serde_json::from_str(&j).unwrap();
        assert!(v.get("type").is_some());
        assert!(v.get("source-ref").is_some());
        assert!(v.get("target-ref").is_some());
        assert!(v.get("relationship-type").is_some());
    }
}
