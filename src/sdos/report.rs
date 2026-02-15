use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};
use crate::sdos::BuilderError;

/// Report SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Report {
    #[serde(flatten)]
    pub common: CommonProperties,
    pub name: String,
    pub published: Option<DateTime<Utc>>,
    pub report_types: Option<Vec<String>>,
    pub object_refs: Option<Vec<String>>,
}

impl Report {
    pub fn builder() -> ReportBuilder {
        ReportBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct ReportBuilder {
    name: Option<String>,
    published: Option<DateTime<Utc>>,
    report_types: Option<Vec<String>>,
    object_refs: Option<Vec<String>>,
    created_by_ref: Option<String>,
}

impl ReportBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn published(mut self, t: DateTime<Utc>) -> Self {
        self.published = Some(t);
        self
    }

    pub fn report_types(mut self, r: Vec<String>) -> Self {
        self.report_types = Some(r);
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

    pub fn build(self) -> Result<Report, BuilderError> {
        let name = self.name.ok_or(BuilderError::MissingField("name"))?;
        let common = CommonProperties::new("report", self.created_by_ref);
        Ok(Report {
            common,
            name,
            published: self.published,
            report_types: self.report_types,
            object_refs: self.object_refs,
        })
    }
}

impl StixObject for Report {
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

impl From<Report> for crate::StixObjectEnum {
    fn from(r: Report) -> Self {
        crate::StixObjectEnum::Report(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn report_builder() {
        let report = Report::builder()
            .name("Threat Intelligence Report Q1 2024")
            .published(Utc::now())
            .report_types(vec!["threat-actor".into()])
            .object_refs(vec!["malware--1234".into()])
            .build()
            .unwrap();

        assert_eq!(report.name, "Threat Intelligence Report Q1 2024");
        assert_eq!(report.common.r#type, "report");
    }

    #[test]
    fn report_serialize() {
        let report = Report::builder().name("APT Analysis").build().unwrap();

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"type\":\"report\""));
        assert!(json.contains("\"name\":\"APT Analysis\""));
    }
}
