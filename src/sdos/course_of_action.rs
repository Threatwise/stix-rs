use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};

/// Course of Action SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CourseOfAction { #[serde(flatten)] pub common: CommonProperties, pub name: String, pub description: Option<String> }
impl CourseOfAction { pub fn builder() -> CourseOfActionBuilder { CourseOfActionBuilder::default() } }
#[derive(Debug, Default)]
pub struct CourseOfActionBuilder { name: Option<String>, description: Option<String>, created_by_ref: Option<String> }
impl CourseOfActionBuilder { pub fn name(mut self, name: impl Into<String>) -> Self { self.name = Some(name.into()); self } pub fn description(mut self, d: impl Into<String>) -> Self { self.description = Some(d.into()); self } pub fn created_by_ref(mut self, r: impl Into<String>) -> Self { self.created_by_ref = Some(r.into()); self } pub fn build(self) -> Result<CourseOfAction, super::BuilderError> { let name = self.name.ok_or(super::BuilderError::MissingField("name"))?; let common = CommonProperties::new("course-of-action", self.created_by_ref); Ok(CourseOfAction{common, name, description: self.description}) } }
impl StixObject for CourseOfAction { fn id(&self) -> &str { &self.common.id } fn type_(&self) -> &str { &self.common.r#type } fn created(&self) -> DateTime<Utc> { self.common.created } }
impl From<CourseOfAction> for crate::StixObjectEnum { fn from(c: CourseOfAction) -> Self { crate::StixObjectEnum::CourseOfAction(c) } }
