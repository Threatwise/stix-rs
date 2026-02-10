use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};
use crate::sdos::BuilderError;

/// Tool SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Tool {
    #[serde(flatten)]
    pub common: CommonProperties,
    pub name: String,
    pub description: Option<String>,
    pub tool_types: Option<Vec<String>>,
}

impl Tool {
    pub fn builder() -> ToolBuilder {
        ToolBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct ToolBuilder {
    name: Option<String>,
    description: Option<String>,
    tool_types: Option<Vec<String>>,
    created_by_ref: Option<String>,
}

impl ToolBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    pub fn tool_types(mut self, t: Vec<String>) -> Self {
        self.tool_types = Some(t);
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<Tool, BuilderError> {
        let name = self.name.ok_or(BuilderError::MissingField("name"))?;
        let common = CommonProperties::new("tool", self.created_by_ref);
        Ok(Tool {
            common,
            name,
            description: self.description,
            tool_types: self.tool_types,
        })
    }
}

impl StixObject for Tool {
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

impl From<Tool> for crate::StixObjectEnum {
    fn from(t: Tool) -> Self {
        crate::StixObjectEnum::Tool(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_builder() {
        let tool = Tool::builder()
            .name("Metasploit")
            .description("Penetration testing framework")
            .tool_types(vec!["exploitation".into()])
            .build()
            .unwrap();

        assert_eq!(tool.name, "Metasploit");
        assert_eq!(tool.common.r#type, "tool");
    }

    #[test]
    fn tool_serialize() {
        let tool = Tool::builder()
            .name("Cobalt Strike")
            .build()
            .unwrap();

        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("\"type\":\"tool\""));
        assert!(json.contains("\"name\":\"Cobalt Strike\""));
    }
}
