use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Software {
    pub name: Option<String>,
    pub cpe: Option<String>,
    pub lang: Option<String>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl Software {
    pub fn builder() -> SoftwareBuilder {
        SoftwareBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct SoftwareBuilder {
    name: Option<String>,
    cpe: Option<String>,
    lang: Option<String>,
    custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl SoftwareBuilder {
    pub fn name(mut self, n: impl Into<String>) -> Self {
        self.name = Some(n.into());
        self
    }
    pub fn cpe(mut self, c: impl Into<String>) -> Self {
        self.cpe = Some(c.into());
        self
    }
    pub fn lang(mut self, l: impl Into<String>) -> Self {
        self.lang = Some(l.into());
        self
    }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        self.custom_properties.insert(k.into(), v.into());
        self
    }
    pub fn build(self) -> Software {
        Software {
            name: self.name,
            cpe: self.cpe,
            lang: self.lang,
            custom_properties: self.custom_properties,
        }
    }
}

impl From<Software> for crate::StixObjectEnum {
    fn from(s: Software) -> Self {
        crate::StixObjectEnum::Software(s)
    }
}
