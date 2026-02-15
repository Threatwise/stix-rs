use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SoftwarePackage {
    pub name: Option<String>,
    pub version: Option<String>,
    pub cpe: Option<String>,
    pub created: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl SoftwarePackage {
    pub fn builder() -> SoftwarePackageBuilder {
        SoftwarePackageBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct SoftwarePackageBuilder {
    name: Option<String>,
    version: Option<String>,
    cpe: Option<String>,
    created: Option<DateTime<Utc>>,
    custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl SoftwarePackageBuilder {
    pub fn name(mut self, n: impl Into<String>) -> Self {
        self.name = Some(n.into());
        self
    }
    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into());
        self
    }
    pub fn cpe(mut self, c: impl Into<String>) -> Self {
        self.cpe = Some(c.into());
        self
    }
    pub fn created(mut self, d: DateTime<Utc>) -> Self {
        self.created = Some(d);
        self
    }
    pub fn property(mut self, k: impl Into<String>, val: impl Into<serde_json::Value>) -> Self {
        self.custom_properties.insert(k.into(), val.into());
        self
    }
    pub fn build(self) -> SoftwarePackage {
        SoftwarePackage {
            name: self.name,
            version: self.version,
            cpe: self.cpe,
            created: self.created,
            custom_properties: self.custom_properties,
        }
    }
}

impl From<SoftwarePackage> for crate::StixObjectEnum {
    fn from(s: SoftwarePackage) -> Self {
        crate::StixObjectEnum::SoftwarePackage(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn software_package_serde() {
        let v = json!({"type": "software-package", "name": "pkg", "version": "1.2.3"});
        let obj: crate::StixObjectEnum =
            serde_json::from_value(v).expect("deserialize into StixObjectEnum");
        match obj {
            crate::StixObjectEnum::SoftwarePackage(sp) => {
                assert_eq!(sp.name.unwrap(), "pkg");
                assert_eq!(sp.version.unwrap(), "1.2.3");
            }
            _ => panic!("expected SoftwarePackage variant"),
        }
    }
}
