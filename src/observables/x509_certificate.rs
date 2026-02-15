use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct X509Certificate {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl X509Certificate {
    pub fn builder() -> X509CertificateBuilder {
        X509CertificateBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct X509CertificateBuilder {
    subject: Option<String>,
    issuer: Option<String>,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl X509CertificateBuilder {
    pub fn subject(mut self, s: impl Into<String>) -> Self {
        self.subject = Some(s.into());
        self
    }
    pub fn issuer(mut self, i: impl Into<String>) -> Self {
        self.issuer = Some(i.into());
        self
    }
    pub fn valid_from(mut self, d: DateTime<Utc>) -> Self {
        self.valid_from = Some(d);
        self
    }
    pub fn valid_until(mut self, d: DateTime<Utc>) -> Self {
        self.valid_until = Some(d);
        self
    }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        self.custom_properties.insert(k.into(), v.into());
        self
    }
    pub fn build(self) -> X509Certificate {
        X509Certificate {
            subject: self.subject,
            issuer: self.issuer,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            custom_properties: self.custom_properties,
        }
    }
}

impl From<X509Certificate> for crate::StixObjectEnum {
    fn from(x: X509Certificate) -> Self {
        crate::StixObjectEnum::X509Certificate(x)
    }
}
