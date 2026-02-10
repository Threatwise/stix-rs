use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Url {
    pub value: String,
    pub url_scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub path: Option<String>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl Url {
    pub fn builder() -> UrlBuilder { UrlBuilder::default() }
}

#[derive(Debug, Default)]
pub struct UrlBuilder { value: Option<String>, url_scheme: Option<String>, host: Option<String>, port: Option<u16>, path: Option<String>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl UrlBuilder {
    pub fn value(mut self, v: impl Into<String>) -> Self { self.value = Some(v.into()); self }
    pub fn scheme(mut self, s: impl Into<String>) -> Self { self.url_scheme = Some(s.into()); self }
    pub fn host(mut self, h: impl Into<String>) -> Self { self.host = Some(h.into()); self }
    pub fn port(mut self, p: u16) -> Self { self.port = Some(p); self }
    pub fn path(mut self, p: impl Into<String>) -> Self { self.path = Some(p.into()); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> Url { Url { value: self.value.unwrap_or_default(), url_scheme: self.url_scheme, host: self.host, port: self.port, path: self.path, custom_properties: self.custom_properties } }
}

impl From<Url> for crate::StixObjectEnum { fn from(u: Url) -> Self { crate::StixObjectEnum::Url(u) } }
