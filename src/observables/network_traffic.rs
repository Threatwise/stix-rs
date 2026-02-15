use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Network traffic observable (STIX 2.1) - core fields
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkTraffic {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub protocols: Option<Vec<String>>,
    pub src_ref: Option<String>,
    pub dst_ref: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl NetworkTraffic {
    pub fn builder() -> NetworkTrafficBuilder { NetworkTrafficBuilder::default() }
}

#[derive(Debug, Default)]
pub struct NetworkTrafficBuilder {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    protocols: Option<Vec<String>>,
    src_ref: Option<String>,
    dst_ref: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl NetworkTrafficBuilder {
    pub fn start(mut self, t: DateTime<Utc>) -> Self { self.start = Some(t); self }
    pub fn end(mut self, t: DateTime<Utc>) -> Self { self.end = Some(t); self }
    pub fn protocols(mut self, p: Vec<String>) -> Self { self.protocols = Some(p); self }
    pub fn src_ref(mut self, r: impl Into<String>) -> Self { self.src_ref = Some(r.into()); self }
    pub fn dst_ref(mut self, r: impl Into<String>) -> Self { self.dst_ref = Some(r.into()); self }
    pub fn src_port(mut self, p: u16) -> Self { self.src_port = Some(p); self }
    pub fn dst_port(mut self, p: u16) -> Self { self.dst_port = Some(p); self }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), v.into()); self }
    pub fn build(self) -> NetworkTraffic {
        NetworkTraffic { start: self.start, end: self.end, protocols: self.protocols, src_ref: self.src_ref, dst_ref: self.dst_ref, src_port: self.src_port, dst_port: self.dst_port, custom_properties: self.custom_properties }
    }
}

impl From<NetworkTraffic> for crate::StixObjectEnum { fn from(n: NetworkTraffic) -> Self { crate::StixObjectEnum::NetworkTraffic(n) } }

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn network_traffic_serde() {
        let nt = NetworkTraffic::builder().src_ref("ipv4-1").dst_ref("ipv4-2").src_port(1234).dst_port(80).start(Utc::now()).build();
        let s = serde_json::to_string(&nt).unwrap();
        let de: NetworkTraffic = serde_json::from_str(&s).unwrap();
        assert_eq!(de.src_port, Some(1234));
    }
}
