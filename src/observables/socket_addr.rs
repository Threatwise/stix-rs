use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SocketAddr {
    pub value: Option<String>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl SocketAddr {
    pub fn builder() -> SocketAddrBuilder { SocketAddrBuilder::default() }
}

#[derive(Debug, Default)]
pub struct SocketAddrBuilder { value: Option<String>, custom_properties: std::collections::HashMap<String, serde_json::Value> }

impl SocketAddrBuilder {
    pub fn value(mut self, v: impl Into<String>) -> Self { self.value = Some(v.into()); self }
    pub fn property(mut self, k: impl Into<String>, val: impl Into<serde_json::Value>) -> Self { self.custom_properties.insert(k.into(), val.into()); self }
    pub fn build(self) -> SocketAddr { SocketAddr { value: self.value, custom_properties: self.custom_properties } }
}

impl From<SocketAddr> for crate::StixObjectEnum { fn from(s: SocketAddr) -> Self { crate::StixObjectEnum::SocketAddr(s) } }

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn socket_addr_serde() {
        let v = json!({"type": "socket-addr", "value": "192.0.2.1:443"});
        let obj: crate::StixObjectEnum = serde_json::from_value(v).expect("deserialize into StixObjectEnum");
        match obj {
            crate::StixObjectEnum::SocketAddr(sa) => assert_eq!(sa.value.unwrap(), "192.0.2.1:443"),
            _ => panic!("expected SocketAddr variant"),
        }
    }
}
