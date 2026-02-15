use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UserAccount {
    pub user_id: Option<String>,
    pub account_login: Option<String>,
    pub display_name: Option<String>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl UserAccount {
    pub fn builder() -> UserAccountBuilder {
        UserAccountBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct UserAccountBuilder {
    user_id: Option<String>,
    account_login: Option<String>,
    display_name: Option<String>,
    custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl UserAccountBuilder {
    pub fn user_id(mut self, u: impl Into<String>) -> Self {
        self.user_id = Some(u.into());
        self
    }
    pub fn account_login(mut self, a: impl Into<String>) -> Self {
        self.account_login = Some(a.into());
        self
    }
    pub fn display_name(mut self, d: impl Into<String>) -> Self {
        self.display_name = Some(d.into());
        self
    }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        self.custom_properties.insert(k.into(), v.into());
        self
    }
    pub fn build(self) -> UserAccount {
        UserAccount {
            user_id: self.user_id,
            account_login: self.account_login,
            display_name: self.display_name,
            custom_properties: self.custom_properties,
        }
    }
}

impl From<UserAccount> for crate::StixObjectEnum {
    fn from(u: UserAccount) -> Self {
        crate::StixObjectEnum::UserAccount(u)
    }
}
