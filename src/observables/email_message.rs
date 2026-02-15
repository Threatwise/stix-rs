use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EmailMessage {
    pub subject: Option<String>,
    pub body: Option<String>,
    pub from: Option<String>,
    pub to: Option<Vec<String>>,
    pub date: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl EmailMessage {
    pub fn builder() -> EmailMessageBuilder {
        EmailMessageBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct EmailMessageBuilder {
    subject: Option<String>,
    body: Option<String>,
    from: Option<String>,
    to: Option<Vec<String>>,
    date: Option<DateTime<Utc>>,
    custom_properties: std::collections::HashMap<String, serde_json::Value>,
}

impl EmailMessageBuilder {
    pub fn subject(mut self, s: impl Into<String>) -> Self {
        self.subject = Some(s.into());
        self
    }
    pub fn body(mut self, b: impl Into<String>) -> Self {
        self.body = Some(b.into());
        self
    }
    pub fn from(mut self, f: impl Into<String>) -> Self {
        self.from = Some(f.into());
        self
    }
    pub fn to(mut self, t: Vec<String>) -> Self {
        self.to = Some(t);
        self
    }
    pub fn date(mut self, d: DateTime<Utc>) -> Self {
        self.date = Some(d);
        self
    }
    pub fn property(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        self.custom_properties.insert(k.into(), v.into());
        self
    }
    pub fn build(self) -> EmailMessage {
        EmailMessage {
            subject: self.subject,
            body: self.body,
            from: self.from,
            to: self.to,
            date: self.date,
            custom_properties: self.custom_properties,
        }
    }
}

impl From<EmailMessage> for crate::StixObjectEnum {
    fn from(e: EmailMessage) -> Self {
        crate::StixObjectEnum::EmailMessage(e)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn email_message_serde_roundtrip() {
        let v = json!({
            "type": "email-message",
            "subject": "Test",
            "from": "alice@example.com",
            "to": ["bob@example.com"],
            "body": "hello"
        });

        let obj: crate::StixObjectEnum =
            serde_json::from_value(v).expect("deserialize into StixObjectEnum");
        match obj {
            crate::StixObjectEnum::EmailMessage(em) => {
                assert_eq!(em.subject.unwrap(), "Test");
                assert_eq!(em.from.unwrap(), "alice@example.com");
            }
            _ => panic!("expected EmailMessage variant"),
        }
    }
}
