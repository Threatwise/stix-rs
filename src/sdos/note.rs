use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};
use crate::sdos::BuilderError;

/// Note SDO
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Note {
    #[serde(flatten)]
    pub common: CommonProperties,
    #[serde(rename = "abstract")]
    pub abstract_: Option<String>,
    pub content: Option<String>,
}

impl Note {
    pub fn builder() -> NoteBuilder {
        NoteBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct NoteBuilder {
    abstract_: Option<String>,
    content: Option<String>,
    created_by_ref: Option<String>,
}

impl NoteBuilder {
    pub fn abstract_(mut self, a: impl Into<String>) -> Self {
        self.abstract_ = Some(a.into());
        self
    }

    pub fn content(mut self, c: impl Into<String>) -> Self {
        self.content = Some(c.into());
        self
    }

    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self {
        self.created_by_ref = Some(r.into());
        self
    }

    pub fn build(self) -> Result<Note, BuilderError> {
        let common = CommonProperties::new("note", self.created_by_ref);
        Ok(Note {
            common,
            abstract_: self.abstract_,
            content: self.content,
        })
    }
}

impl StixObject for Note {
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

impl From<Note> for crate::StixObjectEnum {
    fn from(n: Note) -> Self {
        crate::StixObjectEnum::Note(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_builder() {
        let note = Note::builder()
            .abstract_("Summary of findings")
            .content("Detailed analysis of the threat actor's TTPs")
            .build()
            .unwrap();

        assert_eq!(note.abstract_.as_deref(), Some("Summary of findings"));
        assert_eq!(note.common.r#type, "note");
    }

    #[test]
    fn note_serialize() {
        let note = Note::builder()
            .content("Important observation")
            .build()
            .unwrap();

        let json = serde_json::to_string(&note).unwrap();
        assert!(json.contains("\"type\":\"note\""));
        assert!(json.contains("\"content\":\"Important observation\""));
    }
}
