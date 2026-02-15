use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// File observable (STIX 2.1)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct File {
    pub hashes: Option<HashMap<String, String>>,
    pub name: Option<String>,
    pub size: Option<u64>,
    pub mime_type: Option<String>,
    pub parent_directory_ref: Option<String>,
    pub content_ref: Option<String>,
    #[serde(flatten)]
    pub custom_properties: HashMap<String, serde_json::Value>,
}

impl File {
    /// Builder convenience
    pub fn builder() -> FileBuilder {
        FileBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct FileBuilder {
    hashes: Option<HashMap<String, String>>,
    name: Option<String>,
    size: Option<u64>,
    mime_type: Option<String>,
    parent_directory_ref: Option<String>,
    content_ref: Option<String>,
    custom_properties: HashMap<String, serde_json::Value>,
}

impl FileBuilder {
    pub fn hashes(mut self, hashes: HashMap<String, String>) -> Self {
        self.hashes = Some(hashes);
        self
    }
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    pub fn size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }
    pub fn mime_type(mut self, mime: impl Into<String>) -> Self {
        self.mime_type = Some(mime.into());
        self
    }
    pub fn parent_directory_ref(mut self, dir: impl Into<String>) -> Self {
        self.parent_directory_ref = Some(dir.into());
        self
    }
    pub fn content_ref(mut self, content: impl Into<String>) -> Self {
        self.content_ref = Some(content.into());
        self
    }
    pub fn property(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.custom_properties.insert(key.into(), value.into());
        self
    }
    pub fn build(self) -> File {
        File {
            hashes: self.hashes,
            name: self.name,
            size: self.size,
            mime_type: self.mime_type,
            parent_directory_ref: self.parent_directory_ref,
            content_ref: self.content_ref,
            custom_properties: self.custom_properties,
        }
    }
}

impl From<File> for crate::StixObjectEnum {
    fn from(f: File) -> Self {
        crate::StixObjectEnum::File(f)
    }
}
