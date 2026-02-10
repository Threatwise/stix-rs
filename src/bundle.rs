//! Bundles of STIX objects

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::StixObjectEnum;

/// A minimal STIX Bundle type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Bundle {
    pub r#type: String,
    pub id: String,
    pub objects: Vec<StixObjectEnum>,
}

impl Bundle {
    /// Create a new bundle; sets `type` to "bundle" and auto-generates an id
    pub fn new(objects: Vec<StixObjectEnum>) -> Self {
        Self {
            r#type: "bundle".to_string(),
            id: format!("bundle--{}", Uuid::new_v4()),
            objects,
        }
    }

    /// Find a specific object by its ID
    ///
    /// # Examples
    ///
    /// ```
    /// use stix_rs::{Bundle, Identity, IdentityClass, StixObject};
    ///
    /// let identity = Identity::builder()
    ///     .name("ACME")
    ///     .class(IdentityClass::Organization)
    ///     .build()
    ///     .unwrap();
    ///
    /// let id = identity.id().to_string();
    /// let bundle = Bundle::new(vec![identity.into()]);
    ///
    /// assert!(bundle.get(&id).is_some());
    /// assert!(bundle.get("nonexistent--id").is_none());
    /// ```
    pub fn get(&self, id: &str) -> Option<&StixObjectEnum> {
        self.objects.iter().find(|obj| obj.id() == id)
    }

    /// Returns an iterator over all objects in the bundle
    pub fn iter(&self) -> impl Iterator<Item = &StixObjectEnum> {
        self.objects.iter()
    }

    /// Returns a mutable iterator over all objects in the bundle
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut StixObjectEnum> {
        self.objects.iter_mut()
    }

    /// Filter objects by type string (e.g., "malware", "indicator")
    ///
    /// # Examples
    ///
    /// ```
    /// use stix_rs::{Bundle, Identity, Malware, IdentityClass};
    ///
    /// let identity = Identity::builder()
    ///     .name("ACME")
    ///     .class(IdentityClass::Organization)
    ///     .build()
    ///     .unwrap();
    ///
    /// let malware = Malware::builder()
    ///     .name("BadWare")
    ///     .malware_types(vec!["trojan".into()])
    ///     .build()
    ///     .unwrap();
    ///
    /// let bundle = Bundle::new(vec![identity.into(), malware.into()]);
    ///
    /// let malware_objects = bundle.filter_by_type("malware");
    /// assert_eq!(malware_objects.len(), 1);
    /// ```
    pub fn filter_by_type(&self, type_name: &str) -> Vec<&StixObjectEnum> {
        self.objects
            .iter()
            .filter(|obj| obj.type_() == type_name)
            .collect()
    }

    /// Get all Identity objects
    pub fn identities(&self) -> Vec<&crate::Identity> {
        self.objects
            .iter()
            .filter_map(|obj| match obj {
                StixObjectEnum::Identity(i) => Some(i),
                _ => None,
            })
            .collect()
    }

    /// Get all Malware objects
    pub fn malware(&self) -> Vec<&crate::Malware> {
        self.objects
            .iter()
            .filter_map(|obj| match obj {
                StixObjectEnum::Malware(m) => Some(m),
                _ => None,
            })
            .collect()
    }

    /// Get all Indicator objects
    pub fn indicators(&self) -> Vec<&crate::Indicator> {
        self.objects
            .iter()
            .filter_map(|obj| match obj {
                StixObjectEnum::Indicator(i) => Some(i),
                _ => None,
            })
            .collect()
    }

    /// Get all ThreatActor objects
    pub fn threat_actors(&self) -> Vec<&crate::sdos::ThreatActor> {
        self.objects
            .iter()
            .filter_map(|obj| match obj {
                StixObjectEnum::ThreatActor(t) => Some(t),
                _ => None,
            })
            .collect()
    }

    /// Get all AttackPattern objects
    pub fn attack_patterns(&self) -> Vec<&crate::sdos::AttackPattern> {
        self.objects
            .iter()
            .filter_map(|obj| match obj {
                StixObjectEnum::AttackPattern(a) => Some(a),
                _ => None,
            })
            .collect()
    }

    /// Get all Campaign objects
    pub fn campaigns(&self) -> Vec<&crate::sdos::Campaign> {
        self.objects
            .iter()
            .filter_map(|obj| match obj {
                StixObjectEnum::Campaign(c) => Some(c),
                _ => None,
            })
            .collect()
    }

    /// Get all Relationship objects
    pub fn relationships(&self) -> Vec<&crate::sros::Relationship> {
        self.objects
            .iter()
            .filter_map(|obj| match obj {
                StixObjectEnum::Relationship(r) => Some(r),
                _ => None,
            })
            .collect()
    }

    /// Count objects by type
    ///
    /// # Examples
    ///
    /// ```
    /// use stix_rs::{Bundle, Malware};
    ///
    /// let m1 = Malware::builder().name("M1").malware_types(vec!["trojan".into()]).build().unwrap();
    /// let m2 = Malware::builder().name("M2").malware_types(vec!["ransomware".into()]).build().unwrap();
    ///
    /// let bundle = Bundle::new(vec![m1.into(), m2.into()]);
    ///
    /// assert_eq!(bundle.count_by_type("malware"), 2);
    /// assert_eq!(bundle.count_by_type("indicator"), 0);
    /// ```
    pub fn count_by_type(&self, type_name: &str) -> usize {
        self.objects
            .iter()
            .filter(|obj| obj.type_() == type_name)
            .count()
    }

    /// Get all unique object types in this bundle
    ///
    /// # Examples
    ///
    /// ```
    /// use stix_rs::{Bundle, Identity, Malware, IdentityClass};
    ///
    /// let identity = Identity::builder()
    ///     .name("ACME")
    ///     .class(IdentityClass::Organization)
    ///     .build()
    ///     .unwrap();
    ///
    /// let malware = Malware::builder()
    ///     .name("BadWare")
    ///     .malware_types(vec!["trojan".into()])
    ///     .build()
    ///     .unwrap();
    ///
    /// let bundle = Bundle::new(vec![identity.into(), malware.into()]);
    /// let types = bundle.object_types();
    ///
    /// assert!(types.contains(&"identity"));
    /// assert!(types.contains(&"malware"));
    /// assert_eq!(types.len(), 2);
    /// ```
    pub fn object_types(&self) -> Vec<&str> {
        let mut types: Vec<&str> = self.objects.iter().map(|obj| obj.type_()).collect();
        types.sort_unstable();
        types.dedup();
        types
    }

    /// Find objects that reference a specific ID
    ///
    /// Useful for finding relationships or objects that reference a specific object
    pub fn find_references_to(&self, target_id: &str) -> Vec<&StixObjectEnum> {
        self.objects
            .iter()
            .filter(|obj| match obj {
                StixObjectEnum::Relationship(r) => {
                    r.source_ref == target_id || r.target_ref == target_id
                }
                StixObjectEnum::Sighting(s) => s.sighting_of_ref == target_id,
                // Could extend to check created_by_ref, etc.
                _ => false,
            })
            .collect()
    }

    /// Returns the number of objects in the bundle
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Returns true if the bundle contains no objects
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Identity, IdentityClass, Malware, StixObjectEnum};

    #[test]
    fn bundle_serializes_objects() {
        let idty = Identity::builder()
            .name("ACME")
            .class(IdentityClass::Organization)
            .build()
            .unwrap();
        let obj = StixObjectEnum::Identity(idty);
        let bundle = Bundle::new(vec![obj]);
        let s = serde_json::to_string(&bundle).unwrap();
        assert!(s.contains("\"type\":\"bundle\""));
        assert!(s.contains("\"objects\""));
        assert!(s.contains("\"type\":\"identity\""));
    }

    #[test]
    fn bundle_get_by_id() {
        let identity = Identity::builder()
            .name("Test Org")
            .class(IdentityClass::Organization)
            .build()
            .unwrap();

        let id = identity.id().to_string();
        let bundle = Bundle::new(vec![identity.into()]);

        assert!(bundle.get(&id).is_some());
        assert!(bundle.get("nonexistent--id").is_none());
    }

    #[test]
    fn bundle_filter_by_type() {
        let identity = Identity::builder()
            .name("Org")
            .class(IdentityClass::Organization)
            .build()
            .unwrap();

        let malware = Malware::builder()
            .name("BadWare")
            .malware_types(vec!["trojan".into()])
            .build()
            .unwrap();

        let bundle = Bundle::new(vec![identity.into(), malware.into()]);

        let malware_objects = bundle.filter_by_type("malware");
        assert_eq!(malware_objects.len(), 1);

        let identity_objects = bundle.filter_by_type("identity");
        assert_eq!(identity_objects.len(), 1);
    }

    #[test]
    fn bundle_typed_getters() {
        let identity = Identity::builder()
            .name("Org")
            .class(IdentityClass::Organization)
            .build()
            .unwrap();

        let m1 = Malware::builder()
            .name("M1")
            .malware_types(vec!["trojan".into()])
            .build()
            .unwrap();

        let m2 = Malware::builder()
            .name("M2")
            .malware_types(vec!["ransomware".into()])
            .build()
            .unwrap();

        let bundle = Bundle::new(vec![identity.into(), m1.into(), m2.into()]);

        assert_eq!(bundle.identities().len(), 1);
        assert_eq!(bundle.malware().len(), 2);
        assert_eq!(bundle.indicators().len(), 0);
    }

    #[test]
    fn bundle_count_and_types() {
        let m1 = Malware::builder()
            .name("M1")
            .malware_types(vec!["trojan".into()])
            .build()
            .unwrap();
        let m2 = Malware::builder()
            .name("M2")
            .malware_types(vec!["ransomware".into()])
            .build()
            .unwrap();

        let bundle = Bundle::new(vec![m1.into(), m2.into()]);

        assert_eq!(bundle.count_by_type("malware"), 2);
        assert_eq!(bundle.len(), 2);
        assert!(!bundle.is_empty());

        let types = bundle.object_types();
        assert_eq!(types, vec!["malware"]);
    }
}
