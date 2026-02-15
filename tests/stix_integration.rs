use serde_json::Value;

use stix_rs::{Identity, Sighting, StixObjectEnum, IdentityClass};

#[test]
fn test_identity_serialization() {
    let idty = Identity::builder()
        .name("ACME")
        .class(IdentityClass::Organization)
        .build()
        .unwrap();
    let s = serde_json::to_string(&idty).unwrap();
    let v: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v.get("type").and_then(Value::as_str).unwrap(), "identity");
    let id_field = v.get("id").and_then(Value::as_str).unwrap();
    assert!(id_field.starts_with("identity--"), "id does not start with identity--: {}", id_field);
}

#[test]
fn test_sighting_link() {
    let fake_malware = "malware--12345678-1234-1234-1234-1234567890ab";
    let fake_sensor = "sensor--87654321-4321-4321-4321-ba0987654321";

    let s = Sighting::builder()
        .count(5)
        .sighting_of_ref(fake_malware)
        .where_sighted_refs(vec![fake_sensor.to_string()])
        .build()
        .unwrap();
    let j = serde_json::to_string_pretty(&s).unwrap();

    // Print JSON to visually inspect in test output when running with --nocapture
    println!("Sighting JSON:\n{}", j);

    let v: Value = serde_json::from_str(&j).unwrap();

    assert_eq!(v.get("sighting_of_ref").and_then(Value::as_str).unwrap(), fake_malware);
    let where_refs = v.get("where_sighted_refs").and_then(Value::as_array).unwrap();
    assert_eq!(where_refs.len(), 1);
    assert_eq!(where_refs[0].as_str().unwrap(), fake_sensor);
}

#[test]
fn test_deserialization() {
    let raw = r#"
    {
      "type": "malware",
      "id": "malware--11111111-2222-3333-4444-555555555555",
      "created": "2020-01-01T00:00:00Z",
      "modified": "2020-01-01T00:00:00Z",
      "name": "EvilWare",
      "is_family": true,
      "malware_types": ["ransomware"]
    }
    "#;

    let obj: StixObjectEnum = serde_json::from_str(raw).expect("failed to deserialize StixObjectEnum");

    match obj {
        StixObjectEnum::Malware(m) => {
            assert_eq!(m.name, "EvilWare");
            assert!(m.is_family);
            assert_eq!(m.malware_types, vec!["ransomware".to_string()]);
        }
        other => panic!("Expected Malware variant, got: {:?}", other),
    }
}
