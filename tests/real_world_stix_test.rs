use stix_rs::bundle::Bundle;

#[test]
fn test_deserialize_malware_example() {
    // Real STIX 2.1 Malware object example
    let stix_json = r#"{
        "type": "bundle",
        "id": "bundle--44af6c39-c09b-49c5-9de2-394224b04982",
        "objects": [
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--92ec0cbd-2c30-44a2-b270-73f4ec949841",
                "created": "2017-05-19T13:02:31.000Z",
                "modified": "2017-05-19T13:02:31.000Z",
                "name": "Poison Ivy",
                "description": "Poison Ivy is a popular remote access trojan (RAT) that has been used by many groups",
                "malware-types": ["remote-access-trojan"],
                "is-family": true,
                "aliases": ["PIVY"],
                "kill-chain-phases": [{
                    "kill-chain-name": "mandiant-attack-lifecycle-model",
                    "phase-name": "establish-foothold"
                }]
            }
        ]
    }"#;

    // Test deserialization
    let bundle: Bundle = serde_json::from_str(stix_json).unwrap();

    assert_eq!(bundle.r#type, "bundle");
    assert_eq!(bundle.objects.len(), 1);

    // Test serialization round-trip
    let serialized = serde_json::to_string(&bundle).unwrap();
    let deserialized: Bundle = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.objects.len(), 1);
}

#[test]
fn test_deserialize_indicator_with_valid_from() {
    // STIX 2.1 Indicator with valid_from field
    let stix_json = r#"{
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "name": "Malicious site hosting downloader",
        "description": "This indicator identifies the SSL certificate for the malicious site",
        "indicator-types": ["malicious-activity"],
        "pattern": "[x509-certificate:hashes.SHA-256 = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
        "pattern-type": "stix",
        "pattern-version": "2.1",
        "valid-from": "2016-01-01T00:00:00Z"
    }"#;

    let indicator: stix_rs::objects::Indicator = serde_json::from_str(stix_json).unwrap();

    assert_eq!(indicator.name.as_deref(), Some("Malicious site hosting downloader"));
    assert_eq!(indicator.pattern_type, stix_rs::vocab::IndicatorPatternType::Stix);
    assert!(indicator.valid_from.to_rfc3339().starts_with("2016-01-01"));
}

#[test]
fn test_deserialize_marking_definition() {
    // STIX 2.1 TLP Marking Definition
    let stix_json = r#"{
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "modified": "2017-01-20T00:00:00.000Z",
        "name": "TLP:WHITE",
        "definition-type": "tlp",
        "definition": {
            "tlp": "white"
        }
    }"#;

    let marking: stix_rs::common::MarkingDefinition = serde_json::from_str(stix_json).unwrap();

    assert_eq!(marking.definition_type, "tlp");
    assert_eq!(marking.name.as_deref(), Some("TLP:WHITE"));
}
