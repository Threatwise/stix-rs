use chrono::Utc;
use stix_rs::objects::{Identity, Indicator};
use stix_rs::vocab::{IdentityClass, IndicatorPatternType};
use stix_rs::bundle::Bundle;

#[test]
fn test_complex_workflow() {
    // 1. Build an Identity (Sensor)
    let sensor = Identity::builder()
        .name("Honeypot-Beta")
        .identity_class(IdentityClass::System)
        .property("x_custom_region", "us-east-1") // Test custom property
        .build()
        .unwrap();

    // 2. Build an Indicator (Bad IP)
    let indicator = Indicator::builder()
        .name("Malicious IP")
        .pattern("[ipv4-addr:value = '198.51.100.1']")
        .pattern_type(IndicatorPatternType::Stix)
        .valid_from(Utc::now())
        .build()
        .unwrap();

    // 3. Bundle them
    let bundle = Bundle::new(vec![sensor.into(), indicator.into()]);

    // 4. Serialize
    let json = serde_json::to_string_pretty(&bundle).unwrap();
    println!("{}", json);

    // 5. Verify
    assert!(json.contains("\"type\": \"bundle\""));
    assert!(json.contains("\"x_custom_region\": \"us-east-1\""));
    // serialization uses snake_case keys for compatibility with our consumers
    assert!(json.contains("\"identity_class\": \"system\""));
}
