use chrono::Utc;
use stix_rs::objects::Indicator;
use stix_rs::pattern::{PatternBuilder, validate_pattern};
use stix_rs::vocab::IndicatorPatternType;

#[test]
fn test_indicator_with_pattern_validation() {
    // Valid pattern - should build successfully
    let indicator = Indicator::builder()
        .name("File Hash Indicator")
        .pattern("[file:hashes.MD5 = 'abc123']")
        .pattern_type(IndicatorPatternType::Stix)
        .valid_from(Utc::now())
        .validate_pattern(true) // Enable validation
        .build()
        .unwrap();

    // Validate pattern after creation
    assert!(indicator.validate_pattern().is_ok());
}

#[test]
fn test_invalid_pattern_rejected() {
    // Invalid pattern - missing brackets
    let result = Indicator::builder()
        .name("Bad Indicator")
        .pattern("file:hashes.MD5 = 'abc123'") // Missing []
        .pattern_type(IndicatorPatternType::Stix)
        .valid_from(Utc::now())
        .validate_pattern(true)
        .build();

    assert!(result.is_err());
}

#[test]
fn test_pattern_builder() {
    let pattern = PatternBuilder::new()
        .compare("file", "hashes.MD5", "=", "'abc123'")
        .and()
        .compare("file", "size", ">", "1000")
        .build();

    assert!(validate_pattern(&pattern).is_ok());

    // Use it in an indicator
    let indicator = Indicator::builder()
        .name("Complex File Indicator")
        .pattern(&pattern)
        .pattern_type(IndicatorPatternType::Stix)
        .valid_from(Utc::now())
        .build()
        .unwrap();

    assert!(indicator.validate_pattern().is_ok());
}

#[test]
fn test_various_valid_patterns() {
    let patterns = vec![
        "[ipv4-addr:value = '192.168.1.1']",
        "[domain-name:value = 'evil.com']",
        "[url:value = 'https://malicious.com/payload']",
        "[email-addr:value = 'attacker@evil.com']",
        "[network-traffic:src_port = 443]",
        "[process:name = 'malware.exe']",
        "[x509-certificate:hashes.SHA-256 = 'abc...']",
        "[file:name = 'bad.exe' AND file:size > 1000]",
        "[ipv4-addr:value = '10.0.0.1' OR ipv4-addr:value = '10.0.0.2']",
    ];

    for pattern in patterns {
        assert!(
            validate_pattern(pattern).is_ok(),
            "Pattern should be valid: {}",
            pattern
        );
    }
}

#[test]
fn test_non_stix_patterns_not_validated() {
    // PCRE patterns are not validated - stored as-is
    let indicator = Indicator::builder()
        .name("PCRE Indicator")
        .pattern("^malware.*\\.exe$")
        .pattern_type(IndicatorPatternType::Pcre)
        .valid_from(Utc::now())
        .validate_pattern(true) // Validation only applies to STIX patterns
        .build()
        .unwrap();

    // PCRE validation should succeed (it's not validated)
    assert!(indicator.validate_pattern().is_ok());
}
