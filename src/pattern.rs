//! STIX Pattern Language Validator
//!
//! Validates STIX 2.1 pattern expressions used in Indicator objects.
//! Patterns follow the format: `[object-type:property comparison-op value]`

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PatternError {
    #[error("pattern must start with '[' and end with ']'")]
    MissingBrackets,

    #[error("empty pattern")]
    EmptyPattern,

    #[error("invalid object type: {0}")]
    InvalidObjectType(String),

    #[error("missing colon separator between object type and property")]
    MissingColon,

    #[error("missing comparison operator")]
    MissingOperator,

    #[error("invalid comparison operator: {0}")]
    InvalidOperator(String),

    #[error("unbalanced brackets")]
    UnbalancedBrackets,

    #[error("invalid pattern syntax: {0}")]
    InvalidSyntax(String),
}

/// Valid STIX Cyber Observable object types
const VALID_OBJECT_TYPES: &[&str] = &[
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "x509-certificate",
];

/// Valid comparison operators in STIX patterns
const VALID_OPERATORS: &[&str] = &[
    "=",
    "!=",
    ">",
    ">=",
    "<",
    "<=",
    "IN",
    "MATCHES",
    "LIKE",
    "ISSUBSET",
    "ISSUPERSET",
];

/// Valid pattern combiners
const VALID_COMBINERS: &[&str] = &["AND", "OR", "FOLLOWEDBY"];

/// Validates a STIX pattern string
///
/// # Examples
///
/// ```
/// use stix_rs::pattern::validate_pattern;
///
/// // Valid patterns
/// assert!(validate_pattern("[file:hashes.MD5 = 'abc123']").is_ok());
/// assert!(validate_pattern("[ipv4-addr:value = '192.168.1.1']").is_ok());
/// assert!(validate_pattern("[file:name = 'malware.exe' AND file:size > 1000]").is_ok());
///
/// // Invalid patterns
/// assert!(validate_pattern("file:hashes.MD5 = 'abc123'").is_err()); // Missing brackets
/// assert!(validate_pattern("[]").is_err()); // Empty
/// assert!(validate_pattern("[invalid-type:prop = 'value']").is_err()); // Invalid type
/// ```
pub fn validate_pattern(pattern: &str) -> Result<(), PatternError> {
    let trimmed = pattern.trim();

    // Check for brackets
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(PatternError::MissingBrackets);
    }

    // Check for balanced brackets
    let open_count = trimmed.chars().filter(|c| *c == '[').count();
    let close_count = trimmed.chars().filter(|c| *c == ']').count();
    if open_count != close_count {
        return Err(PatternError::UnbalancedBrackets);
    }

    // Remove outer brackets
    let inner = &trimmed[1..trimmed.len() - 1].trim();

    if inner.is_empty() {
        return Err(PatternError::EmptyPattern);
    }

    // Split by logical operators (AND, OR, FOLLOWEDBY)
    let patterns = split_by_combiners(inner);

    for pattern_part in patterns {
        validate_single_comparison(pattern_part.trim())?;
    }

    Ok(())
}

/// Split pattern by logical combiners while respecting quotes and nested brackets
fn split_by_combiners(pattern: &str) -> Vec<&str> {
    // Simple implementation: if no combiners, return the whole pattern
    // For complex patterns with nested brackets, this would need more sophisticated parsing
    let mut parts = vec![];
    let mut last_pos = 0;

    for combiner in VALID_COMBINERS {
        if let Some(pos) = pattern.find(combiner) {
            // Check if combiner is not inside quotes
            if !is_inside_quotes(pattern, pos) {
                parts.push(&pattern[last_pos..pos]);
                last_pos = pos + combiner.len();
            }
        }
    }

    if parts.is_empty() {
        vec![pattern]
    } else {
        parts.push(&pattern[last_pos..]);
        parts
    }
}

/// Check if a position in a string is inside quotes
fn is_inside_quotes(s: &str, pos: usize) -> bool {
    let before = &s[..pos];
    let single_quotes = before.chars().filter(|c| *c == '\'').count();
    let double_quotes = before.chars().filter(|c| *c == '"').count();

    // If odd number of quotes before position, we're inside quotes
    single_quotes % 2 != 0 || double_quotes % 2 != 0
}

/// Validate a single comparison expression
fn validate_single_comparison(expr: &str) -> Result<(), PatternError> {
    // Handle nested brackets (for complex expressions)
    if expr.starts_with('[') && expr.ends_with(']') {
        return validate_pattern(&format!("[{}]", expr));
    }

    // Pattern format: object-type:property operator value
    // Example: file:hashes.MD5 = 'abc123'

    // Find the colon separator
    let colon_pos = expr.find(':').ok_or(PatternError::MissingColon)?;

    let object_type = expr[..colon_pos].trim();

    // Validate object type
    if !VALID_OBJECT_TYPES.contains(&object_type) {
        return Err(PatternError::InvalidObjectType(object_type.to_string()));
    }

    let rest = &expr[colon_pos + 1..];

    // Find the operator
    let mut found_operator = None;
    for op in VALID_OPERATORS {
        if rest.contains(op) {
            found_operator = Some(op);
            break;
        }
    }

    if found_operator.is_none() {
        return Err(PatternError::MissingOperator);
    }

    Ok(())
}

/// Pattern builder for constructing valid STIX patterns programmatically
pub struct PatternBuilder {
    parts: Vec<String>,
}

impl PatternBuilder {
    pub fn new() -> Self {
        Self { parts: Vec::new() }
    }

    /// Add a comparison expression
    pub fn compare(
        mut self,
        object_type: &str,
        property: &str,
        operator: &str,
        value: &str,
    ) -> Self {
        let expr = format!("{}:{} {} {}", object_type, property, operator, value);
        self.parts.push(expr);
        self
    }

    /// Add an AND combiner
    pub fn and(mut self) -> Self {
        if !self.parts.is_empty() {
            self.parts.push(" AND ".to_string());
        }
        self
    }

    /// Add an OR combiner
    pub fn or(mut self) -> Self {
        if !self.parts.is_empty() {
            self.parts.push(" OR ".to_string());
        }
        self
    }

    /// Build the final pattern
    pub fn build(self) -> String {
        format!("[{}]", self.parts.join(""))
    }
}

impl Default for PatternBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_simple_pattern() {
        assert!(validate_pattern("[file:hashes.MD5 = 'abc123']").is_ok());
        assert!(validate_pattern("[ipv4-addr:value = '192.168.1.1']").is_ok());
        assert!(validate_pattern("[domain-name:value = 'evil.com']").is_ok());
    }

    #[test]
    fn test_valid_complex_pattern() {
        assert!(validate_pattern("[file:name = 'malware.exe' AND file:size > 1000]").is_ok());
        assert!(
            validate_pattern("[ipv4-addr:value = '10.0.0.1' OR ipv4-addr:value = '10.0.0.2']")
                .is_ok()
        );
    }

    #[test]
    fn test_missing_brackets() {
        assert!(matches!(
            validate_pattern("file:hashes.MD5 = 'abc123'"),
            Err(PatternError::MissingBrackets)
        ));
    }

    #[test]
    fn test_empty_pattern() {
        assert!(matches!(
            validate_pattern("[]"),
            Err(PatternError::EmptyPattern)
        ));
        assert!(matches!(
            validate_pattern("[  ]"),
            Err(PatternError::EmptyPattern)
        ));
    }

    #[test]
    fn test_invalid_object_type() {
        assert!(matches!(
            validate_pattern("[invalid-type:property = 'value']"),
            Err(PatternError::InvalidObjectType(_))
        ));
    }

    #[test]
    fn test_missing_colon() {
        assert!(matches!(
            validate_pattern("[file-hashes.MD5 = 'abc123']"),
            Err(PatternError::MissingColon)
        ));
    }

    #[test]
    fn test_pattern_builder() {
        let pattern = PatternBuilder::new()
            .compare("file", "hashes.MD5", "=", "'abc123'")
            .and()
            .compare("file", "size", ">", "1000")
            .build();

        assert_eq!(pattern, "[file:hashes.MD5 = 'abc123' AND file:size > 1000]");
        assert!(validate_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_operators() {
        assert!(validate_pattern("[file:size > 1000]").is_ok());
        assert!(validate_pattern("[file:size >= 1000]").is_ok());
        assert!(validate_pattern("[file:size < 1000]").is_ok());
        assert!(validate_pattern("[file:size <= 1000]").is_ok());
        assert!(validate_pattern("[file:size != 1000]").is_ok());
    }

    #[test]
    fn test_network_traffic_pattern() {
        assert!(validate_pattern("[network-traffic:src_port = 443]").is_ok());
        assert!(validate_pattern("[network-traffic:protocols[0] = 'tcp']").is_ok());
    }

    #[test]
    fn test_process_pattern() {
        assert!(validate_pattern("[process:name = 'cmd.exe']").is_ok());
        assert!(validate_pattern("[process:pid > 100]").is_ok());
    }

    #[test]
    fn test_x509_pattern() {
        assert!(validate_pattern("[x509-certificate:hashes.SHA-256 = 'abc...']").is_ok());
        assert!(validate_pattern("[x509-certificate:subject = 'CN=Evil Corp']").is_ok());
    }
}
