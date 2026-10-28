//! Comprehensive False Positive Suppression Engine
//! Filters out documentation samples, dummy placeholders, template expressions,
//! sequential keyboard walks, and public object identifiers (UUIDs).

pub struct FalsePositiveFilter;

impl FalsePositiveFilter {
    /// Evaluates whether a matched candidate secret is a false positive
    pub fn is_false_positive(candidate: &str, rule_id: &str, line_context: &str) -> bool {
        let trimmed = candidate
            .trim()
            .trim_matches(&['"', '\'', '`', ';', ','][..]);

        // 1. Exact known documentation and sample credentials
        if Self::is_known_documentation_credential(trimmed) {
            return true;
        }

        // 2. Template interpolations and placeholder variable expressions
        if Self::is_template_or_placeholder_expression(trimmed, line_context) {
            return true;
        }

        // 3. Monotonous / low unique character count (e.g. 000000..., XXXXX...)
        if Self::is_monotonous_character_set(trimmed) {
            return true;
        }

        // 4. Sequential alphabetical or numeric keyboard walks
        if Self::is_sequential_run(trimmed) {
            return true;
        }

        // 5. Rule-specific heuristics (e.g. UUIDs and public IDs in generic-api-key)
        if Self::is_rule_specific_fp(trimmed, rule_id, line_context) {
            return true;
        }

        false
    }

    /// Known documentation, official SDK examples, and RFC sample keys
    fn is_known_documentation_credential(token: &str) -> bool {
        // AWS documentation standard examples
        if token == "AKIAIOSFODNN7EXAMPLE"
            || token == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            || token == "AKIAI44QH8DHBEXAMPLE"
            || token == "AKIAEXAMPLEEXAMPLEE"
        {
            return true;
        }

        // Google / Firebase documentation examples
        if token.starts_with("AIzaSyD-EXAMPLE")
            || token == "AIzaSyDummySecretKeyForDocumentation123"
        {
            return true;
        }

        // GitHub documentation examples
        if token.starts_with("ghp_EXAMPLE")
            || token == "ghp_000000000000000000000000000000000000"
            || token == "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        {
            return true;
        }

        // Slack documentation examples
        if token.contains("T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX") {
            return true;
        }

        false
    }

    /// Placeholder, template interpolation, and documentation patterns
    fn is_template_or_placeholder_expression(token: &str, line_context: &str) -> bool {
        let token_upper = token.to_ascii_uppercase();
        let line_upper = line_context.to_ascii_uppercase();

        // Template interpolation markers: ${...}, {{...}}, <%...%>
        if token.contains("${")
            || token.contains("}}")
            || token.contains("<%")
            || token.contains("%>")
        {
            return true;
        }

        // Prominent placeholder prefix/substring indicators
        let placeholder_markers = [
            "YOUR_KEY",
            "YOUR_API_KEY",
            "YOUR_SECRET",
            "YOUR_TOKEN",
            "YOUR_CREDENTIAL",
            "YOUR-KEY",
            "YOUR-API-KEY",
            "INSERT_KEY",
            "INSERT_HERE",
            "REPLACE_WITH",
            "REPLACE_ME",
            "CHANGE_ME",
            "CHANGEME",
            "PLACEHOLDER",
            "DUMMY_KEY",
            "DUMMY_TOKEN",
            "FAKE_KEY",
            "MOCK_KEY",
            "MOCK_TOKEN",
            "EXAMPLE_KEY",
            "EXAMPLE_TOKEN",
            "SAMPLE_KEY",
            "TEST_SECRET",
            "TEST_KEY",
            "FOOBAR",
            "TODO_KEY",
            "<YOUR_",
            "[YOUR_",
        ];

        for marker in placeholder_markers {
            if token_upper.contains(marker) {
                return true;
            }
        }

        // Line-level placeholder assignment checks: e.g. api_key = "<insert_your_key_here>"
        if (line_upper.contains("YOUR_API_KEY") || line_upper.contains("INSERT_YOUR_KEY"))
            && (line_context.contains('<') || line_context.contains('['))
        {
            return true;
        }

        false
    }

    /// Checks if token has virtually no character variance (e.g. repeated 0s, Xs, Fs)
    fn is_monotonous_character_set(token: &str) -> bool {
        if token.len() < 8 {
            return false;
        }

        let mut unique_mask = [false; 256];
        let mut unique_count = 0;

        for byte in token.bytes() {
            if !unique_mask[byte as usize] {
                unique_mask[byte as usize] = true;
                unique_count += 1;
            }
        }

        // If a 20+ character token has 3 or fewer distinct characters, it's a dummy repeated string
        if token.len() >= 20 && unique_count <= 3 {
            return true;
        }

        // If a 12+ character token has only 1 or 2 distinct characters (e.g. 000000000000)
        if token.len() >= 12 && unique_count <= 2 {
            return true;
        }

        false
    }

    /// Detects sequential alphabetical or numeric runs (keyboard walks)
    fn is_sequential_run(token: &str) -> bool {
        let bytes = token.as_bytes();
        if bytes.len() < 16 {
            return false;
        }

        // Check for long consecutive ascending ASCII sequences: e.g. "abcdefghijklmno"
        let mut ascending_run = 1;
        let mut max_ascending = 1;

        for window in bytes.windows(2) {
            if window[1] == window[0].wrapping_add(1) {
                ascending_run += 1;
                max_ascending = max_ascending.max(ascending_run);
            } else {
                ascending_run = 1;
            }
        }

        // A continuous sequential run of 10+ characters (e.g. abcdefghijk or 0123456789)
        if max_ascending >= 10 {
            return true;
        }

        false
    }

    /// Rule-specific false positive rules
    fn is_rule_specific_fp(token: &str, rule_id: &str, line_context: &str) -> bool {
        let line_lower = line_context.to_ascii_lowercase();

        // 1. Generic API Key heuristics
        if rule_id == "generic-api-key" {
            // Check if token is a standard UUIDv4: 8-4-4-4-12 hex format
            if Self::is_standard_uuid(token) {
                return true;
            }

            // Public object IDs, tracking IDs, or telemetry identifiers
            let public_id_indicators = [
                "request_id",
                "requestid",
                "req_id",
                "trace_id",
                "traceid",
                "correlation_id",
                "correlationid",
                "session_id",
                "sessionid",
                "client_id",
                "clientid",
                "user_id",
                "userid",
                "account_id",
                "accountid",
                "device_id",
                "deviceid",
                "model_id",
                "modelid",
                "uuid",
                "guid",
                "checksum",
                "sha256",
                "commit_hash",
                "commit_id",
                "git_commit",
            ];

            for indicator in public_id_indicators {
                if line_lower.contains(indicator) {
                    return true;
                }
            }
        }

        // 2. Stripe rule heuristics
        if rule_id == "stripe-secret-key" || rule_id == "stripe-restricted-key" {
            // Stripe test keys (sk_test_ / rk_test_) are safe non-production test keys
            if token.starts_with("sk_test_") || token.starts_with("rk_test_") {
                return true;
            }
        }

        // 3. OpenAI rule heuristics: Anthropic tokens starting with sk-ant- are not OpenAI keys
        if rule_id == "openai-api-key" && token.starts_with("sk-ant-") {
            return true;
        }

        false
    }

    /// Verifies if string conforms to standard UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    fn is_standard_uuid(token: &str) -> bool {
        if token.len() != 36 {
            return false;
        }

        let bytes = token.as_bytes();
        if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
            return false;
        }

        // All other characters must be hexadecimal digits
        token.chars().enumerate().all(|(i, c)| {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_documentation_example_suppression() {
        assert!(FalsePositiveFilter::is_false_positive(
            "AKIAIOSFODNN7EXAMPLE",
            "aws-access-key-id",
            "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'"
        ));
    }

    #[test]
    fn test_placeholder_suppression() {
        assert!(FalsePositiveFilter::is_false_positive(
            "your-api-key-here-1234567890123456",
            "generic-api-key",
            "const apiKey = 'your-api-key-here-1234567890123456';"
        ));

        assert!(FalsePositiveFilter::is_false_positive(
            "sk_live_YOUR_KEY_GOES_HERE_123456",
            "stripe-secret-key",
            "const key = 'sk_live_YOUR_KEY_GOES_HERE_123456';"
        ));
    }

    #[test]
    fn test_uuid_suppression_for_generic_keys() {
        assert!(FalsePositiveFilter::is_false_positive(
            "123e4567-e89b-12d3-a456-426614174000",
            "generic-api-key",
            "const id = '123e4567-e89b-12d3-a456-426614174000';"
        ));

        assert!(FalsePositiveFilter::is_false_positive(
            "4f8a9b2c1d3e5f7a8b9c0d1e2f3a4b5c",
            "generic-api-key",
            "const correlation_id = '4f8a9b2c1d3e5f7a8b9c0d1e2f3a4b5c';"
        ));
    }

    #[test]
    fn test_monotonous_and_sequential_suppression() {
        assert!(FalsePositiveFilter::is_false_positive(
            "00000000000000000000000000000000",
            "generic-api-key",
            "const key = '00000000000000000000000000000000';"
        ));

        assert!(FalsePositiveFilter::is_false_positive(
            "abcdefghijklmnopqrstuvwxyz123456",
            "generic-api-key",
            "const key = 'abcdefghijklmnopqrstuvwxyz123456';"
        ));
    }

    #[test]
    fn test_real_secret_is_not_suppressed() {
        assert!(!FalsePositiveFilter::is_false_positive(
            concat!("sk_live_", "51AbcDefGhIjKlMnOpQrStUvWxYz123456"),
            "stripe-secret-key",
            concat!(
                "const stripeKey = '",
                "sk_live_",
                "51AbcDefGhIjKlMnOpQrStUvWxYz123456';"
            )
        ));

        assert!(!FalsePositiveFilter::is_false_positive(
            concat!("AKIA2J5W", "9X7Y8Z9EXAMPLE"),
            "aws-access-key-id",
            concat!("export AWS_ACCESS_KEY_ID='", "AKIA2J5W", "9X7Y8Z9EXAMPLE'")
        ));
    }
}
