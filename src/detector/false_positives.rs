//! Comprehensive False Positive Suppression Engine
//! Filters out documentation samples, dummy placeholders, template expressions,
//! sequential keyboard walks, and public object identifiers (UUIDs).

pub struct FalsePositiveFilter;

fn is_generic_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "generic-api-key" | "credential-assignment" | "credential-assignment-unquoted"
    )
}

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

        // 6. Syntactic comment & documentation example context awareness
        if Self::is_comment_documentation_example(rule_id, line_context) {
            return true;
        }

        false
    }

    /// Syntactic context check: suppresses generic-api-key matches or documentation examples
    /// that appear purely inside source code comments (`//`, `#`, `/*`, `* `, `--`).
    fn is_comment_documentation_example(rule_id: &str, line_context: &str) -> bool {
        let trimmed_line = line_context.trim_start();
        let is_comment = trimmed_line.starts_with("//")
            || trimmed_line.starts_with('#')
            || trimmed_line.starts_with("/*")
            || trimmed_line.starts_with("* ")
            || (trimmed_line.starts_with("--")
                && trimmed_line[2..].starts_with(|c: char| c.is_whitespace()));

        if !is_comment {
            return false;
        }

        // Keyed generic assignments inside code comments are almost universally documentation prose;
        // credential-assignment needs an explicit doc marker because commented-out credentials are still leaks
        if rule_id == "generic-api-key" {
            return true;
        }

        let lower = trimmed_line.to_ascii_lowercase();
        let doc_indicators = [
            "example",
            "e.g.",
            "eg:",
            "sample",
            "format:",
            "looks like",
            "placeholder",
            "mock",
            "dummy",
            "pattern",
        ];

        doc_indicators.iter().any(|ind| lower.contains(ind))
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

        // Check for consecutive identical character runs (e.g. ghp_aaaaaaaaaaaa or sk_live_1111111111)
        let bytes = token.as_bytes();
        let mut identical_run = 1usize;
        for window in bytes.windows(2) {
            if window[0] == window[1] {
                identical_run += 1;
                if identical_run >= 8 {
                    return true;
                }
            } else {
                identical_run = 1;
            }
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

        if rule_id.starts_with("credential-assignment")
            && !Self::looks_like_literal_credential(token, line_context)
        {
            return true;
        }

        // 1. Generic API Key heuristics
        if is_generic_rule(rule_id) {
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

        if rule_id == "url-basic-auth" {
            let password = token
                .split_once(':')
                .map_or("", |(_, p)| p)
                .to_ascii_lowercase();
            const PLACEHOLDERS: [&str; 12] = [
                "password",
                "pass",
                "passwd",
                "pwd",
                "secret",
                "token",
                "changeme",
                "example",
                "yourpassword",
                "your_password",
                "xxxx",
                "user",
            ];
            if PLACEHOLDERS.contains(&password.as_str())
                || password.chars().all(|c| c == 'x' || c == '*')
            {
                return true;
            }
        }

        // 2. Stripe test keys and publishable keys are not production secrets, whichever rule matched them
        if (rule_id.starts_with("stripe-") || is_generic_rule(rule_id))
            && Self::is_stripe_non_secret(token)
        {
            return true;
        }

        // 3. OpenAI rule heuristics: Anthropic tokens starting with sk-ant- are not OpenAI keys
        if rule_id == "openai-api-key" && token.starts_with("sk-ant-") {
            return true;
        }

        false
    }

    /// Quoted literal assigned to a password/token-like name: reject code references, paths,
    /// dictionary words and identifiers; keep strings that look machine- or human-generated secrets.
    fn looks_like_literal_credential(token: &str, line: &str) -> bool {
        let lower = token.to_ascii_lowercase();
        const STOPWORDS: [&str; 24] = [
            "example",
            "changeme",
            "change_me",
            "redacted",
            "placeholder",
            "dummy",
            "sample",
            "your",
            "insert",
            "xxxx",
            "****",
            "localhost",
            "process.env",
            "getenv",
            "environ",
            "secretmanager",
            "undefined",
            "required",
            "bearer",
            "basic ",
            "password",
            "secret",
            "token",
            "null",
        ];
        if STOPWORDS.iter().any(|w| lower.contains(w)) {
            return false;
        }
        let bytes = token.as_bytes();
        let env_ref = bytes[0] == b'$'
            && bytes
                .get(1)
                .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_');
        if env_ref
            || matches!(bytes[0], b'<' | b'{' | b'[' | b'/')
            || token.starts_with("~/")
            || token.starts_with("./")
            || token.contains("://")
            || token.contains(['(', ')', '{', '}', '<', '>', '\\'])
        {
            return false;
        }
        const HASH_PREFIXES: [&str; 9] = [
            "$2a$", "$2b$", "$2y$", "$argon2", "$pbkdf2", "$scrypt", "$1$", "$5$", "$6$",
        ];
        if HASH_PREFIXES.iter().any(|p| token.starts_with(p)) || lower.starts_with("pbkdf2_") {
            return false;
        }
        if Self::key_names_a_hash(line, token)
            && matches!(token.len(), 32 | 40 | 64 | 128)
            && token.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return false;
        }
        if Self::is_word_phrase(token) || Self::is_camel_identifier(token) {
            return false;
        }
        let has_digit = token.bytes().any(|b| b.is_ascii_digit());
        let has_upper = token.bytes().any(|b| b.is_ascii_uppercase());
        let has_lower = token.bytes().any(|b| b.is_ascii_lowercase());
        let has_symbol = token
            .bytes()
            .any(|b| b.is_ascii_punctuation() && !matches!(b, b'.' | b'-' | b'_' | b'/'));
        has_digit
            || [has_upper, has_lower, has_symbol]
                .iter()
                .filter(|&&c| c)
                .count()
                >= 3
            || Self::case_flip_ratio(token) >= 0.3
    }

    /// Stripe test-mode and publishable keys (sk_test_, rk_test_, pk_test_, pk_live_) with a full-length body
    fn is_stripe_non_secret(token: &str) -> bool {
        ["sk_test_", "rk_test_", "pk_test_", "pk_live_"]
            .iter()
            .find_map(|p| token.strip_prefix(p))
            .is_some_and(|body| {
                body.len() >= 16 && body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
    }

    /// True when the assigned name *ends* in a hash word (`secret_hash`, `tokenSha256`, `password.digest`);
    /// `shared_secret` or `hash_secret` are not hashes
    fn key_names_a_hash(line: &str, token: &str) -> bool {
        const HASH_WORDS: [&str; 9] = [
            "hash",
            "digest",
            "checksum",
            "sha1",
            "sha256",
            "sha512",
            "md5",
            "etag",
            "fingerprint",
        ];
        let Some(idx) = line.find(token) else {
            return false;
        };
        let before =
            line[..idx].trim_end_matches(|c: char| c.is_whitespace() || "'\"=:>".contains(c));
        let key: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let last = key.rsplit(['_', '-', '.']).next().unwrap_or("");
        let camel_tail = last
            .rfind(|c: char| c.is_ascii_uppercase())
            .map_or(last, |i| &last[i..]);
        [last, camel_tail]
            .iter()
            .any(|w| HASH_WORDS.contains(&w.to_ascii_lowercase().as_str()))
    }

    /// Separator-joined lowercase words ("group-2024-xmas-party", "auth.reset.expired") are names, not secrets
    fn is_word_phrase(token: &str) -> bool {
        let segments: Vec<&str> = token
            .split(['-', '_', '.'])
            .filter(|s| !s.is_empty())
            .collect();
        segments.len() >= 3
            && segments.iter().all(|s| {
                s.bytes().all(|b| b.is_ascii_digit())
                    || (s.len() >= 3 && s.bytes().all(|b| b.is_ascii_lowercase()))
            })
    }

    /// Letters-only values with a natural-language vowel share ("NonExpressionParenKeyword") are identifiers;
    /// random letters average ~19% vowels, English-like words 35-45%.
    fn is_camel_identifier(token: &str) -> bool {
        let body = token.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
        if body.len() < 10 || !body.bytes().all(|b| b.is_ascii_alphabetic()) {
            return false;
        }
        let vowels = body.bytes().filter(|b| b"aeiouAEIOU".contains(b)).count();
        vowels * 10 >= body.len() * 3
    }

    /// Share of adjacent letter pairs that flip case: ~0.5 for random letters, ~0.15 for camelCase identifiers
    fn case_flip_ratio(token: &str) -> f64 {
        let letters: Vec<bool> = token
            .bytes()
            .filter(u8::is_ascii_alphabetic)
            .map(|b| b.is_ascii_uppercase())
            .collect();
        if letters.len() < 2 {
            return 0.0;
        }
        letters.windows(2).filter(|w| w[0] != w[1]).count() as f64 / (letters.len() - 1) as f64
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

    #[test]
    fn test_syntactic_comment_documentation_suppression() {
        assert!(FalsePositiveFilter::is_false_positive(
            concat!("sk_live_", "51AbcDefGhIjKlMnOpQrStUvWxYz123456"),
            "stripe-secret-key",
            concat!(
                "// Example format: const key = '",
                "sk_live_",
                "51AbcDefGhIjKlMnOpQrStUvWxYz123456';"
            )
        ));

        assert!(FalsePositiveFilter::is_false_positive(
            "xK9mP2vL8qR4tW7zN1bY5jC3dF6hT0sU8yA2",
            "generic-api-key",
            concat!("# api_key = '", "xK9mP2vL8qR4tW7zN1bY5jC3dF6hT0sU8yA2'")
        ));
    }
}

#[cfg(test)]
mod review_regressions {
    use super::*;

    #[test]
    fn hash_key_detection_uses_last_name_segment() {
        let hash = |line: &str, token: &str| FalsePositiveFilter::key_names_a_hash(line, token);
        let hex = "a737a27cef579e9dfeeaf6d87209f034";
        assert!(hash(&format!("secret_hash = \"{hex}\""), hex));
        assert!(hash(&format!("tokenSha256: '{hex}'"), hex));
        assert!(!hash(&format!("shared_secret = \"{hex}\""), hex));
        assert!(!hash(&format!("hash_secret = \"{hex}\""), hex));
    }

    #[test]
    fn stripe_exemption_needs_stripe_rule_and_full_body() {
        let body = "51AbcDefGhIjKlMnOpQrStUv";
        let key = format!("sk_test_{body}");
        assert!(FalsePositiveFilter::is_false_positive(
            &key,
            "stripe-secret-key",
            &key
        ));
        assert!(!FalsePositiveFilter::is_false_positive(
            "sk_test_Zq8",
            "credential-assignment",
            "token = \"sk_test_Zq8\""
        ));
    }
}
