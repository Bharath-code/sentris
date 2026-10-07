/// Calculates the Shannon Entropy of a string.
/// Shannon entropy measures the unpredictability or randomness of information content.
/// Formula: H(X) = - \sum P(x) * \log_2(P(x))
/// High entropy (> 3.5 - 4.5 depending on alphabet) indicates likely cryptographic keys, hashes, or high-randomness tokens.
pub fn calculate_shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut char_counts = [0usize; 256];
    let mut total_chars = 0usize;

    for byte in data.bytes() {
        char_counts[byte as usize] += 1;
        total_chars += 1;
    }

    if total_chars == 0 {
        return 0.0;
    }

    let mut entropy = 0.0;
    let total = total_chars as f64;

    for &count in &char_counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Checks whether a given secret candidate meets the minimum entropy threshold.
#[allow(dead_code)]
pub fn is_high_entropy(data: &str, threshold: f64) -> bool {
    calculate_shannon_entropy(data) >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        assert_eq!(calculate_shannon_entropy(""), 0.0);
        assert_eq!(calculate_shannon_entropy("aaaaaaa"), 0.0);
    }

    #[test]
    fn test_high_entropy_random_key() {
        // High randomness token
        let key = "4f8a9b2c1d3e5f7a8b9c0d1e2f3a4b5c";
        let entropy = calculate_shannon_entropy(key);
        assert!(entropy > 3.0);
    }

    #[test]
    fn test_dummy_repeated_string() {
        // Low randomness dummy string
        let dummy = "sk_live_000000000000000000000000";
        let entropy = calculate_shannon_entropy(dummy);
        assert!(entropy < 2.5);
    }
}
