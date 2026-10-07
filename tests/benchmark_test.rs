use std::time::Instant;

#[test]
fn test_microbenchmark_throughput_sla() {
    let test_lines: Vec<String> = (0..1000)
        .map(|i| {
            if i % 250 == 0 {
                "const stripeKey = \"sk_live_51AbcDefGhIjKlMnOpQrStUvWxYz123456\";".to_string()
            } else {
                format!("const variable_{i} = \"non_secret_standard_application_code_value_{i}\";")
            }
        })
        .collect();

    let payload = test_lines.join("\n");

    let engine = sentris::detector::DetectorEngine::new().expect("Failed to initialize engine");

    // Benchmark 1: Detector scan throughput
    let start = Instant::now();
    let findings = engine.scan_text(&payload, "benchmark.js");
    let duration = start.elapsed();

    assert_eq!(findings.len(), 4);
    // Performance SLA: Sub-35ms in release, <150ms in unoptimized debug test profile
    let max_allowed_ms = if cfg!(debug_assertions) { 150 } else { 35 };
    assert!(
        duration.as_millis() <= max_allowed_ms,
        "Detection SLA violated: took {}ms (expected <{}ms)",
        duration.as_millis(),
        max_allowed_ms
    );

    // Benchmark 2: False positive filter latency (<1 microsecond per token)
    let sample_token = "AKIAIOSFODNN7EXAMPLE";
    let fp_start = Instant::now();
    for _ in 0..10_000 {
        let _ = sentris::detector::false_positives::FalsePositiveFilter::is_false_positive(
            sample_token,
            "aws-access-key-id",
            "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'",
        );
    }
    let fp_duration = fp_start.elapsed();
    let per_token_ns = fp_duration.as_nanos() / 10_000;
    // Must be under 1,000ns (1µs) per check
    assert!(
        per_token_ns < 1000,
        "FP Filter SLA violated: took {}ns/token (expected <1000ns)",
        per_token_ns
    );
}
