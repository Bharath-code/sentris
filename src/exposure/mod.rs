//! Read-only exposure probes: what can a leaked credential reach, observed through the provider.
//!
//! A tier is a capability judgement, never a dollar estimate; `measured_usd` is set only when the provider returned a number.
pub mod aws;
pub mod github;
pub mod http;
pub mod stripe;

use crate::error::SentrisError;
use crate::model::{Finding, ScanReport, Severity};
use crate::remediator::Remediator;
use crate::verifier::LiveStatus;
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lower")]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

impl From<Severity> for RiskTier {
    fn from(s: Severity) -> Self {
        match s {
            Severity::Low => Self::Low,
            Severity::Medium => Self::Medium,
            Severity::High => Self::High,
            Severity::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Exposure {
    pub provider: String,
    pub live: LiveStatus,
    pub capabilities: Vec<String>,
    pub tier: RiskTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_usd: Option<f64>,
}

impl Exposure {
    /// No verdict: the provider could not be asked. Never reads as "safe"; the caller supplies the tier to fall back on.
    pub fn undecided(provider: &str, reason: impl Into<String>, tier: RiskTier) -> Self {
        Self {
            provider: provider.to_string(),
            live: LiveStatus::Unverified(reason.into()),
            capabilities: Vec::new(),
            tier,
            measured_usd: None,
        }
    }
}

pub trait ExposureProbe {
    fn provider(&self) -> &'static str;

    /// `secret_or_keyid` is the credential itself (Stripe, GitHub) or the access key id (AWS). Read-only calls only.
    fn probe(&self, secret_or_keyid: &str) -> Result<Exposure, SentrisError>;
}

/// The probe for a rule id, wired to the real network; `None` when the provider has no probe.
pub fn probe_for_rule(rule_id: &str) -> Option<Box<dyn ExposureProbe>> {
    match rule_id {
        "stripe-secret-key" | "stripe-restricted-key" => {
            Some(Box::new(stripe::StripeProbe::new(Box::new(http::UreqHttp))))
        }
        "github-pat" | "github-fine-grained-pat" | "github-oauth-access-token" => {
            Some(Box::new(github::GithubProbe::new(Box::new(http::UreqHttp))))
        }
        "aws-access-key-id" => Some(Box::new(aws::AwsProbe::new())),
        _ => None,
    }
}

/// Probes each distinct credential once and stores the verdicts in `report.exposures`, keyed by fingerprint.
///
/// `secret_of` re-reads the secret from source (findings never hold it); `on_probe` runs just before each network call so it can be audited.
/// A probe that cannot reach a verdict falls back to the finding's severity: an unanswered question must not lower the risk.
pub fn probe_report(
    report: &mut ScanReport,
    mut secret_of: impl FnMut(&Finding) -> Option<String>,
    probe_for: impl Fn(&str) -> Option<Box<dyn ExposureProbe>>,
    mut on_probe: impl FnMut(&Finding, &str),
) {
    let mut exposures = std::collections::BTreeMap::new();
    for f in &report.findings {
        if exposures.contains_key(&f.fingerprint) {
            continue;
        }
        let Some(probe) = probe_for(&f.rule_id) else {
            continue;
        };
        let fallback = RiskTier::from(f.severity);
        let Some(mut secret) = secret_of(f) else {
            exposures.insert(
                f.fingerprint.clone(),
                Exposure::undecided(
                    probe.provider(),
                    "secret not readable at the flagged location (history-only finding or file changed)",
                    fallback,
                ),
            );
            continue;
        };
        on_probe(f, probe.provider());
        let result = probe.probe(&secret);
        Remediator::zeroize_secret_string(&mut secret);
        let mut exposure = result
            .unwrap_or_else(|e| Exposure::undecided(probe.provider(), e.to_string(), fallback));
        if matches!(exposure.live, LiveStatus::Unverified(_)) {
            exposure.tier = fallback;
        }
        exposures.insert(f.fingerprint.clone(), exposure);
    }
    report.exposures = exposures;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanStats;
    use std::cell::RefCell;

    struct Canned(Result<Exposure, String>);

    impl ExposureProbe for Canned {
        fn provider(&self) -> &'static str {
            "Test"
        }
        fn probe(&self, _: &str) -> Result<Exposure, SentrisError> {
            self.0.clone().map_err(SentrisError::Scan)
        }
    }

    fn finding(rule: &str, fp: &str, sev: Severity) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            description: "d".to_string(),
            severity: sev,
            file_path: "src/a.rs".to_string(),
            line_number: 1,
            column: 1,
            redacted_match: "x...y".to_string(),
            entropy: 4.0,
            fingerprint: fp.to_string(),
            commit_hash: None,
            commit_author: None,
            commit_date: None,
        }
    }

    pub(crate) fn report_of(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            timestamp: "0".to_string(),
            version: "0".to_string(),
            stats: ScanStats::default(),
            findings,
            exposures: Default::default(),
        }
    }

    fn live(tier: RiskTier) -> Exposure {
        Exposure {
            provider: "Test".to_string(),
            live: LiveStatus::Active { scopes: vec![] },
            capabilities: vec!["x".to_string()],
            tier,
            measured_usd: None,
        }
    }

    fn run(report: &mut ScanReport, outcome: Result<Exposure, String>) -> Vec<String> {
        let noted = RefCell::new(Vec::new());
        probe_report(
            report,
            |_| Some("secret".to_string()),
            |rule| (rule != "no-probe").then(|| Box::new(Canned(outcome.clone())) as _),
            |f, provider| {
                noted
                    .borrow_mut()
                    .push(format!("{provider}:{}", f.fingerprint))
            },
        );
        noted.into_inner()
    }

    #[test]
    fn one_probe_and_one_audit_note_per_distinct_credential() {
        let mut r = report_of(vec![
            finding("stripe-secret-key", "fp1", Severity::Critical),
            finding("stripe-secret-key", "fp1", Severity::Critical),
            finding("github-pat", "fp2", Severity::High),
        ]);
        let noted = run(&mut r, Ok(live(RiskTier::Critical)));
        assert_eq!(noted, ["Test:fp1", "Test:fp2"]);
        assert_eq!(r.exposures.len(), 2);
    }

    #[test]
    fn rules_without_a_probe_get_no_exposure_and_no_call() {
        let mut r = report_of(vec![finding("no-probe", "fp1", Severity::High)]);
        assert!(run(&mut r, Ok(live(RiskTier::Low))).is_empty());
        assert!(r.exposures.is_empty());
    }

    #[test]
    fn unanswered_probe_falls_back_to_severity_never_lower() {
        let mut r = report_of(vec![finding(
            "stripe-secret-key",
            "fp1",
            Severity::Critical,
        )]);
        run(&mut r, Err("network down".to_string()));
        let e = &r.exposures["fp1"];
        assert_eq!(e.tier, RiskTier::Critical);
        assert!(matches!(&e.live, LiveStatus::Unverified(m) if m.contains("network down")));

        let mut r = report_of(vec![finding("stripe-secret-key", "fp1", Severity::High)]);
        let unverified = Exposure::undecided("Test", "429", RiskTier::Low);
        run(&mut r, Ok(unverified));
        assert_eq!(r.exposures["fp1"].tier, RiskTier::High);
    }

    #[test]
    fn a_decided_probe_keeps_its_own_tier_even_below_severity() {
        let mut r = report_of(vec![finding(
            "stripe-secret-key",
            "fp1",
            Severity::Critical,
        )]);
        let mut revoked = live(RiskTier::Low);
        revoked.live = LiveStatus::Revoked;
        run(&mut r, Ok(revoked));
        assert_eq!(r.exposures["fp1"].tier, RiskTier::Low);
    }

    #[test]
    fn unreadable_secret_makes_no_call_and_no_audit_note() {
        let mut r = report_of(vec![finding("stripe-secret-key", "fp1", Severity::High)]);
        let noted = RefCell::new(0);
        probe_report(
            &mut r,
            |_| None,
            |_| Some(Box::new(Canned(Ok(live(RiskTier::Low)))) as _),
            |_, _| *noted.borrow_mut() += 1,
        );
        assert_eq!(noted.into_inner(), 0);
        assert_eq!(r.exposures["fp1"].tier, RiskTier::High);
    }

    #[test]
    fn measured_usd_is_omitted_from_json_unless_present() {
        let json = serde_json::to_value(live(RiskTier::High)).unwrap();
        assert!(json.get("measured_usd").is_none());
        assert_eq!(json["tier"], "high");
    }

    #[test]
    fn probe_sources_use_no_mutating_http_method() {
        for (name, src) in [
            ("stripe", include_str!("stripe.rs")),
            ("github", include_str!("github.rs")),
            ("http", include_str!("http.rs")),
        ] {
            let prod = src.split("#[cfg(test)]").next().unwrap();
            for banned in [
                "::post(",
                "::put(",
                "::patch(",
                "::delete(",
                ".post(",
                ".put(",
                ".patch(",
                ".delete(",
            ] {
                assert!(!prod.contains(banned), "{name} uses {banned}");
            }
        }
    }
}
