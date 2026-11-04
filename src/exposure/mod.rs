//! Read-only exposure probes: what can a leaked credential reach, observed through the provider.
//!
//! A tier is a capability judgement, never a dollar estimate; `measured_usd` is set only when the provider returned a number.
pub mod aws;
pub mod github;
pub mod gitlab;
pub mod http;
pub mod huggingface;
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
        "huggingface-token" => Some(Box::new(huggingface::HuggingFaceProbe::new(Box::new(
            http::UreqHttp,
        )))),
        "gitlab-pat" => Some(Box::new(gitlab::GitlabProbe::new(Box::new(http::UreqHttp)))),
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
        if let Some(canary_reason) = crate::verifier::detect_canary_token(&secret, None) {
            Remediator::zeroize_secret_string(&mut secret);
            exposures.insert(
                f.fingerprint.clone(),
                Exposure::undecided(
                    probe.provider(),
                    format!("canary tripwire bypassed — {canary_reason}"),
                    fallback,
                ),
            );
            continue;
        }
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

/// Evaluates an active `Exposure` for OWASP NHI5 (Overprivileged Non-Human Identity) risks
/// and returns a concrete least-privilege remediation recommendation when broad or administrative scopes are observed.
pub fn advise_least_privilege(rule_id: &str, exposure: &Exposure) -> Option<String> {
    let LiveStatus::Active { scopes } = &exposure.live else {
        return None;
    };
    match rule_id {
        "stripe-secret-key" => Some(
            "OWASP NHI5 advisory: unrestricted sk_live_ key grants full account access; downgrade to a Stripe restricted key (rk_live_) scoped only to required resources".to_string(),
        ),
        "github-pat" | "github-oauth-access-token" => {
            let dangerous: Vec<&str> = scopes
                .iter()
                .map(String::as_str)
                .filter(|s| {
                    matches!(
                        *s,
                        "admin:org"
                            | "delete_repo"
                            | "admin:public_key"
                            | "admin:repo_hook"
                            | "admin:org_hook"
                            | "admin:gpg_key"
                            | "site_admin"
                            | "repo"
                            | "workflow"
                    )
                })
                .collect();
            if dangerous.is_empty() {
                None
            } else {
                Some(format!(
                    "OWASP NHI5 advisory: classic token carries broad scopes ({}); migrate to a repository-scoped fine-grained PAT (github_pat_) or short-lived GitHub App token",
                    dangerous.join(", ")
                ))
            }
        }
        "gitlab-pat" => {
            let dangerous: Vec<&str> = scopes
                .iter()
                .map(String::as_str)
                .filter(|s| matches!(*s, "api" | "sudo" | "admin_mode" | "write_repository"))
                .collect();
            if dangerous.is_empty() {
                None
            } else {
                Some(format!(
                    "OWASP NHI5 advisory: token carries broad GitLab scopes ({}); restrict to read_api/read_repository or use a project-scoped access token",
                    dangerous.join(", ")
                ))
            }
        }
        "aws-access-key-id" => {
            let is_admin = exposure.capabilities.iter().any(|c| {
                c.contains("AdministratorAccess")
                    || c.contains("PowerUserAccess")
                    || c.contains("IAMFullAccess")
            });
            if is_admin {
                Some(
                    "OWASP NHI5 advisory: long-lived IAM key carries administrative policy; migrate to secretless OIDC federation (sts:AssumeRoleWithWebIdentity) with least-privilege IAM permissions".to_string(),
                )
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The tier a finding is ranked and gated at: the probe's verdict when there is one, else its severity.
fn tier_of(exposures: &std::collections::BTreeMap<String, Exposure>, f: &Finding) -> RiskTier {
    exposures
        .get(&f.fingerprint)
        .map_or_else(|| f.severity.into(), |e| e.tier)
}

/// Highest tier first, then rule, path and position so the order is stable. Does nothing unless probes ran: without `--probe` the output order must stay what it was.
pub fn rank_findings(report: &mut ScanReport) {
    if report.exposures.is_empty() || report.findings.len() <= 1 {
        return;
    }
    let ScanReport {
        findings,
        exposures,
        ..
    } = report;
    let tiers: Vec<RiskTier> = findings.iter().map(|f| tier_of(exposures, f)).collect();
    let mut order: Vec<usize> = (0..findings.len()).collect();
    order.sort_by(|&a, &b| {
        tiers[b]
            .cmp(&tiers[a])
            .then_with(|| findings[a].rule_id.cmp(&findings[b].rule_id))
            .then_with(|| findings[a].file_path.cmp(&findings[b].file_path))
            .then_with(|| findings[a].line_number.cmp(&findings[b].line_number))
            .then_with(|| findings[a].column.cmp(&findings[b].column))
    });
    let mut sorted = Vec::with_capacity(findings.len());
    let mut slots: Vec<Option<Finding>> = findings.drain(..).map(Some).collect();
    for idx in order {
        if let Some(f) = slots[idx].take() {
            sorted.push(f);
        }
    }
    *findings = sorted;
}

/// True when any finding sits at or above `threshold` (see `tier_of`).
pub fn at_or_above(report: &ScanReport, threshold: RiskTier) -> bool {
    report
        .findings
        .iter()
        .any(|f| tier_of(&report.exposures, f) >= threshold)
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

    fn probed(tier: RiskTier) -> Exposure {
        live(tier)
    }

    fn at(mut f: Finding, path: &str, line: usize) -> Finding {
        f.file_path = path.to_string();
        f.line_number = line;
        f
    }

    #[test]
    fn ranking_orders_by_tier_then_rule_then_location_using_severity_when_unprobed() {
        let mut r = report_of(vec![
            finding("zeta-rule", "u_high", Severity::High),
            at(
                finding("stripe-secret-key", "p_low", Severity::Critical),
                "a.rs",
                1,
            ),
            finding("github-pat", "p_crit", Severity::High),
            at(
                finding("aws-secret-access-key", "u_crit", Severity::Critical),
                "b.rs",
                9,
            ),
            at(
                finding("aws-secret-access-key", "u_crit2", Severity::Critical),
                "b.rs",
                2,
            ),
            finding("alpha-rule", "u_high2", Severity::High),
        ]);
        r.exposures
            .insert("p_low".to_string(), probed(RiskTier::Low));
        r.exposures
            .insert("p_crit".to_string(), probed(RiskTier::Critical));
        rank_findings(&mut r);
        let order: Vec<&str> = r.findings.iter().map(|f| f.fingerprint.as_str()).collect();
        assert_eq!(
            order,
            ["u_crit2", "u_crit", "p_crit", "u_high2", "u_high", "p_low"]
        );
    }

    #[test]
    fn ranking_is_a_no_op_when_nothing_was_probed() {
        let mut r = report_of(vec![
            finding("z-rule", "a", Severity::Low),
            finding("a-rule", "b", Severity::Critical),
        ]);
        rank_findings(&mut r);
        assert_eq!(r.findings[0].fingerprint, "a");
    }

    #[test]
    fn gate_uses_probe_tier_when_present_and_severity_otherwise() {
        let mut r = report_of(vec![
            finding("stripe-secret-key", "p", Severity::Critical),
            finding("other", "u", Severity::Medium),
        ]);
        r.exposures.insert("p".to_string(), probed(RiskTier::Low));
        assert!(!at_or_above(&r, RiskTier::High));
        assert!(at_or_above(&r, RiskTier::Medium));
        assert!(at_or_above(&r, RiskTier::Low));
        r.exposures
            .insert("p".to_string(), probed(RiskTier::Critical));
        assert!(at_or_above(&r, RiskTier::Critical));
        assert!(!at_or_above(&report_of(vec![]), RiskTier::Low));
    }

    #[test]
    fn probe_sources_use_no_mutating_http_method() {
        for (name, src) in [
            ("stripe", include_str!("stripe.rs")),
            ("github", include_str!("github.rs")),
            ("huggingface", include_str!("huggingface.rs")),
            ("gitlab", include_str!("gitlab.rs")),
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

    #[test]
    fn canary_token_bypasses_network_probe_and_audit() {
        let mut r = report_of(vec![finding("github-pat", "fp_canary", Severity::High)]);
        let noted = RefCell::new(0);
        probe_report(
            &mut r,
            |_| Some("ghp_canarytokens_org_tripwire_1234567890".to_string()),
            |_| Some(Box::new(Canned(Ok(live(RiskTier::Low)))) as _),
            |_, _| *noted.borrow_mut() += 1,
        );
        assert_eq!(noted.into_inner(), 0);
        let e = &r.exposures["fp_canary"];
        assert_eq!(e.tier, RiskTier::High);
        assert!(matches!(&e.live, LiveStatus::Unverified(m) if m.contains("canary tripwire")));
    }

    #[test]
    fn advise_least_privilege_flags_owasp_nhi5_overprivilege() {
        let stripe_exp = live(RiskTier::Critical);
        let adv = advise_least_privilege("stripe-secret-key", &stripe_exp).unwrap();
        assert!(adv.contains("OWASP NHI5") && adv.contains("rk_live_"));

        let mut gh_exp = live(RiskTier::Critical);
        gh_exp.live = LiveStatus::Active {
            scopes: vec!["repo".to_string(), "admin:org".to_string()],
        };
        let gh_adv = advise_least_privilege("github-pat", &gh_exp).unwrap();
        assert!(gh_adv.contains("admin:org") && gh_adv.contains("github_pat_"));

        let mut aws_exp = live(RiskTier::Critical);
        aws_exp.capabilities =
            vec!["attached policy AdministratorAccess (AWS managed)".to_string()];
        let aws_adv = advise_least_privilege("aws-access-key-id", &aws_exp).unwrap();
        assert!(aws_adv.contains("sts:AssumeRoleWithWebIdentity"));
    }
}
