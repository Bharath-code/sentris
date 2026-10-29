pub mod aws;
pub mod window;

use crate::error::SentrisError;
use crate::model::{short, Finding, ScanReport};
use crate::rotator::timefmt::format_utc;
use aws::{UsageGroup, UsageReport};
use serde_json::{json, Value};
use std::path::Path;
use window::Exposure;

const AWS_RULE: &str = "aws-access-key-id";
/// CloudTrail event history reaches back 90 days; used when git gives no start.
const LOOKBACK_SECS: u64 = 90 * 86_400;

#[derive(Debug)]
pub struct Investigation {
    pub finding_id: String,
    pub rule_id: String,
    pub file_path: String,
    pub line_number: usize,
    pub supported: bool,
    pub exposure: Option<Exposure>,
    pub since: Option<u64>,
    pub usage: Option<UsageReport>,
    pub known_ips: Vec<String>,
}

/// The finding named by `id` (fingerprint prefix, rule id or path); the first finding when `id` is `None`.
pub fn select_finding<'a>(report: &'a ScanReport, id: Option<&str>) -> Option<&'a Finding> {
    match id {
        None => report.findings.first(),
        Some(id) => report.findings.iter().find(|f| {
            f.fingerprint.starts_with(id)
                || f.rule_id == id
                || f.file_path == id
                || f.file_path.ends_with(id)
        }),
    }
}

/// Read-only forensics for one finding. `usage` looks up provider logs for the secret since a unix time.
pub fn investigate<F>(
    finding: &Finding,
    secret: &str,
    repo: &Path,
    known_ips: &[String],
    now: u64,
    usage: F,
) -> Result<Investigation, SentrisError>
where
    F: FnOnce(&str, u64) -> Result<UsageReport, SentrisError>,
{
    let mut inv = Investigation {
        finding_id: short(&finding.fingerprint, 12).to_string(),
        rule_id: finding.rule_id.clone(),
        file_path: finding.file_path.clone(),
        line_number: finding.line_number,
        supported: finding.rule_id == AWS_RULE,
        exposure: None,
        since: None,
        usage: None,
        known_ips: known_ips.to_vec(),
    };
    if !inv.supported {
        return Ok(inv);
    }
    let exposure = window::first_exposure(repo, &finding.fingerprint)?;
    let since = exposure
        .start
        .as_ref()
        .map_or(now.saturating_sub(LOOKBACK_SECS), |s| s.author_time);
    inv.usage = Some(usage(secret, since)?);
    inv.exposure = Some(exposure);
    inv.since = Some(since);
    Ok(inv)
}

/// Scans `target`, picks the finding named by `finding_id` and investigates it. `None` when nothing matches.
pub fn investigate_target(
    scanner: &crate::scanner::Scanner,
    target: &Path,
    finding_id: Option<&str>,
    known_ips: &[String],
    repo: &Path,
) -> Result<Option<Investigation>, SentrisError> {
    let report = scanner.scan_path(target)?;
    let Some(finding) = select_finding(&report, finding_id) else {
        return Ok(None);
    };
    if finding.rule_id != AWS_RULE {
        return investigate(finding, "", repo, known_ips, 0, |_, _| {
            Err(SentrisError::Scan("unsupported provider".to_string()))
        })
        .map(Some);
    }
    let content = std::fs::read_to_string(&finding.file_path)?;
    let mut secret = scanner.resolve_finding_secret(&content, finding)?;
    let now = crate::rotator::unix_now();
    let result = investigate(finding, &secret, repo, known_ips, now, aws::usage_since);
    crate::remediator::Remediator::zeroize_secret_string(&mut secret);
    result.map(Some)
}

fn group_json(g: &UsageGroup) -> Value {
    json!({
        "source_ip": g.source_ip,
        "user_agent": g.user_agent,
        "event_name": g.event_name,
        "count": g.count,
        "first": g.first,
        "last": g.last,
        "unknown_ip": g.unknown_ip,
    })
}

impl Investigation {
    pub fn unsupported_message(&self) -> String {
        format!("no forensics for {} yet", self.rule_id)
    }

    pub fn to_json(&self) -> Value {
        let mut out = json!({
            "ok": true,
            "command": "investigate",
            "finding": {
                "id": self.finding_id,
                "rule_id": self.rule_id,
                "file_path": self.file_path,
                "line_number": self.line_number,
            },
            "supported": self.supported,
        });
        let (Some(exposure), Some(usage)) = (&self.exposure, &self.usage) else {
            out["message"] = json!(self.unsupported_message());
            return out;
        };
        out["provider"] = json!("AWS");
        out["exposure"] = json!({
            "commit": exposure.start.as_ref().map(|s| &s.commit),
            "author_time": exposure.start.as_ref().map(|s| s.author_time),
            "note": exposure.note,
        });
        let groups: Vec<Value> = usage
            .groups(&self.known_ips)
            .iter()
            .map(group_json)
            .collect();
        out["usage"] = json!({
            "since": self.since,
            "event_count": usage.events.len(),
            "last_used": usage.last_used.as_ref().map(|l| json!({"at": l.at, "service": l.service, "region": l.region})),
            "window_note": usage.window_note,
            "groups": groups,
        });
        out
    }

    pub fn to_text(&self) -> String {
        let mut s = format!(
            "Investigation of finding {} ({} in {}:{})\n",
            self.finding_id, self.rule_id, self.file_path, self.line_number
        );
        let (Some(exposure), Some(usage)) = (&self.exposure, &self.usage) else {
            s.push_str(&format!("{}\n", self.unsupported_message()));
            return s;
        };
        match &exposure.start {
            Some(st) => s.push_str(&format!(
                "First exposure: commit {} at {} ({})\n",
                short(&st.commit, 12),
                format_utc(st.author_time),
                exposure.note
            )),
            None => s.push_str(&format!("First exposure: unknown ({})\n", exposure.note)),
        }
        s.push_str(&format!(
            "Provider log window: since {}\n",
            self.since.map_or("unknown".to_string(), format_utc)
        ));
        s.push_str(&format!("{}\n", usage.window_note));
        if let Some(l) = &usage.last_used {
            s.push_str(&format!(
                "Last use: {} {} {}\n",
                format_utc(l.at),
                l.service,
                l.region
            ));
        }
        for g in usage.groups(&self.known_ips) {
            let flag = if g.unknown_ip { "  UNKNOWN IP" } else { "" };
            s.push_str(&format!(
                "  {} x{}  {}  {}  {}..{}{flag}\n",
                g.source_ip,
                g.count,
                g.event_name,
                g.user_agent,
                format_utc(g.first),
                format_utc(g.last)
            ));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::aws::UsageEvent;
    use super::*;
    use crate::model::Severity;
    use std::fs;

    const KEY: &str = "AKIAJ5Q7X2M9R4T6W8YB";

    fn finding(rule: &str) -> Finding {
        Finding {
            rule_id: rule.into(),
            description: "d".into(),
            severity: Severity::Critical,
            file_path: "src/app.py".into(),
            line_number: 7,
            column: 1,
            redacted_match: "AKIA...".into(),
            entropy: 4.0,
            fingerprint: "a1b2c3d4e5f60718293a4b5c6d7e8f90".into(),
            commit_hash: None,
            commit_author: None,
            commit_date: None,
        }
    }

    fn ev(at: u64, ip: &str, name: &str) -> UsageEvent {
        UsageEvent {
            at,
            event_name: name.into(),
            event_source: "s3.amazonaws.com".into(),
            region: "us-east-1".into(),
            source_ip: ip.into(),
            user_agent: "aws-cli/2.15".into(),
        }
    }

    fn fixed() -> Investigation {
        let usage = UsageReport {
            last_used: Some(crate::rotator::LastUse {
                at: 1_793_181_600,
                service: "s3".into(),
                region: "us-east-1".into(),
            }),
            events: vec![
                ev(1_793_170_000, "203.0.113.10", "ListBuckets"),
                ev(1_793_181_600, "198.51.100.7", "DescribeInstances"),
            ],
            window_note: "2 recorded events in CloudTrail event history (management events only, last 90 days); absence of other activity is not evidence it did not happen".into(),
        };
        Investigation {
            finding_id: "a1b2c3d4e5f6".into(),
            rule_id: AWS_RULE.into(),
            file_path: "src/app.py".into(),
            line_number: 7,
            supported: true,
            exposure: Some(Exposure {
                start: Some(window::ExposureStart {
                    commit: "0123456789abcdef0123456789abcdef01234567".into(),
                    author_time: 1_790_000_000,
                }),
                note: window::TIME_NOTE.into(),
            }),
            since: Some(1_790_000_000),
            usage: Some(usage),
            known_ips: vec!["203.0.113.10".into()],
        }
    }

    fn golden(name: &str, actual: &str) {
        let path = format!(
            "{}/tests/fixtures/investigate/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            fs::create_dir_all(format!(
                "{}/tests/fixtures/investigate",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            fs::write(&path, actual).unwrap();
        }
        assert_eq!(fs::read_to_string(&path).unwrap(), actual, "golden {name}");
    }

    #[test]
    fn json_output_matches_golden() {
        let pretty = serde_json::to_string_pretty(&fixed().to_json()).unwrap() + "\n";
        golden("report.json", &pretty);
    }

    #[test]
    fn text_output_matches_golden() {
        golden("report.txt", &fixed().to_text());
    }

    #[test]
    fn output_never_contains_the_key_or_says_safe() {
        let both = format!("{}{}", fixed().to_text(), fixed().to_json());
        assert!(!both.contains(KEY) && !both.to_lowercase().contains("safe"));
    }

    #[test]
    fn unsupported_provider_is_ok_with_a_plain_message() {
        let f = finding("stripe-secret-key");
        let inv = investigate(&f, "x", Path::new("."), &[], 0, |_, _| {
            panic!("must not query a provider")
        })
        .unwrap();
        assert!(!inv.supported);
        assert!(inv
            .to_text()
            .contains("no forensics for stripe-secret-key yet"));
        assert_eq!(inv.to_json()["ok"], true);
        assert_eq!(inv.to_json()["supported"], false);
    }

    #[test]
    fn aws_uses_exposure_start_as_the_window() {
        let d = tempfile::tempdir().unwrap();
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(d.path())
            .args(["init", "-q"])
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let f = finding(AWS_RULE);
        let seen = std::cell::Cell::new(0u64);
        let inv = investigate(&f, KEY, d.path(), &[], 2_000_000_000, |_, since| {
            seen.set(since);
            Ok(UsageReport {
                last_used: None,
                events: vec![],
                window_note: "n".into(),
            })
        })
        .unwrap();
        // no commits: falls back to the 90-day CloudTrail horizon
        assert_eq!(seen.get(), 2_000_000_000 - 90 * 86_400);
        assert_eq!(inv.since, Some(seen.get()));
    }
}
