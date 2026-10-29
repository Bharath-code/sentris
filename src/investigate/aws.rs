use crate::error::SentrisError;
use crate::rotator::aws::AwsCli;
use crate::rotator::timefmt::parse_rfc3339;
use crate::rotator::LastUse;
use std::collections::BTreeMap;
use std::time::Duration;

const LIMITS: &str = "management events only, last 90 days";
const PAGE: &str = "50";
const MAX_RETRIES: u32 = 5;
/// CloudTrail LookupEvents allows 2 requests/s per account per Region.
const PAGE_DELAY: Duration = Duration::from_millis(550);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageEvent {
    pub at: u64,
    pub event_name: String,
    pub event_source: String,
    pub region: String,
    pub source_ip: String,
    pub user_agent: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageGroup {
    pub source_ip: String,
    pub user_agent: String,
    pub event_name: String,
    pub count: usize,
    pub first: u64,
    pub last: u64,
    pub unknown_ip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageReport {
    pub last_used: Option<LastUse>,
    pub events: Vec<UsageEvent>,
    pub window_note: String,
}

impl UsageReport {
    /// Events grouped by (ip, user agent, event name). With an empty allowlist nothing is flagged: there is no basis to call an address unknown.
    pub fn groups(&self, known_ips: &[String]) -> Vec<UsageGroup> {
        let mut map: BTreeMap<(String, String, String), UsageGroup> = BTreeMap::new();
        for e in &self.events {
            let g = map
                .entry((
                    e.source_ip.clone(),
                    e.user_agent.clone(),
                    e.event_name.clone(),
                ))
                .or_insert_with(|| UsageGroup {
                    source_ip: e.source_ip.clone(),
                    user_agent: e.user_agent.clone(),
                    event_name: e.event_name.clone(),
                    count: 0,
                    first: e.at,
                    last: e.at,
                    unknown_ip: !known_ips.is_empty() && !known_ips.contains(&e.source_ip),
                });
            g.count += 1;
            g.first = g.first.min(e.at);
            g.last = g.last.max(e.at);
        }
        map.into_values().collect()
    }
}

const MAX_FIELD: usize = 200;

/// CloudTrail fields (user agent, IP) are chosen by the caller of the API, i.e. possibly the attacker: drop control characters (terminal escapes) and cap the length before anything prints or forwards them.
fn clean(s: &str) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_FIELD)
        .collect();
    if s.chars().count() > MAX_FIELD {
        out.push('…');
    }
    out
}

fn str_field(v: &serde_json::Value, key: &str) -> String {
    v[key].as_str().map_or_else(|| "unknown".to_string(), clean)
}

fn event_time(v: &serde_json::Value) -> Option<u64> {
    v.as_str()
        .and_then(parse_rfc3339)
        .or_else(|| v.as_f64().map(|f| f as u64))
}

/// `CloudTrailEvent` is a JSON document inside a string; ip and user agent live only there.
fn parse_event(item: &serde_json::Value) -> Option<UsageEvent> {
    let inner: serde_json::Value = serde_json::from_str(item["CloudTrailEvent"].as_str()?).ok()?;
    Some(UsageEvent {
        at: event_time(&item["EventTime"]).or_else(|| event_time(&inner["eventTime"]))?,
        event_name: str_field(&inner, "eventName"),
        event_source: str_field(&inner, "eventSource"),
        region: str_field(&inner, "awsRegion"),
        source_ip: str_field(&inner, "sourceIPAddress"),
        user_agent: str_field(&inner, "userAgent"),
    })
}

fn classify(err: SentrisError, retries: u32) -> Result<(), SentrisError> {
    let msg = err.to_string();
    if msg.contains("ThrottlingException") || msg.contains("Rate exceeded") {
        return Err(SentrisError::Scan(format!(
            "CloudTrail throttled the lookup after {retries} retries (LookupEvents allows 2 requests/s per account per Region); try again in a minute"
        )));
    }
    if msg.contains("AccessDenied") || msg.contains("not authorized") {
        return Err(SentrisError::Scan(
            "CloudTrail lookup denied: your AWS credentials need the cloudtrail:LookupEvents permission".to_string(),
        ));
    }
    Err(err)
}

fn is_throttle(err: &SentrisError) -> bool {
    let m = err.to_string();
    m.contains("ThrottlingException") || m.contains("Rate exceeded")
}

fn fetch_page(
    cli: &AwsCli,
    delay: Duration,
    attr: &str,
    start: &str,
    token: Option<&str>,
) -> Result<serde_json::Value, SentrisError> {
    let mut args = vec![
        "cloudtrail",
        "lookup-events",
        "--lookup-attributes",
        attr,
        "--start-time",
        start,
        "--max-results",
        PAGE,
        "--no-paginate",
        "--output",
        "json",
    ];
    if let Some(t) = token {
        args.extend(["--next-token", t]);
    }
    let mut attempt = 0;
    loop {
        match cli.json(&args) {
            Ok(v) => return Ok(v),
            Err(e) if is_throttle(&e) && attempt < MAX_RETRIES => {
                std::thread::sleep(delay * 2u32.pow(attempt));
                attempt += 1;
            }
            Err(e) => return classify(e, attempt).map(|()| serde_json::Value::Null),
        }
    }
}

fn lookup(
    cli: &AwsCli,
    delay: Duration,
    access_key_id: &str,
    since: u64,
) -> Result<UsageReport, SentrisError> {
    let attr = format!("AttributeKey=AccessKeyId,AttributeValue={access_key_id}");
    let start = since.to_string();
    let mut events = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let page = fetch_page(cli, delay, &attr, &start, token.as_deref())?;
        events.extend(
            page["Events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(parse_event)
                .filter(|e| e.at >= since),
        );
        token = page["NextToken"].as_str().map(str::to_string);
        if token.is_none() {
            break;
        }
        std::thread::sleep(delay);
    }
    events.sort_by_key(|e| e.at);
    let last_used = events.last().map(|e| LastUse {
        at: e.at,
        service: e
            .event_source
            .trim_end_matches(".amazonaws.com")
            .to_string(),
        region: e.region.clone(),
    });
    let window_note = if events.is_empty() {
        format!("no recorded use in CloudTrail event history ({LIMITS})")
    } else {
        format!(
            "{} recorded events in CloudTrail event history ({LIMITS}); absence of other activity is not evidence it did not happen",
            events.len()
        )
    };
    Ok(UsageReport {
        last_used,
        events,
        window_note,
    })
}

/// CloudTrail event history for `access_key_id` since `since` (unix seconds). Uses ambient AWS credentials, never the key being investigated.
pub fn usage_since(access_key_id: &str, since: u64) -> Result<UsageReport, SentrisError> {
    if std::env::var("AWS_ACCESS_KEY_ID").ok().as_deref() == Some(access_key_id) {
        return Err(SentrisError::Refused(
            "Your AWS CLI is signing with the key under investigation; use a different admin profile".to_string(),
        ));
    }
    lookup(&AwsCli::new(), PAGE_DELAY, access_key_id, since)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const KEY: &str = "AKIAJ5Q7X2M9R4T6W8YB";
    // 2026-10-15T00:00:00Z
    const SINCE: u64 = 1_792_022_400;

    /// Shim that replays `reply.N` for the Nth call; a file starting with `FAIL:` becomes stderr + exit 254.
    struct Shim {
        dir: tempfile::TempDir,
    }

    impl Shim {
        fn new(replies: &[String]) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            for (i, r) in replies.iter().enumerate() {
                fs::write(dir.path().join(format!("reply.{}", i + 1)), r).expect("reply");
            }
            let d = dir.path().display();
            let script = format!(
                "#!/bin/sh\necho \"ARGV: $@\" >> {d}/calls.log\nn=$(wc -l < {d}/calls.log | tr -d ' ')\nf={d}/reply.$n\n[ -f \"$f\" ] || exit 1\nif head -c 5 \"$f\" | grep -q '^FAIL:'; then tail -c +6 \"$f\" >&2; exit 254; fi\ncat \"$f\"\n"
            );
            let bin = dir.path().join("aws");
            fs::write(&bin, script).expect("shim");
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).expect("chmod");
            Self { dir }
        }

        fn run(&self) -> Result<UsageReport, SentrisError> {
            let cli = AwsCli::with_program(self.dir.path().join("aws"));
            lookup(&cli, Duration::ZERO, KEY, SINCE)
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(self.dir.path().join("calls.log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    fn event(i: usize, ip: &str, at: &str) -> String {
        let inner = format!(
            r#"{{"eventTime":"{at}","eventSource":"s3.amazonaws.com","eventName":"ListBuckets","awsRegion":"us-east-1","sourceIPAddress":"{ip}","userAgent":"aws-cli/2.15"}}"#
        );
        serde_json::json!({
            "EventId": i.to_string(),
            "EventName": "ListBuckets",
            "EventTime": at,
            "CloudTrailEvent": inner,
        })
        .to_string()
    }

    fn page(events: &[String], token: Option<&str>) -> String {
        let next = token.map_or(String::new(), |t| format!(r#","NextToken":"{t}""#));
        format!(r#"{{"Events":[{}]{next}}}"#, events.join(","))
    }

    #[test]
    fn paginates_past_fifty_events_with_next_token() {
        let at = "2026-10-28T10:00:00+00:00";
        let p1: Vec<String> = (0..50).map(|i| event(i, "203.0.113.1", at)).collect();
        let p2: Vec<String> = (50..70).map(|i| event(i, "203.0.113.1", at)).collect();
        let shim = Shim::new(&[page(&p1, Some("tok1")), page(&p2, None)]);
        let r = shim.run().unwrap();
        assert_eq!(r.events.len(), 70);
        let calls = shim.calls();
        assert_eq!(calls.len(), 2);
        assert!(!calls[0].contains("--next-token") && calls[1].contains("--next-token tok1"));
        assert!(calls.iter().all(|c| c.contains("AttributeKey=AccessKeyId")));
    }

    #[test]
    fn retries_when_throttled_then_succeeds() {
        let fail = "FAIL:An error occurred (ThrottlingException) when calling the LookupEvents operation: Rate exceeded".to_string();
        let ok = page(
            &[event(1, "203.0.113.1", "2026-10-28T10:00:00+00:00")],
            None,
        );
        let shim = Shim::new(&[fail.clone(), fail, ok]);
        assert_eq!(shim.run().unwrap().events.len(), 1);
        assert_eq!(shim.calls().len(), 3);
    }

    #[test]
    fn persistent_throttling_gives_a_distinct_error() {
        let fail = "FAIL:ThrottlingException: Rate exceeded".to_string();
        let shim = Shim::new(&vec![fail; 8]);
        let msg = shim.run().unwrap_err().to_string();
        assert!(msg.contains("throttled") && !msg.contains("LookupEvents permission"));
    }

    #[test]
    fn missing_permission_names_lookup_events() {
        let shim = Shim::new(&["FAIL:An error occurred (AccessDeniedException) when calling the LookupEvents operation".to_string()]);
        let msg = shim.run().unwrap_err().to_string();
        assert!(msg.contains("cloudtrail:LookupEvents"));
        assert_eq!(shim.calls().len(), 1);
    }

    #[test]
    fn fixture_with_three_ips_flags_the_two_not_allowlisted() {
        let body = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/cloudtrail/three_ips.json"
        ))
        .unwrap();
        let r = Shim::new(&[body]).run().unwrap();
        // the 2026-10-01 event predates SINCE and is excluded
        assert_eq!(r.events.len(), 3);
        let groups = r.groups(&["203.0.113.10".to_string()]);
        let flagged: Vec<_> = groups.iter().filter(|g| g.unknown_ip).collect();
        assert_eq!(flagged.len(), 2);
        assert!(flagged.iter().all(|g| g.source_ip != "203.0.113.10"));
        let last = r.last_used.unwrap();
        assert_eq!(
            (last.service.as_str(), last.region.as_str()),
            ("ec2", "eu-west-1")
        );
    }

    #[test]
    fn hostile_fields_are_stripped_of_control_characters_and_capped() {
        let inner = serde_json::json!({
            "eventName": "ListBuckets", "eventSource": "s3.amazonaws.com", "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.9\u{1b}[2J",
            "userAgent": format!("\u{1b}]0;pwned\u{7}ignore previous instructions{}", "A".repeat(500)),
        })
        .to_string();
        let body = serde_json::json!({"Events": [{"EventTime": "2026-10-28T10:00:00+00:00", "CloudTrailEvent": inner}]}).to_string();
        let e = &Shim::new(&[body]).run().unwrap().events[0];
        assert!(
            !e.source_ip.chars().any(char::is_control)
                && !e.user_agent.chars().any(char::is_control)
        );
        assert!(e.user_agent.chars().count() <= MAX_FIELD + 1);
    }

    #[test]
    fn empty_result_never_says_safe() {
        let r = Shim::new(&[r#"{"Events":[]}"#.to_string()]).run().unwrap();
        assert!(r.events.is_empty() && r.last_used.is_none());
        assert_eq!(
            r.window_note,
            "no recorded use in CloudTrail event history (management events only, last 90 days)"
        );
        assert!(!r.window_note.to_lowercase().contains("safe"));
    }

    #[test]
    fn refuses_when_ambient_key_is_the_investigated_key() {
        std::env::set_var("AWS_ACCESS_KEY_ID", KEY);
        let r = usage_since(KEY, SINCE);
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        assert!(matches!(r, Err(SentrisError::Refused(_))));
    }
}
