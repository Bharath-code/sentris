//! Labeled detection corpus: synthetic positives (generated per rule from templates, nothing secret is committed)
//! and hard negatives (tests/corpus/negatives.txt). Prints a per-rule precision/recall table.
//!
//! Gates: every rule that fires must keep precision >= 0.9; overall recall may not drop more than 2 points
//! below tests/corpus/baseline_recall.txt. Set CORPUS_DUMP=<dir> to write the positives for other scanners.

use sentris::detector::DetectorEngine;
use std::collections::BTreeMap;

const VARIANTS: usize = 4;
const MIN_PRECISION: f64 = 0.9;
const MAX_RECALL_DROP: f64 = 0.02;

/// (rule_id, template, wrap). Placeholders: {kind:len}; wrap=true embeds the token in several code contexts.
/// kinds: a alnum, h lower-hex, d digits, u upper+digits, l lower+digits, s alnum+_-, b base64, B base32 (A-Z2-7),
/// x alnum+_~., K bech32, U uuid.
#[rustfmt::skip]
const CASES: &[(&str, &str, bool)] = &[
    ("aws-access-key-id", "AKIA{B:16}", true),
    ("aws-access-key-id", "ASIA{B:16}", true),
    ("aws-secret-access-key", "aws_secret_access_key = \"{b:40}\"", false),
    ("aws-secret-access-key", "AWS_SECRET_ACCESS_KEY={b:40}", false),
    ("google-api-key", "AIza{s:35}", true),
    ("azure-storage-account-key", "DefaultEndpointsProtocol=https;AccountName=acct{l:6};AccountKey={b:86}==", false),
    ("digitalocean-access-token", "dop_v1_{h:64}", true),
    ("stripe-secret-key", "sk_live_{a:30}", true),
    ("stripe-restricted-key", "rk_live_{a:30}", true),
    ("stripe-webhook-secret", "whsec_{a:36}", true),
    ("paypal-braintree-token", "access_token$production${l:16}${h:32}", true),
    ("square-access-token", "sq0atp-{s:22}", true),
    ("github-pat", "ghp_{a:36}", true),
    ("github-fine-grained-pat", "github_pat_{a:82}", true),
    ("github-oauth-access-token", "gho_{a:36}", true),
    ("github-refresh-token", "ghr_{a:76}", true),
    ("gitlab-pat", "glpat-{s:20}", true),
    ("npm-access-token", "npm_{a:36}", true),
    ("pypi-upload-token", "pypi-AgEIcHlwaS5vcmc{s:60}", true),
    ("openai-api-key", "sk-proj-{s:48}", true),
    ("anthropic-api-key", "sk-ant-api03-{s:90}", true),
    ("anthropic-api-key", "sk-ant-admin01-{s:90}", true),
    ("huggingface-token", "hf_{a:34}", true),
    ("cohere-api-key", "COHERE_API_KEY=\"{a:40}\"", false),
    ("groq-api-key", "gsk_{a:52}", true),
    ("replicate-api-token", "r8_{a:37}", true),
    ("perplexity-api-key", "pplx-{h:48}", true),
    ("slack-bot-token", "xoxb-{d:12}-{d:12}-{a:24}", true),
    ("slack-user-token", "xoxp-{d:12}-{d:12}-{a:28}", true),
    ("slack-webhook-url", "https://hooks.slack.com/services/T{u:8}/B{u:10}/{a:24}", true),
    ("discord-bot-token", "M{a:24}.{s:6}.{s:30}", true),
    ("discord-webhook-url", "https://discord.com/api/webhooks/{d:18}/{s:68}", true),
    ("telegram-bot-token", "{d:10}:A{s:34}", true),
    ("twilio-api-key", "SK{h:32}", true),
    ("sendgrid-api-key", "SG.{s:22}.{s:43}", true),
    ("mailchimp-api-key", "{h:32}-us{d:1}", true),
    ("postgres-connection-uri", "postgres://app{l:3}:{a:16}@db{l:4}.internal.net:5432/app{l:3}", false),
    ("mysql-connection-uri", "mysql://app{l:3}:{a:16}@db{l:4}.internal.net:3306/app{l:3}", false),
    ("mongodb-connection-uri", "mongodb+srv://app{l:3}:{a:16}@cluster{l:3}.mongodb.net/app", false),
    ("redis-connection-uri", "redis://:{a:18}@cache{l:3}.internal.net:6379", false),
    ("rsa-private-key", "-----BEGIN RSA PRIVATE KEY-----", false),
    ("openssh-private-key", "-----BEGIN OPENSSH PRIVATE KEY-----", false),
    ("pgp-private-key", "-----BEGIN PGP PRIVATE KEY BLOCK-----", false),
    ("ec-private-key", "-----BEGIN EC PRIVATE KEY-----", false),
    ("generic-private-key", "-----BEGIN PRIVATE KEY-----", false),
    ("jwt-token", "eyJ{s:30}.eyJ{s:40}.{s:43}", true),
    ("generic-api-key", "const secret_key = \"{s:48}\"", false),
    ("generic-api-key", "apiKey: '{a:36}'", false),
    ("structural-secret-assignment", "JWT_SECRET=\"{a:44}\"", false),
    ("structural-secret-assignment", "signing_key: '{b:40}'", false),
    ("datadog-api-key", "DD_API_KEY=\"{h:32}\"", false),
    ("sentry-dsn", "https://{h:32}:{h:32}@o{d:6}.ingest.sentry.io/{d:7}", true),
    ("segment-write-key", "segment_write_key = \"{a:32}\"", false),
    ("shopify-access-token", "shpat_{h:32}", true),
    ("hashicorp-vault-token", "hvs.{s:40}", true),
    ("supabase-access-token", "sbp_{h:40}", true),
    ("resend-api-key", "re_{a:32}", true),
    ("linear-api-key", "lin_api_{a:40}", true),
    ("planetscale-token", "pscale_tkn_{s:40}", true),
    ("posthog-api-key", "phx_{a:40}", true),
    ("aws-bedrock-api-key", "ABSK{b:150}", true),
    ("azure-ad-client-secret", "{a:3}8Q~{x:34}", true),
    ("google-oauth-client-secret", "GOCSPX-{s:28}", true),
    ("doppler-api-token", "dp.pt.{a:43}", true),
    ("heroku-api-key-v2", "HRKU-AA{s:58}", true),
    ("heroku-api-key", "HEROKU_API_KEY={U:0}", false),
    ("twilio-auth-token", "TWILIO_AUTH_TOKEN=\"{h:32}\"", false),
    ("github-app-token", "ghs_{a:36}", true),
    ("github-app-token", "ghu_{a:36}", true),
    ("gitlab-runner-token", "glrt-{s:20}", true),
    ("gitlab-deploy-token", "gldt-{s:20}", true),
    ("slack-app-token", "xapp-1-A{u:10}-{d:12}-{l:64}", true),
    ("slack-legacy-token", "xoxr-{a:40}", true),
    ("shopify-app-secret", "shpss_{h:32}", true),
    ("rubygems-api-token", "rubygems_{h:48}", true),
    ("pulumi-api-token", "pul-{h:40}", true),
    ("postman-api-token", "PMAK-{h:24}-{h:34}", true),
    ("grafana-service-account-token", "glsa_{a:32}_{h:8}", true),
    ("grafana-cloud-token", "glc_{b:60}", true),
    ("databricks-api-token", "dapi{h:32}", true),
    ("dynatrace-api-token", "dt0c01.{u:24}.{u:64}", true),
    ("flyio-access-token", "fo1_{s:43}", true),
    ("sourcegraph-access-token", "sgp_{h:40}", true),
    ("notion-api-token", "ntn_{a:46}", true),
    ("age-secret-key", "AGE-SECRET-KEY-1{K:58}", true),
    ("onepassword-service-account-token", "ops_eyJ{b:300}", true),
    ("cloudflare-origin-ca-key", "v1.0-{h:24}-{h:146}", true),
    ("terraform-cloud-token", "{l:14}.atlasv1.{s:64}", true),
    ("sentry-auth-token", "sntrys_eyJ{s:80}", true),
    ("sentry-auth-token", "sntryu_{h:64}", true),
    ("atlassian-api-token", "ATATT3{s:190}", true),
    ("airtable-personal-access-token", "pat{a:14}.{h:64}", true),
    ("mapbox-secret-token", "sk.eyJ{s:30}.{s:30}", true),
    ("dropbox-short-lived-token", "sl.{s:140}", true),
    ("credential-assignment", "db_password = \"{a:16}9!\"", false),
    ("credential-assignment", "client_token: '{a:24}'", false),
    ("credential-assignment", "admin_password=\"{a:12}#\"", false),
    ("credential-assignment", "shared_secret = \"{h:64}\"", false),
    ("credential-assignment", "# db_password = \"{a:16}9!\"", false),
    ("credential-assignment", "mysql --password=\"{a:16}9!\"", false),
    ("credential-assignment", "--password=\"{a:16}9!\"", false),
    ("credential-assignment", "hash_secret: '{h:40}'", false),
    ("basic-auth-header", "Authorization: \"Basic YXlsOnoxYXR1Zi1zaWZ6dnRxaQ==\"", false),
    ("credential-assignment", "\"secret_key\": \"{U:0}\"", false),
    ("credential-assignment-unquoted", "user_token: {U:0}", false),
    ("password-literal", "app_password = \"{a:6}#{d:3}\"", false),
    ("password-literal", "MasterUserPassword=\"cnrltkl\"", false),
    ("keyed-secret-value", "Key = {h:32}", false),
    ("credential-assignment-unquoted", "SharedSecret={h:40}", false),
    ("keyed-secret-value", "wrapping_key: '{s:32}'", false),
    ("url-basic-auth", "https://deploy{l:3}:{a:16}@git.internal.net/org/repo.git", false),
    ("url-basic-auth", "curl -u x https://admin:admin@the-internet.herokuapp.com/basic_auth", false),
    ("vendor-keyed-token", "KUCOIN_SECRET=\"{h:24}\"", false),
    ("vendor-keyed-token", "discordToken: '{h:64}'", false),
    ("vendor-keyed-token", "algolia_admin = \"{l:32}\"", false),
    ("openshift-user-token", "sha256~{s:43}", true),
    ("vault-legacy-token", "VAULT_TOKEN=s.{l:24}", false),
    ("keyed-uuid-credential", "HUBSPOT_API_KEY={U:0}", false),
    ("keyed-uuid-credential", "snykToken: \"{U:0}\"", false),
    ("credential-assignment-unquoted", "DB_PASSWORD={a:20}", false),
    ("credential-assignment-unquoted", "auth_token: {a:32}", false),
    ("credential-assignment-unquoted", "client_secret = {a:30}", false),
    ("credential-assignment-unquoted", "SERVICE_TOKEN={s:40}", false),
];

const CONTEXTS: [&str; 4] = ["{}", "KEY=\"{}\"", "\"value\": \"{}\"", "export CRED='{}'"];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick(&mut self, alphabet: &str, n: usize) -> String {
        let chars: Vec<char> = alphabet.chars().collect();
        (0..n)
            .map(|_| chars[(self.next() % chars.len() as u64) as usize])
            .collect()
    }
}

fn alphabet(kind: char) -> &'static str {
    match kind {
        'a' => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        'h' => "0123456789abcdef",
        'd' => "0123456789",
        'u' => "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        'l' => "abcdefghijklmnopqrstuvwxyz0123456789",
        's' => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
        'b' => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/",
        'B' => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        'x' => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_~.",
        'K' => "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L",
        other => panic!("unknown template kind {other}"),
    }
}

fn expand(template: &str, rng: &mut Rng) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..].find('}').expect("unclosed placeholder") + open;
        let (kind, len) = rest[open + 1..close]
            .split_once(':')
            .expect("placeholder kind:len");
        let kind = kind.chars().next().unwrap();
        if kind == 'U' {
            let h = rng.pick(alphabet('h'), 32);
            out.push_str(&format!(
                "{}-{}-{}-{}-{}",
                &h[..8],
                &h[8..12],
                &h[12..16],
                &h[16..20],
                &h[20..]
            ));
        } else {
            out.push_str(&rng.pick(alphabet(kind), len.parse().unwrap()));
        }
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

fn positives() -> Vec<(&'static str, String)> {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut out = Vec::new();
    for (rule, template, wrap) in CASES {
        for variant in 0..VARIANTS {
            let token = expand(template, &mut rng);
            let line = if *wrap {
                CONTEXTS[variant % CONTEXTS.len()].replace("{}", &token)
            } else {
                token
            };
            out.push((*rule, line));
        }
    }
    out
}

fn negatives() -> Vec<(String, String)> {
    include_str!("corpus/negatives.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let (cat, line) = l.split_once('\t').expect("category<TAB>line");
            (cat.to_string(), line.to_string())
        })
        .collect()
}

#[derive(Default)]
struct Tally {
    tp: usize,
    fp: usize,
    fn_: usize,
}

#[test]
fn corpus_precision_recall() {
    let engine = DetectorEngine::new().unwrap();
    let pos = positives();
    let neg = negatives();
    assert!(
        pos.len() >= 200,
        "need >= 200 positives, have {}",
        pos.len()
    );
    assert!(
        neg.len() >= 200,
        "need >= 200 negatives, have {}",
        neg.len()
    );

    if let Ok(dir) = std::env::var("CORPUS_DUMP") {
        let text = |lines: Vec<&str>| lines.join("\n") + "\n";
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            format!("{dir}/positives.txt"),
            text(pos.iter().map(|(_, l)| l.as_str()).collect()),
        )
        .unwrap();
        std::fs::write(
            format!("{dir}/negatives.txt"),
            text(neg.iter().map(|(_, l)| l.as_str()).collect()),
        )
        .unwrap();
    }

    let mut rules: BTreeMap<String, Tally> = BTreeMap::new();
    let mut misses = Vec::new();
    let mut false_alarms = Vec::new();

    for (expected, line) in &pos {
        let found: Vec<String> = engine
            .scan_text(line, "corpus.txt")
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        let tally = rules.entry(expected.to_string()).or_default();
        if found.iter().any(|r| r == expected) {
            tally.tp += 1;
        } else {
            tally.fn_ += 1;
            misses.push(format!("{expected}: {line}  -> {found:?}"));
        }
        for other in found.iter().filter(|r| *r != expected) {
            rules.entry(other.clone()).or_default().fp += 1;
            false_alarms.push(format!("{other} on [{expected}] positive: {line}"));
        }
    }
    for (category, line) in &neg {
        for finding in engine.scan_text(line, "corpus.txt") {
            rules.entry(finding.rule_id.clone()).or_default().fp += 1;
            false_alarms.push(format!(
                "{} on [{category}] negative: {line}",
                finding.rule_id
            ));
        }
    }

    println!(
        "\n{:<36} {:>4} {:>4} {:>4} {:>9} {:>7}",
        "rule", "TP", "FP", "FN", "precision", "recall"
    );
    let (mut tp, mut fn_) = (0, 0);
    let mut weak = Vec::new();
    for (rule, t) in &rules {
        let precision = if t.tp + t.fp == 0 {
            1.0
        } else {
            t.tp as f64 / (t.tp + t.fp) as f64
        };
        let recall = if t.tp + t.fn_ == 0 {
            f64::NAN
        } else {
            t.tp as f64 / (t.tp + t.fn_) as f64
        };
        println!(
            "{rule:<36} {:>4} {:>4} {:>4} {precision:>9.2} {recall:>7.2}",
            t.tp, t.fp, t.fn_
        );
        if precision < MIN_PRECISION {
            weak.push(format!("{rule} precision {precision:.2}"));
        }
        tp += t.tp;
        fn_ += t.fn_;
    }
    let recall = tp as f64 / (tp + fn_) as f64;
    println!(
        "\npositives {} negatives {} | overall recall {recall:.3} ({tp}/{})",
        pos.len(),
        neg.len(),
        tp + fn_
    );
    for m in misses.iter().chain(&false_alarms) {
        println!("  ! {m}");
    }

    let baseline: f64 = include_str!("corpus/baseline_recall.txt")
        .trim()
        .parse()
        .unwrap();
    assert!(weak.is_empty(), "precision below {MIN_PRECISION}: {weak:?}");
    assert!(
        recall >= baseline - MAX_RECALL_DROP,
        "recall {recall:.3} regressed more than {MAX_RECALL_DROP} below baseline {baseline}"
    );
}
