//! Replaces detected secrets in arbitrary text with stable markers, so prompts and tool output can leave the machine without them.

use crate::detector::DetectorEngine;
use crate::model::{short, Finding};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RedactedFinding {
    pub rule_id: String,
    pub line: usize,
    pub fingerprint_prefix: String,
}

#[derive(Debug, Clone)]
pub struct Redaction {
    pub text: String,
    pub findings: Vec<RedactedFinding>,
}

struct Span {
    start: usize,
    end: usize,
    marker: String,
}

const MARKER_OPEN: &str = "«sentris:";
const MARKER_CLOSE: char = '»';

fn marker(f: &Finding) -> String {
    format!(
        "{MARKER_OPEN}{}:{}{MARKER_CLOSE}",
        f.rule_id,
        short(&f.fingerprint, 8)
    )
}

fn is_marker_body(body: &str, known_rule: &impl Fn(&str) -> bool) -> bool {
    body.rsplit_once(':').is_some_and(|(rule, fp)| {
        fp.len() == 8 && fp.bytes().all(|b| b.is_ascii_hexdigit()) && known_rule(rule)
    })
}

/// True when `start..end` of `line` lies entirely inside one complete, well-formed marker.
/// A string that merely contains `sentris:` is not a marker, so it cannot hide a real secret.
/// `known_rule` must confirm the rule part, so arbitrary text (including a real secret) cannot pose as one.
pub fn inside_marker(
    line: &str,
    start: usize,
    end: usize,
    known_rule: impl Fn(&str) -> bool,
) -> bool {
    line.match_indices(MARKER_OPEN).any(|(open, _)| {
        let body_start = open + MARKER_OPEN.len();
        line[body_start..].find(MARKER_CLOSE).is_some_and(|rel| {
            let close_end = body_start + rel + MARKER_CLOSE.len_utf8();
            is_marker_body(&line[body_start..body_start + rel], &known_rule)
                && start >= open
                && end <= close_end
        })
    })
}

/// `(byte offset, line without EOL)` for every line, matching the 1-based numbering of `scan_text`.
fn line_table(text: &str) -> Vec<(usize, &str)> {
    let mut offset = 0;
    text.split_inclusive('\n')
        .map(|raw| {
            let start = offset;
            offset += raw.len();
            (
                start,
                raw.strip_suffix('\n')
                    .map_or(raw, |l| l.strip_suffix('\r').unwrap_or(l)),
            )
        })
        .collect()
}

/// Byte range of a whole `-----BEGIN ...----- ... -----END ...-----` block starting on `line_no`.
fn pem_span(text: &str, lines: &[(usize, &str)], line_no: usize) -> Option<(usize, usize)> {
    let (first, last, _) = DetectorEngine::extract_multiline_pem_block(text, line_no)?;
    let (first_off, first_line) = lines.get(first - 1)?;
    let (last_off, last_line) = lines.get(last - 1)?;
    let start = first_off + first_line.find("-----BEGIN ")?;
    let end_marker = last_line.find("-----END ")?;
    let close = last_line[end_marker + 9..].find("-----")?;
    Some((start, last_off + end_marker + 9 + close + 5))
}

fn spans_for(
    engine: &DetectorEngine,
    text: &str,
    lines: &[(usize, &str)],
    f: &Finding,
) -> Vec<Span> {
    let Some(&(off, line)) = lines.get(f.line_number.wrapping_sub(1)) else {
        return Vec::new();
    };
    let mark = marker(f);
    if f.rule_id.ends_with("private-key") {
        // No END marker means the key may run to the end of the text: hide all of it
        let (start, end) = pem_span(text, lines, f.line_number)
            .unwrap_or_else(|| (off + line.find("-----BEGIN ").unwrap_or(0), text.len()));
        return vec![Span {
            start,
            end,
            marker: mark,
        }];
    }
    match engine.extract_secret_for_fingerprint(line, &f.rule_id, &f.fingerprint) {
        Some(raw) if !raw.is_empty() => line
            .match_indices(raw.as_str())
            .map(|(i, m)| Span {
                start: off + i,
                end: off + i + m.len(),
                marker: mark.clone(),
            })
            .collect(),
        // Could not isolate the secret: hide the whole line rather than leak it
        _ => vec![Span {
            start: off,
            end: off + line.len(),
            marker: mark,
        }],
    }
}

pub fn redact(engine: &DetectorEngine, text: &str) -> Redaction {
    let findings = engine.scan_text_for_redaction(text);
    if findings.is_empty() {
        return Redaction {
            text: text.to_string(),
            findings: Vec::new(),
        };
    }
    let lines = line_table(text);
    let mut spans: Vec<Span> = findings
        .iter()
        .flat_map(|f| spans_for(engine, text, &lines, f))
        .collect();
    spans.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for span in &spans {
        if span.start < cursor {
            // Overlaps a span already replaced; extend it if this one reaches further
            if span.end > cursor {
                cursor = span.end;
            }
            continue;
        }
        out.push_str(&text[cursor..span.start]);
        out.push_str(&span.marker);
        cursor = span.end;
    }
    out.push_str(&text[cursor..]);

    Redaction {
        text: out,
        findings: findings
            .iter()
            .map(|f| RedactedFinding {
                rule_id: f.rule_id.clone(),
                line: f.line_number,
                fingerprint_prefix: short(&f.fingerprint, 8).to_string(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::DetectorEngine;

    const STRIPE: &str = concat!("sk_live_", "51Nq8xT2LmV7pRz0aBcDeFgHiJk9WsYuXo3Zt4");
    const GITHUB: &str = concat!("ghp_", "R7tK2mQ9xV4bN8cL1wZ5yH3jD6fG0sA2pXuE");

    fn engine() -> DetectorEngine {
        DetectorEngine::new().unwrap()
    }

    fn secrets_in(text: &str) -> Vec<&'static str> {
        [STRIPE, GITHUB]
            .into_iter()
            .filter(|s| text.contains(s))
            .collect()
    }

    #[test]
    fn replaces_a_secret_and_keeps_every_other_byte() {
        let text = format!("before {STRIPE} after\n");
        let out = redact(&engine(), &text);
        assert_eq!(out.findings.len(), 1);
        assert!(out.text.starts_with("before «sentris:stripe-secret-key:"));
        assert!(out.text.ends_with("» after\n"));
        assert!(!out.text.contains(STRIPE));
    }

    #[test]
    fn clean_text_is_returned_untouched() {
        let text = "just a normal sentence\r\nwith CRLF and no trailing newline";
        let out = redact(&engine(), text);
        assert_eq!(out.text, text);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn crlf_and_missing_final_newline_survive() {
        let text = format!("a = 1\r\nkey = \"{STRIPE}\"\r\nb = 2");
        let out = redact(&engine(), &text);
        assert!(out.text.starts_with("a = 1\r\nkey = \""));
        assert!(out.text.ends_with("\"\r\nb = 2"));
    }

    #[test]
    fn several_secrets_on_and_across_lines_are_all_replaced() {
        let text = format!("x={STRIPE} y={STRIPE}\ntoken: {GITHUB}\n");
        let out = redact(&engine(), &text);
        assert!(secrets_in(&out.text).is_empty(), "{}", out.text);
        assert_eq!(out.text.matches("«sentris:stripe-secret-key:").count(), 2);
        assert!(out.text.contains("«sentris:github-pat:"));
    }

    #[test]
    fn redaction_is_idempotent() {
        let text = format!("k = \"{STRIPE}\"\n{GITHUB}\n");
        let once = redact(&engine(), &text);
        let twice = redact(&engine(), &once.text);
        assert_eq!(once.text, twice.text);
        assert!(twice.findings.is_empty());
    }

    #[test]
    fn multiline_pem_block_becomes_one_marker() {
        let text = "pre\n  -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxyz\nabcdef==\n-----END RSA PRIVATE KEY-----\npost\n";
        let out = redact(&engine(), text);
        assert!(
            !out.text.contains("MIIEow") && !out.text.contains("abcdef"),
            "{}",
            out.text
        );
        assert!(out.text.starts_with("pre\n  «sentris:rsa-private-key:"));
        assert!(out.text.ends_with("»\npost\n"));
        assert_eq!(out.findings.len(), 1);
    }

    #[test]
    fn multibyte_neighbours_do_not_break_spans() {
        let text = format!("é🔑日本語 {STRIPE} ünï🙂\n");
        let out = redact(&engine(), &text);
        assert!(out.text.starts_with("é🔑日本語 «sentris:"));
        assert!(out.text.ends_with("» ünï🙂\n"));
    }

    #[test]
    fn findings_carry_no_secret_material() {
        let out = redact(&engine(), &format!("{STRIPE}\n"));
        let json = serde_json::to_string(&out.findings).unwrap();
        assert!(!json.contains("51Nq8x"), "{json}");
        assert_eq!(out.findings[0].line, 1);
    }

    #[test]
    fn inline_ignore_comments_do_not_exempt_a_secret_from_redaction() {
        for text in [
            format!("{STRIPE} // nosec"),
            format!("# sentris-ignore\ntoken = {GITHUB}"),
            format!("x = \"{STRIPE}\"  # gitleaks:allow"),
            format!("{GITHUB} pragma: allowlist secret"),
        ] {
            let out = redact(&engine(), &text);
            assert!(
                secrets_in(&out.text).is_empty(),
                "leaked from {text:?}: {}",
                out.text
            );
        }
    }

    #[test]
    fn unquoted_credential_assignments_are_redacted() {
        let text = "DB_PASSWORD=Xk9Qw3Er7Ty1Ui5Op8As2Df4\n";
        let out = redact(&engine(), text);
        assert!(!out.text.contains("Xk9Qw3Er7"), "{}", out.text);
    }

    #[test]
    fn truncated_pem_block_is_hidden_to_the_end_of_the_text() {
        let text = "intro\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxyz\nabcdef==\nstill key material";
        let out = redact(&engine(), text);
        assert!(
            out.text.starts_with("intro\n«sentris:rsa-private-key:"),
            "{}",
            out.text
        );
        for leaked in ["MIIEow", "abcdef", "still key"] {
            assert!(!out.text.contains(leaked), "{}", out.text);
        }
    }

    #[test]
    fn marker_recognition_is_strict() {
        let line = "a «sentris:stripe-secret-key:0123abcd» b";
        let (s, e) = (
            line.find('«').unwrap(),
            line.find('»').unwrap() + '»'.len_utf8(),
        );
        let known = |id: &str| id == "stripe-secret-key";
        assert!(inside_marker(line, s, e, known));
        assert!(inside_marker(line, s + 3, e - 3, known));
        assert!(!inside_marker(line, 0, e, known));
        assert!(!inside_marker(
            "«sentris:stripe-secret-key:nothex!!»",
            0,
            40,
            known
        ));
        assert!(!inside_marker(
            "sentris:stripe-secret-key:0123abcd",
            0,
            34,
            known
        ));
        assert!(
            !inside_marker("«sentris:made-up-rule:0123abcd»", 0, 33, known),
            "unknown rule ids are not markers"
        );
    }

    #[test]
    fn a_real_secret_dressed_up_as_a_marker_is_still_redacted() {
        let text = format!("«sentris:{STRIPE}:deadbeef»\n");
        let out = redact(&engine(), &text);
        assert!(!out.text.contains("51Nq8x"), "{}", out.text);
    }
}
