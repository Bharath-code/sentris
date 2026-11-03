/// Prefixes of Base64-encoded well-known secret tokens and URL-encoded scheme separators
/// registered in the Aho-Corasick prefilter under `DECODE_OWNER`.
pub const DECODE_TRIGGER_LITERALS: &[&str] = &[
    "c2tfbGl2ZV",     // sk_live_
    "cmtfbGl2ZV",     // rk_live_
    "Z2hwX",          // ghp_
    "Z2l0aHViX3BhdF", // github_pat_
    "QUtJQ",          // AKIA
    "QVNJQ",          // ASIA
    "c2stYW50",       // sk-ant-
    "c2stcHJvai",     // sk-proj-
    "eG94Y",          // xoxb-
    "eG94c",          // xoxp-
    "aGZf",           // hf_
    "Z2xwYXQt",       // glpat-
    "Z3NrX",          // gsk_
    "U0cu",           // SG.
    "%3a%2f%2f",      // :// (URL-encoded)
];

#[inline]
fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Decodes a standard or URL-safe Base64 token into printable ASCII/UTF-8 if valid.
pub fn decode_base64_ascii(token: &str) -> Option<String> {
    let trimmed = token.trim_end_matches('=');
    if trimmed.len() < 20 || token.len() > 4096 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let mut chunks = bytes.chunks_exact(4);
    for chunk in &mut chunks {
        let a = b64_val(chunk[0])?;
        let b = b64_val(chunk[1])?;
        let c = b64_val(chunk[2])?;
        let d = b64_val(chunk[3])?;
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
        out.push((c << 6) | d);
    }
    let rem = chunks.remainder();
    match rem.len() {
        2 => {
            let a = b64_val(rem[0])?;
            let b = b64_val(rem[1])?;
            out.push((a << 2) | (b >> 4));
        }
        3 => {
            let a = b64_val(rem[0])?;
            let b = b64_val(rem[1])?;
            let c = b64_val(rem[2])?;
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
        }
        0 => {}
        _ => return None,
    }

    if out.is_empty()
        || !out
            .iter()
            .all(|&b| matches!(b, 0x20..=0x7E | b'\t' | b'\n' | b'\r'))
    {
        return None;
    }
    String::from_utf8(out).ok()
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes URL percent-encoded sequences (`%XX`) in `line` if any are present and valid UTF-8.
pub fn decode_url_percent(line: &str) -> Option<String> {
    if !line.contains('%') || line.len() > 8192 {
        return None;
    }
    let bytes = line.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut decoded_any = false;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                decoded_any = true;
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    if !decoded_any {
        return None;
    }
    String::from_utf8(out).ok()
}

#[inline]
fn is_b64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
}

/// Extracts decoded candidate lines from `line` (via URL-percent decoding or Base64 token expansion).
pub fn extract_decoded_candidates(line: &str, force_unpadded_b64: bool) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(url_dec) = decode_url_percent(line) {
        candidates.push(url_dec);
    }

    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && !is_b64_char(bytes[i]) {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && is_b64_char(bytes[i]) {
            i += 1;
        }
        let tok = &line[start..i];
        if tok.len() >= 24
            && (force_unpadded_b64
                || tok.ends_with('=')
                || DECODE_TRIGGER_LITERALS
                    .iter()
                    .any(|p| tok.starts_with(p)))
        {
            if let Some(decoded) = decode_base64_ascii(tok) {
                // Reconstruct the surrounding line context so keyed rules (e.g. `api_key: <b64>`) work too
                let mut reconstructed =
                    String::with_capacity(line.len() - tok.len() + decoded.len());
                reconstructed.push_str(&line[..start]);
                reconstructed.push_str(&decoded);
                reconstructed.push_str(&line[i..]);
                candidates.push(reconstructed);
            }
        }
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base64_and_url_encoded_secrets() {
        let b64 = concat!(
            "c2tfbGl2ZV",
            "81MUFiY0RlZkdoSWpLbE1uT3BRclN0VXZ3eFl6MTIzNDU2"
        );
        let expected_raw = concat!(
            "sk_live_",
            "51AbcDefGhIjKlMnOpQrStUvwxYz123456"
        );
        let dec = decode_base64_ascii(b64).unwrap();
        assert_eq!(dec, expected_raw);

        let line = format!("  stripe_key: {b64}");
        let cands = extract_decoded_candidates(&line, false);
        assert_eq!(
            cands,
            vec![format!("  stripe_key: {expected_raw}")]
        );

        let url_line = concat!(
            "DATABASE_URL=\"postgres%3A%2F%2F",
            "admin%3As3cr3tP4ssw0rd99%40db.internal%3A5432%2Fprod\""
        );
        let url_cands = extract_decoded_candidates(url_line, false);
        assert_eq!(
            url_cands,
            vec![concat!(
                "DATABASE_URL=\"postgres://",
                "admin:s3cr3tP4ssw0rd99@db.internal:5432/prod\""
            )]
        );
    }
}
