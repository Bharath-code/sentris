use std::io::Read;

use crate::hook::{config_snippet, evaluate, Verdict};
use crate::scanner::Scanner;

/// Hook payloads are small JSON; anything larger cannot be inspected in reasonable time.
const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;

enum Failure {
    /// The hook could not do its job: follows `--fail-closed`.
    Soft(String),
    /// The input cannot be inspected or the guard cannot start: always blocks, so padding or a bad config cannot switch it off.
    Block(String),
}

/// Exit 2 blocks the action (stderr is shown to the user or sent to Claude).
pub fn handle_hook(print_config: bool, fail_closed: bool) {
    if print_config {
        println!("{}", config_snippet());
        return;
    }
    match run() {
        Ok(Verdict::Allow) => {}
        Ok(Verdict::Deny(message)) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
        Err(Failure::Block(reason)) => {
            eprintln!("sentris hook blocked this action: {reason}");
            std::process::exit(2);
        }
        Err(Failure::Soft(reason)) => {
            eprintln!("sentris hook: {reason}");
            std::process::exit(if fail_closed { 2 } else { 0 });
        }
    }
}

fn run() -> Result<Verdict, Failure> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Failure::Soft(format!("cannot read stdin: {e}")))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(Failure::Block(
            "the input is too large to inspect (over 8 MiB); split it into smaller pieces"
                .to_string(),
        ));
    }
    let raw = String::from_utf8(bytes).map_err(|_| {
        Failure::Block("the input is not valid UTF-8, so it cannot be inspected".to_string())
    })?;
    let input: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| Failure::Soft(format!("input is not valid JSON: {e}")))?;
    let scanner = Scanner::trusted()
        .map_err(|e| Failure::Block(format!("the secret scanner cannot start: {e}")))?;
    Ok(evaluate(&scanner, &input))
}
