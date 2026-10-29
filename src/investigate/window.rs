use crate::detector::DetectorEngine;
use crate::error::SentrisError;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

pub const TIME_NOTE: &str =
    "time is the author date of the first commit containing the value; not the push time";
const MARK: &str = "@@SENTRIS-COMMIT@@ ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureStart {
    pub commit: String,
    pub author_time: u64,
}

/// Outcome of the history search; `note` states the time semantics or why nothing was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    pub start: Option<ExposureStart>,
    pub note: String,
}

fn git(repo: &Path, args: &[&str]) -> Command {
    let mut c = Command::new("git");
    c.arg("-C").arg(repo).args(args);
    c
}

fn is_shallow(repo: &Path) -> bool {
    git(repo, &["rev-parse", "--is-shallow-repository"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false)
}

/// Oldest commit (any branch) whose added lines contain a secret with `fingerprint`.
pub fn first_exposure(repo: &Path, fingerprint: &str) -> Result<Exposure, SentrisError> {
    let engine = DetectorEngine::new()?;
    let mut child = git(
        repo,
        &[
            "log",
            "--all",
            "--reverse",
            "-p",
            "-U0",
            "--no-color",
            &format!("--format={MARK}%H %at"),
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .map_err(|e| SentrisError::Scan(format!("Failed to spawn git log: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SentrisError::Scan("Failed to capture git stdout".to_string()))?;

    let mut current: Option<ExposureStart> = None;
    let mut found = None;
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if let Some(rest) = line.strip_prefix(MARK) {
            current = rest.split_once(' ').and_then(|(c, t)| {
                Some(ExposureStart {
                    commit: c.to_string(),
                    author_time: t.trim().parse().ok()?,
                })
            });
        } else if let Some(added) = line.strip_prefix('+').filter(|_| !line.starts_with("+++")) {
            let hit = engine
                .scan_single_line(added, "history", 1, None)
                .iter()
                .any(|f| f.fingerprint == fingerprint);
            if hit && current.is_some() {
                found = current.clone();
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    let note = match (&found, is_shallow(repo)) {
        (Some(_), _) => TIME_NOTE.to_string(),
        (None, true) => {
            "shallow clone: older history is missing, so the first exposure cannot be determined"
                .to_string()
        }
        (None, false) => "value not found in any commit's added lines".to_string(),
    };
    Ok(Exposure { start: found, note })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const KEY_LINE: &str = "aws_access_key_id = AKIAJ5Q7X2M9R4T6W8YB";

    fn run(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .env("GIT_AUTHOR_DATE", "2024-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2024-01-01T00:00:00Z")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        assert!(ok, "git {args:?} failed");
    }

    fn commit(dir: &Path, n: u32, body: &str, date: &str) {
        fs::write(dir.join("f.txt"), body).unwrap();
        run(dir, &["add", "."]);
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(["commit", "-m", &format!("c{n}")])
            .env("GIT_AUTHOR_DATE", date)
            .env("GIT_COMMITTER_DATE", date)
            .output()
            .unwrap();
        assert!(out.status.success());
    }

    fn fingerprint() -> String {
        let engine = DetectorEngine::new().unwrap();
        let hits = engine.scan_single_line(KEY_LINE, "f.txt", 1, None);
        assert!(!hits.is_empty(), "fixture key must be detected");
        hits[0].fingerprint.clone()
    }

    fn repo() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        run(d.path(), &["init", "-q"]);
        commit(d.path(), 1, "hello\n", "2024-01-01T00:00:00Z");
        commit(
            d.path(),
            2,
            &format!("hello\n{KEY_LINE}\n"),
            "2024-02-01T00:00:00Z",
        );
        commit(
            d.path(),
            3,
            &format!("hello\n{KEY_LINE}\nmore\n"),
            "2024-03-01T00:00:00Z",
        );
        commit(d.path(), 4, "hello\nmore\n", "2024-04-01T00:00:00Z");
        d
    }

    #[test]
    fn finds_commit_that_introduced_the_value() {
        let d = repo();
        let second = String::from_utf8(
            git(d.path(), &["rev-list", "--reverse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .lines()
        .nth(1)
        .unwrap()
        .to_string();
        let e = first_exposure(d.path(), &fingerprint()).unwrap();
        let start = e.start.unwrap();
        assert_eq!(start.commit, second);
        assert_eq!(start.author_time, 1_706_745_600); // 2024-02-01T00:00:00Z
        assert!(e.note.contains("author date") && e.note.contains("not the push time"));
    }

    #[test]
    fn value_never_in_history_is_none() {
        let d = repo();
        let e = first_exposure(d.path(), &"0".repeat(64)).unwrap();
        assert!(e.start.is_none());
        assert!(e.note.contains("not found"));
    }

    #[test]
    fn shallow_clone_states_reason_instead_of_panicking() {
        let d = repo();
        let clone = tempfile::tempdir().unwrap();
        let ok = Command::new("git")
            .args(["clone", "-q", "--depth", "1"])
            .arg(format!("file://{}", d.path().display()))
            .arg(clone.path())
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok);
        let e = first_exposure(clone.path(), &fingerprint()).unwrap();
        assert!(e.start.is_none());
        assert!(e.note.contains("shallow"));
    }
}
