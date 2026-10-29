use super::timefmt::parse_rfc3339;
use super::{LastUse, MintedCredential, RotationPlan, Rotator};
use crate::error::SentrisError;
use crate::remediator::Remediator;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Thin `aws` CLI runner shared by rotation, forensics and exposure probes. Uses the caller's ambient credentials, never the leaked key.
pub(crate) struct AwsCli {
    program: PathBuf,
}

impl AwsCli {
    /// `SENTRIS_AWS_BIN` overrides the `aws` executable (nonstandard installs, test shims).
    pub(crate) fn new() -> Self {
        let program = std::env::var_os("SENTRIS_AWS_BIN")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("aws"));
        Self::with_program(program)
    }

    pub(crate) fn with_program(program: PathBuf) -> Self {
        Self { program }
    }

    pub(crate) fn run(&self, args: &[&str]) -> Result<String, SentrisError> {
        let verb = args.iter().take(2).copied().collect::<Vec<_>>().join(" ");
        let out = Command::new(&self.program)
            .args(args)
            .env("AWS_PAGER", "")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                SentrisError::Scan(format!(
                    "Failed to run 'aws {verb}' (install AWS CLI v2 and configure credentials): {e}"
                ))
            })?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let hint = if stderr.contains("AccessDenied") {
            " (your AWS credentials lack the IAM permission for this call)"
        } else {
            ""
        };
        Err(SentrisError::Scan(format!(
            "aws {verb} failed: {}{hint}",
            stderr.trim()
        )))
    }

    fn json(&self, args: &[&str]) -> Result<serde_json::Value, SentrisError> {
        let mut raw = self.run(args)?;
        let parsed = serde_json::from_str(&raw);
        Remediator::zeroize_secret_string(&mut raw);
        parsed.map_err(|_| {
            SentrisError::Scan(format!(
                "aws {} returned output that is not valid JSON",
                args.iter().take(2).copied().collect::<Vec<_>>().join(" ")
            ))
        })
    }

    /// IAM user that owns `access_key_id`, via `get-access-key-last-used`.
    pub(crate) fn resolve_principal(&self, access_key_id: &str) -> Result<String, SentrisError> {
        let v = self
            .json(&[
                "iam",
                "get-access-key-last-used",
                "--access-key-id",
                access_key_id,
                "--output",
                "json",
            ])
            .map_err(|e| match e.to_string() {
                m if m.contains("NoSuchEntity") => SentrisError::Scan(
                    "Access key not found in the AWS account your credentials point at (check AWS_PROFILE / account)".to_string(),
                ),
                _ => e,
            })?;
        v["UserName"]
            .as_str()
            .filter(|u| !u.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                SentrisError::Scan(
                    "Access key has no IAM user owner (root keys must be rotated in the AWS console)".to_string(),
                )
            })
    }
}

pub struct AwsRotator {
    cli: AwsCli,
    env_key_id: Option<String>,
}

impl AwsRotator {
    pub fn new() -> Self {
        Self::with_cli(AwsCli::new())
    }

    pub(crate) fn with_cli(cli: AwsCli) -> Self {
        Self {
            cli,
            env_key_id: std::env::var("AWS_ACCESS_KEY_ID")
                .ok()
                .filter(|k| !k.is_empty()),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_env_key_id(mut self, key_id: Option<String>) -> Self {
        self.env_key_id = key_id;
        self
    }

    /// True when the credentials the CLI would sign with are the leaked key itself.
    fn ambient_is(&self, key_id: &str) -> bool {
        let ambient = self.env_key_id.clone().or_else(|| {
            self.cli
                .run(&["configure", "get", "aws_access_key_id"])
                .ok()
                .map(|s| s.trim().to_string())
        });
        ambient.as_deref() == Some(key_id)
    }
}

impl Default for AwsRotator {
    fn default() -> Self {
        Self::new()
    }
}

fn is_iam_user_key_id(s: &str) -> bool {
    s.len() == 20
        && s.starts_with("AKIA")
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn short_fingerprint(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..16].to_string()
}

impl Rotator for AwsRotator {
    fn provider_name(&self) -> &'static str {
        "AWS"
    }

    fn plan(&self, old_secret: &str) -> Result<RotationPlan, SentrisError> {
        let old = old_secret.trim();
        if old.starts_with("ASIA") {
            return Err(SentrisError::Scan(
                "Temporary (ASIA...) credentials expire on their own; there is nothing to rotate"
                    .to_string(),
            ));
        }
        if !is_iam_user_key_id(old) {
            return Err(SentrisError::Scan(
                "AWS rotation expects an IAM user access key id (AKIA + 16 characters)".to_string(),
            ));
        }
        if self.ambient_is(old) {
            return Err(SentrisError::Scan(
                "Your AWS CLI is signing with the same key you are rotating; use a different admin profile so the old key can be deactivated safely".to_string(),
            ));
        }
        let principal = self.cli.resolve_principal(old)?;
        let listed = self.cli.json(&[
            "iam",
            "list-access-keys",
            "--user-name",
            &principal,
            "--output",
            "json",
        ])?;
        let keys = listed["AccessKeyMetadata"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let status = keys
            .iter()
            .find(|k| k["AccessKeyId"] == old)
            .and_then(|k| k["Status"].as_str())
            .ok_or_else(|| {
                SentrisError::Scan(format!("Key is not listed under IAM user '{principal}'"))
            })?;
        if status != "Active" {
            return Err(SentrisError::Scan(format!(
                "Key is already {status}; nothing to rotate"
            )));
        }
        if keys.len() >= 2 {
            return Err(SentrisError::Scan(format!(
                "IAM user '{principal}' already has 2 access keys (the AWS maximum); delete an unused one first, Sentris will not delete keys for you"
            )));
        }
        Ok(RotationPlan {
            provider: "AWS".to_string(),
            rule_id: "aws-access-key-id".to_string(),
            principal,
            old_key_id: old.to_string(),
            old_fingerprint: short_fingerprint(old),
        })
    }

    fn mint(&self, plan: &RotationPlan) -> Result<MintedCredential, SentrisError> {
        let created = self.cli.json(&[
            "iam",
            "create-access-key",
            "--user-name",
            &plan.principal,
            "--output",
            "json",
        ])?;
        let key = &created["AccessKey"];
        match (key["AccessKeyId"].as_str(), key["SecretAccessKey"].as_str()) {
            (Some(key_id), Some(secret)) => Ok(MintedCredential {
                key_id: key_id.to_string(),
                secret: secret.to_string(),
            }),
            _ => Err(SentrisError::Scan(
                "aws iam create-access-key response did not contain a key pair; check the IAM user for an orphaned new key".to_string(),
            )),
        }
    }

    fn deactivate_old(&self, plan: &RotationPlan) -> Result<(), SentrisError> {
        set_status(&self.cli, &plan.principal, &plan.old_key_id, "Inactive")
    }

    fn reactivate_old(&self, plan: &RotationPlan) -> Result<(), SentrisError> {
        set_status(&self.cli, &plan.principal, &plan.old_key_id, "Active")
    }

    fn discard_new(&self, plan: &RotationPlan, new_key_id: &str) -> Result<(), SentrisError> {
        delete_key(&self.cli, &plan.principal, new_key_id)
    }

    fn delete_old(&self, plan: &RotationPlan) -> Result<(), SentrisError> {
        delete_key(&self.cli, &plan.principal, &plan.old_key_id)
    }

    fn last_used(&self, plan: &RotationPlan) -> Result<Option<LastUse>, SentrisError> {
        let v = self.cli.json(&[
            "iam",
            "get-access-key-last-used",
            "--access-key-id",
            &plan.old_key_id,
            "--output",
            "json",
        ])?;
        let used = &v["AccessKeyLastUsed"];
        Ok(used["LastUsedDate"]
            .as_str()
            .and_then(parse_rfc3339)
            .map(|at| LastUse {
                at,
                service: used["ServiceName"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                region: used["Region"].as_str().unwrap_or("unknown").to_string(),
            }))
    }

    fn env_values(&self, base_var: &str, minted: &MintedCredential) -> Vec<(String, String)> {
        let secret_var = if base_var.contains("AWS_ACCESS_KEY_ID") {
            base_var.replacen("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", 1)
        } else {
            format!("{base_var}_SECRET")
        };
        vec![
            (base_var.to_string(), minted.key_id.clone()),
            (secret_var, minted.secret.clone()),
        ]
    }
}

fn set_status(cli: &AwsCli, user: &str, key_id: &str, status: &str) -> Result<(), SentrisError> {
    cli.run(&[
        "iam",
        "update-access-key",
        "--user-name",
        user,
        "--access-key-id",
        key_id,
        "--status",
        status,
    ])
    .map(|_| ())
}

fn delete_key(cli: &AwsCli, user: &str, key_id: &str) -> Result<(), SentrisError> {
    cli.run(&[
        "iam",
        "delete-access-key",
        "--user-name",
        user,
        "--access-key-id",
        key_id,
    ])
    .map(|_| ())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const OLD: &str = "AKIAIOSFODNN7OLDKEY1";
    const NEW_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLENEWSECRET";

    struct Fake {
        dir: tempfile::TempDir,
    }

    impl Fake {
        fn new(replies: &[(&str, &str)], fails: &[(&str, &str)]) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            for (sub, body) in replies {
                fs::write(dir.path().join(format!("{sub}.out")), body).expect("write reply");
            }
            for (sub, msg) in fails {
                fs::write(dir.path().join(format!("{sub}.fail")), msg).expect("write failure");
            }
            let script = format!(
                "#!/bin/sh\necho \"ARGV: $@\" >> {d}/calls.log\nif [ -f \"{d}/$2.out\" ]; then cat \"{d}/$2.out\"; exit 0; fi\nif [ -f \"{d}/$2.fail\" ]; then cat \"{d}/$2.fail\" >&2; exit 254; fi\nexit 1\n",
                d = dir.path().display()
            );
            let bin = dir.path().join("aws");
            fs::write(&bin, script).expect("write shim");
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).expect("chmod shim");
            Self { dir }
        }

        fn rotator(&self) -> AwsRotator {
            AwsRotator::with_cli(AwsCli::with_program(self.dir.path().join("aws")))
                .with_env_key_id(None)
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(self.dir.path().join("calls.log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    const LAST_USED: &str = r#"{"UserName":"bob","AccessKeyLastUsed":{"LastUsedDate":"2026-10-28T10:00:00+00:00","ServiceName":"s3","Region":"us-east-1"}}"#;
    const ONE_KEY: &str = r#"{"AccessKeyMetadata":[{"UserName":"bob","AccessKeyId":"AKIAIOSFODNN7OLDKEY1","Status":"Active","CreateDate":"2025-01-01T00:00:00+00:00"}]}"#;
    const TWO_KEYS: &str = r#"{"AccessKeyMetadata":[{"UserName":"bob","AccessKeyId":"AKIAIOSFODNN7OLDKEY1","Status":"Active"},{"UserName":"bob","AccessKeyId":"AKIAIOSFODNN7OTHERKY","Status":"Active"}]}"#;
    const CREATED: &str = r#"{"AccessKey":{"UserName":"bob","AccessKeyId":"AKIAIOSFODNN7NEWKEY1","Status":"Active","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLENEWSECRET"}}"#;

    fn happy() -> Fake {
        Fake::new(
            &[
                ("get-access-key-last-used", LAST_USED),
                ("list-access-keys", ONE_KEY),
                ("create-access-key", CREATED),
                ("update-access-key", ""),
                ("delete-access-key", ""),
            ],
            &[],
        )
    }

    fn mutating(calls: &[String]) -> Vec<&String> {
        calls
            .iter()
            .filter(|c| {
                ["create-", "update-", "delete-"]
                    .iter()
                    .any(|v| c.contains(v))
            })
            .collect()
    }

    #[test]
    fn plan_resolves_owner_and_is_read_only() {
        let fake = happy();
        let plan = fake.rotator().plan(OLD).unwrap();
        assert_eq!(plan.principal, "bob");
        assert_eq!(plan.old_key_id, OLD);
        assert_eq!(plan.provider, "AWS");
        assert_eq!(plan.old_fingerprint.len(), 16);
        let calls = fake.calls();
        assert!(!calls.is_empty());
        assert!(mutating(&calls).is_empty(), "{calls:?}");
    }

    #[test]
    fn refuses_when_ambient_key_is_the_leaked_key() {
        let fake = happy();
        let r = fake.rotator().with_env_key_id(Some(OLD.to_string()));
        let err = r.plan(OLD).unwrap_err().to_string();
        assert!(err.contains("same key"), "{err}");
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn refuses_when_profile_key_is_the_leaked_key() {
        let fake = Fake::new(&[("get", &format!("{OLD}\n"))], &[]);
        let err = fake.rotator().plan(OLD).unwrap_err().to_string();
        assert!(err.contains("same key"), "{err}");
        assert!(mutating(&fake.calls()).is_empty());
    }

    #[test]
    fn refuses_at_the_two_key_limit_without_deleting_anything() {
        let fake = Fake::new(
            &[
                ("get-access-key-last-used", LAST_USED),
                ("list-access-keys", TWO_KEYS),
            ],
            &[],
        );
        let err = fake.rotator().plan(OLD).unwrap_err().to_string();
        assert!(
            err.contains("bob") && err.contains("2 access keys"),
            "{err}"
        );
        assert!(mutating(&fake.calls()).is_empty());
    }

    #[test]
    fn unknown_key_is_a_clear_error() {
        let fake = Fake::new(
            &[],
            &[(
                "get-access-key-last-used",
                "An error occurred (NoSuchEntity) when calling the GetAccessKeyLastUsed operation",
            )],
        );
        let err = fake.rotator().plan(OLD).unwrap_err().to_string();
        assert!(err.contains("not found"), "{err}");
        assert!(mutating(&fake.calls()).is_empty());
    }

    #[test]
    fn temporary_and_malformed_ids_are_rejected_before_any_call() {
        let fake = happy();
        for bad in [
            "ASIAIOSFODNN7TEMPKEY",
            "not-a-key",
            "AKIAshort",
            "wJalrXUtnFEMI/K7MDENG",
        ] {
            let err = fake.rotator().plan(bad).unwrap_err().to_string();
            assert!(!err.contains(bad), "error must not echo the input: {err}");
        }
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn mint_returns_secret_in_memory_and_never_in_argv() {
        let fake = happy();
        let r = fake.rotator();
        let plan = r.plan(OLD).unwrap();
        let minted = r.mint(&plan).unwrap();
        assert_eq!(minted.key_id, "AKIAIOSFODNN7NEWKEY1");
        assert_eq!(minted.secret, NEW_SECRET);
        for line in fake.calls() {
            assert!(!line.contains("wJalr"), "secret in argv: {line}");
        }
        assert!(!format!("{minted:?}").contains("wJalr"));
    }

    #[test]
    fn mint_failure_and_garbled_output_do_not_leak_or_panic() {
        let fake = Fake::new(
            &[
                ("get-access-key-last-used", LAST_USED),
                ("list-access-keys", ONE_KEY),
                ("create-access-key", "not json wJalrXUtnFEMI-LEAK"),
            ],
            &[],
        );
        let r = fake.rotator();
        let plan = r.plan(OLD).unwrap();
        let err = r.mint(&plan).unwrap_err().to_string();
        assert!(!err.contains("wJalr"), "{err}");
    }

    #[test]
    fn lifecycle_calls_use_the_right_verbs_and_flags() {
        let fake = happy();
        let r = fake.rotator();
        let plan = r.plan(OLD).unwrap();
        r.deactivate_old(&plan).unwrap();
        r.reactivate_old(&plan).unwrap();
        r.discard_new(&plan, "AKIAIOSFODNN7NEWKEY1").unwrap();
        r.delete_old(&plan).unwrap();
        let calls = fake.calls().join("\n");
        assert!(calls.contains(&format!(
            "iam update-access-key --user-name bob --access-key-id {OLD} --status Inactive"
        )));
        assert!(calls.contains(&format!(
            "iam update-access-key --user-name bob --access-key-id {OLD} --status Active"
        )));
        assert!(calls.contains(
            "iam delete-access-key --user-name bob --access-key-id AKIAIOSFODNN7NEWKEY1"
        ));
        assert!(calls.contains(&format!(
            "iam delete-access-key --user-name bob --access-key-id {OLD}"
        )));
    }

    #[test]
    fn missing_aws_binary_is_an_error_not_a_panic() {
        let r = AwsRotator::with_cli(AwsCli::with_program("/nonexistent/aws".into()))
            .with_env_key_id(None);
        let err = r.plan(OLD).unwrap_err().to_string();
        assert!(err.contains("aws"), "{err}");
    }

    #[test]
    fn resolve_principal_parses_the_recorded_fixture() {
        let fake = happy();
        let cli = AwsCli::with_program(fake.dir.path().join("aws"));
        assert_eq!(cli.resolve_principal(OLD).unwrap(), "bob");
    }

    #[test]
    fn last_used_parses_time_service_and_region() {
        let fake = happy();
        let r = fake.rotator();
        let plan = r.plan(OLD).unwrap();
        let used = r.last_used(&plan).unwrap().unwrap();
        assert_eq!(used.at, 1_793_181_600);
        assert_eq!(
            (used.service.as_str(), used.region.as_str()),
            ("s3", "us-east-1")
        );
    }

    #[test]
    fn last_used_is_none_for_a_never_used_key() {
        let never =
            r#"{"UserName":"bob","AccessKeyLastUsed":{"ServiceName":"N/A","Region":"N/A"}}"#;
        let fake = Fake::new(
            &[
                ("get-access-key-last-used", never),
                ("list-access-keys", ONE_KEY),
            ],
            &[],
        );
        let r = fake.rotator();
        let plan = r.plan(OLD).unwrap();
        assert_eq!(r.last_used(&plan).unwrap(), None);
    }

    #[test]
    fn env_values_pairs_id_and_secret_under_matching_names() {
        let m = MintedCredential {
            key_id: "AKIANEW".into(),
            secret: "S".into(),
        };
        let r = AwsRotator::new();
        assert_eq!(
            r.env_values("AWS_ACCESS_KEY_ID_AB12", &m),
            vec![
                ("AWS_ACCESS_KEY_ID_AB12".to_string(), "AKIANEW".to_string()),
                ("AWS_SECRET_ACCESS_KEY_AB12".to_string(), "S".to_string()),
            ]
        );
        assert_eq!(r.env_values("MY_KEY", &m)[1].0, "MY_KEY_SECRET");
    }
}
