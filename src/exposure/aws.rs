use super::{Exposure, ExposureProbe, RiskTier};
use crate::error::SentrisError;
use crate::rotator::aws::AwsCli;
use crate::verifier::LiveStatus;

const PROVIDER: &str = "AWS";
const LIMITS: &str =
    "permission boundaries, SCPs, session policies and inline policy contents are not evaluated";

/// Reads IAM policy attachments of the key's owning user through the caller's ambient credentials. The probed key is only ever an argument, never used to sign.
pub struct AwsProbe {
    cli: AwsCli,
    env_key_id: Option<String>,
}

impl AwsProbe {
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

    fn list(&self, args: &[&str], field: &str, item: &str) -> Result<Vec<String>, SentrisError> {
        let v = self.cli.json(args)?;
        Ok(v[field]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| {
                if item.is_empty() {
                    e.as_str()
                } else {
                    e[item].as_str()
                }
            })
            .map(str::to_string)
            .collect())
    }

    fn inspect(&self, key_id: &str) -> Result<Exposure, SentrisError> {
        let user = self.cli.resolve_principal(key_id)?;
        let keys = self.cli.json(&[
            "iam",
            "list-access-keys",
            "--user-name",
            &user,
            "--output",
            "json",
        ])?;
        let status = keys["AccessKeyMetadata"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|k| k["AccessKeyId"].as_str() == Some(key_id))
            .and_then(|k| k["Status"].as_str())
            .ok_or_else(|| {
                SentrisError::Scan("key not listed under its owning IAM user".to_string())
            })?;
        if status != "Active" {
            return Ok(Exposure {
                provider: PROVIDER.to_string(),
                live: LiveStatus::Revoked,
                capabilities: vec![format!("key is {status} in IAM")],
                tier: RiskTier::Low,
                measured_usd: None,
            });
        }

        let mut arns = self.list(
            &[
                "iam",
                "list-attached-user-policies",
                "--user-name",
                &user,
                "--output",
                "json",
            ],
            "AttachedPolicies",
            "PolicyArn",
        )?;
        let mut inline = self
            .list(
                &[
                    "iam",
                    "list-user-policies",
                    "--user-name",
                    &user,
                    "--output",
                    "json",
                ],
                "PolicyNames",
                "",
            )?
            .len();
        let groups = self.list(
            &[
                "iam",
                "list-groups-for-user",
                "--user-name",
                &user,
                "--output",
                "json",
            ],
            "Groups",
            "GroupName",
        )?;
        for g in &groups {
            arns.extend(self.list(
                &[
                    "iam",
                    "list-attached-group-policies",
                    "--group-name",
                    g,
                    "--output",
                    "json",
                ],
                "AttachedPolicies",
                "PolicyArn",
            )?);
            inline += self
                .list(
                    &[
                        "iam",
                        "list-group-policies",
                        "--group-name",
                        g,
                        "--output",
                        "json",
                    ],
                    "PolicyNames",
                    "",
                )?
                .len();
        }
        Ok(Exposure {
            provider: PROVIDER.to_string(),
            live: LiveStatus::Active { scopes: Vec::new() },
            capabilities: capabilities(&arns, inline, groups.len()),
            tier: tier_for(&arns, inline),
            measured_usd: None,
        })
    }
}

impl Default for AwsProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl ExposureProbe for AwsProbe {
    fn provider(&self) -> &'static str {
        PROVIDER
    }

    fn probe(&self, key_id: &str) -> Result<Exposure, SentrisError> {
        let key_id = key_id.trim();
        if self.env_key_id.as_deref() == Some(key_id) {
            return Err(SentrisError::Refused(
                "Your AWS CLI is signing with the key being probed; use a different admin profile"
                    .to_string(),
            ));
        }
        match self.inspect(key_id) {
            Err(refused @ SentrisError::Refused(_)) => Err(refused),
            Err(e) => Ok(Exposure::undecided(
                PROVIDER,
                e.to_string(),
                RiskTier::Medium,
            )),
            Ok(exposure) => Ok(exposure),
        }
    }
}

/// An AWS-managed policy has the literal account segment `aws`; a customer policy that merely shares the name does not.
fn is_aws_managed(arn: &str, name: &str) -> bool {
    let mut parts = arn.split(':');
    parts.nth(4) == Some("aws") && parts.next() == Some(&format!("policy/{name}"))
}

fn tier_for(arns: &[String], inline: usize) -> RiskTier {
    let any = |name| arns.iter().any(|a| is_aws_managed(a, name));
    if any("AdministratorAccess") || any("IAMFullAccess") {
        RiskTier::Critical
    } else if any("PowerUserAccess") {
        RiskTier::High
    } else if !arns.is_empty() || inline > 0 {
        RiskTier::Medium
    } else {
        RiskTier::Low
    }
}

fn capabilities(arns: &[String], inline: usize, groups: usize) -> Vec<String> {
    let mut out: Vec<String> = arns
        .iter()
        .map(|a| {
            let name = a.rsplit('/').next().unwrap_or(a);
            let kind = if a.split(':').nth(4) == Some("aws") {
                "AWS managed"
            } else {
                "customer managed"
            };
            format!("attached policy {name} ({kind})")
        })
        .collect();
    if arns.is_empty() && inline == 0 {
        out.push("no policies attached to the user or its groups".to_string());
    }
    if inline > 0 {
        out.push(format!("{inline} inline policy(ies) not inspected"));
    }
    if groups > 0 {
        out.push(format!("member of {groups} group(s)"));
    }
    out.push(format!("limits: {LIMITS}"));
    out
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const KEY: &str = "AKIAJ5Q7X2M9R4T6W8YB";

    macro_rules! fx {
        ($name:literal) => {
            include_str!(concat!("../../tests/fixtures/exposure/", $name))
        };
    }

    /// Replays `<subcommand>.out` from a temp dir and logs every argv.
    struct Shim {
        dir: tempfile::TempDir,
    }

    impl Shim {
        fn new(replies: &[(&str, &str)]) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            for (sub, body) in replies {
                fs::write(dir.path().join(format!("{sub}.out")), body).expect("reply");
            }
            let d = dir.path().display();
            let script = format!(
                "#!/bin/sh\necho \"ARGV: $@\" >> {d}/calls.log\nif [ -f \"{d}/$2.out\" ]; then cat \"{d}/$2.out\"; exit 0; fi\necho \"NoSuchEntity\" >&2\nexit 254\n"
            );
            let bin = dir.path().join("aws");
            fs::write(&bin, script).expect("shim");
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).expect("chmod");
            Self { dir }
        }

        fn probe(&self) -> AwsProbe {
            AwsProbe::with_cli(AwsCli::with_program(self.dir.path().join("aws")))
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

    fn user_with(attached: &'static str, inline: &'static str, groups: &'static str) -> Shim {
        Shim::new(&[
            ("get-access-key-last-used", fx!("aws_last_used.json")),
            ("list-access-keys", fx!("aws_list_access_keys_active.json")),
            ("list-attached-user-policies", attached),
            ("list-user-policies", inline),
            ("list-groups-for-user", groups),
            (
                "list-attached-group-policies",
                fx!("aws_attached_power_group.json"),
            ),
            ("list-group-policies", fx!("aws_names_none.json")),
        ])
    }

    fn none() -> (&'static str, &'static str, &'static str) {
        (
            fx!("aws_attached_none.json"),
            fx!("aws_names_none.json"),
            fx!("aws_groups_none.json"),
        )
    }

    #[test]
    fn attached_administrator_access_is_critical() {
        let (_, inline, groups) = none();
        let shim = user_with(fx!("aws_attached_admin.json"), inline, groups);
        let e = shim.probe().probe(KEY).unwrap();
        assert_eq!(e.tier, RiskTier::Critical);
        assert!(matches!(e.live, LiveStatus::Active { .. }));
        assert!(e
            .capabilities
            .contains(&"attached policy AdministratorAccess (AWS managed)".to_string()));
        assert_eq!(e.measured_usd, None);
    }

    #[test]
    fn power_user_through_a_group_is_high() {
        let (attached, inline, _) = none();
        let shim = user_with(attached, inline, fx!("aws_groups_one.json"));
        let e = shim.probe().probe(KEY).unwrap();
        assert_eq!(e.tier, RiskTier::High);
        assert!(e.capabilities.iter().any(|c| c == "member of 1 group(s)"));
    }

    #[test]
    fn customer_policy_named_like_the_admin_policy_is_not_critical() {
        let (_, inline, groups) = none();
        let shim = user_with(fx!("aws_attached_lookalike.json"), inline, groups);
        let e = shim.probe().probe(KEY).unwrap();
        assert_eq!(e.tier, RiskTier::Medium);
        assert!(e
            .capabilities
            .iter()
            .any(|c| c.contains("customer managed")));
    }

    #[test]
    fn no_policies_is_low_and_the_limits_are_stated() {
        let (attached, inline, groups) = none();
        let e = user_with(attached, inline, groups)
            .probe()
            .probe(KEY)
            .unwrap();
        assert_eq!(e.tier, RiskTier::Low);
        assert!(e
            .capabilities
            .last()
            .is_some_and(|c| c.starts_with("limits:")));
    }

    #[test]
    fn inline_policies_raise_to_medium_and_are_flagged_uninspected() {
        let (attached, _, groups) = none();
        let e = user_with(attached, fx!("aws_names_one.json"), groups)
            .probe()
            .probe(KEY)
            .unwrap();
        assert_eq!(e.tier, RiskTier::Medium);
        assert!(e.capabilities.iter().any(|c| c.contains("not inspected")));
    }

    #[test]
    fn inactive_key_is_revoked_low_with_no_policy_calls() {
        let shim = Shim::new(&[
            ("get-access-key-last-used", fx!("aws_last_used.json")),
            (
                "list-access-keys",
                fx!("aws_list_access_keys_inactive.json"),
            ),
        ]);
        let e = shim.probe().probe(KEY).unwrap();
        assert_eq!(e.live, LiveStatus::Revoked);
        assert_eq!(e.tier, RiskTier::Low);
        assert!(shim.calls().iter().all(|c| !c.contains("policies")));
    }

    #[test]
    fn unknown_key_is_unverified_not_safe() {
        let shim = Shim::new(&[]);
        let e = shim.probe().probe(KEY).unwrap();
        assert!(matches!(e.live, LiveStatus::Unverified(_)));
    }

    #[test]
    fn refuses_when_ambient_key_is_the_probed_key_with_zero_calls() {
        let shim = Shim::new(&[("get-access-key-last-used", fx!("aws_last_used.json"))]);
        let probe = shim.probe().with_env_key_id(Some(KEY.to_string()));
        assert!(matches!(probe.probe(KEY), Err(SentrisError::Refused(_))));
        assert!(shim.calls().is_empty());
    }

    #[test]
    fn only_get_list_and_describe_verbs_are_ever_called() {
        let (_, inline, _) = none();
        let shim = user_with(
            fx!("aws_attached_admin.json"),
            inline,
            fx!("aws_groups_one.json"),
        );
        shim.probe().probe(KEY).unwrap();
        let calls = shim.calls();
        assert!(calls.len() >= 6, "{calls:?}");
        for c in &calls {
            let verb = c
                .trim_start_matches("ARGV: ")
                .split(' ')
                .nth(1)
                .unwrap_or("");
            assert!(
                ["get-", "list-", "describe-"]
                    .iter()
                    .any(|p| verb.starts_with(p)),
                "{c}"
            );
        }
    }

    #[test]
    fn argv_names_the_key_id_only_and_never_signs_with_it() {
        let (attached, inline, groups) = none();
        let shim = user_with(attached, inline, groups);
        shim.probe().probe(KEY).unwrap();
        assert!(shim
            .calls()
            .iter()
            .all(|c| !c.contains("--secret") && !c.contains("AWS_SECRET")));
    }
}
