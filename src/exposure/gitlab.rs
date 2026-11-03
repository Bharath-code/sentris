use super::http::Http;
use super::{Exposure, ExposureProbe, RiskTier};
use crate::error::SentrisError;
use crate::verifier::LiveStatus;
use serde_json::Value;

const PAT_SELF_URL: &str = "https://gitlab.com/api/v4/personal_access_tokens/self";
const PROVIDER: &str = "GitLab";

pub struct GitlabProbe {
    http: Box<dyn Http>,
}

impl GitlabProbe {
    pub fn new(http: Box<dyn Http>) -> Self {
        Self { http }
    }
}

impl ExposureProbe for GitlabProbe {
    fn provider(&self) -> &'static str {
        PROVIDER
    }

    fn probe(&self, secret: &str) -> Result<Exposure, SentrisError> {
        let token = secret.trim();
        let reply = match self.http.get(PAT_SELF_URL, token) {
            Ok(r) => r,
            Err(e) => {
                return Ok(Exposure::undecided(
                    PROVIDER,
                    e.to_string(),
                    RiskTier::Medium,
                ))
            }
        };
        match reply.status {
            200 => {}
            401 => {
                return Ok(Exposure {
                    provider: PROVIDER.to_string(),
                    live: LiveStatus::Revoked,
                    capabilities: vec!["rejected by GitLab (401)".to_string()],
                    tier: RiskTier::Low,
                    measured_usd: None,
                })
            }
            other => {
                return Ok(Exposure::undecided(
                    PROVIDER,
                    format!("GitLab API returned status {other}"),
                    RiskTier::Medium,
                ))
            }
        }
        let Ok(body) = serde_json::from_str::<Value>(&reply.body) else {
            return Ok(Exposure::undecided(
                PROVIDER,
                "unparseable GitLab PAT self response",
                RiskTier::Medium,
            ));
        };
        if body["revoked"].as_bool() == Some(true) || body["active"].as_bool() == Some(false) {
            return Ok(Exposure {
                provider: PROVIDER.to_string(),
                live: LiveStatus::Revoked,
                capabilities: vec!["token marked inactive/revoked by GitLab".to_string()],
                tier: RiskTier::Low,
                measured_usd: None,
            });
        }
        let scopes: Vec<String> = body["scopes"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let has = |s: &str| scopes.iter().any(|x| x == s);
        let tier = if has("api") || has("sudo") || has("admin_mode") {
            RiskTier::Critical
        } else if has("write_repository") || has("write_registry") {
            RiskTier::High
        } else {
            RiskTier::Medium
        };
        let capabilities = if scopes.is_empty() {
            vec!["active GitLab PAT (no scopes listed)".to_string()]
        } else {
            scopes.iter().map(|s| format!("scope {s}")).collect()
        };
        Ok(Exposure {
            provider: PROVIDER.to_string(),
            live: LiveStatus::Active { scopes },
            capabilities,
            tier,
            measured_usd: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::http::Reply;
    use super::*;

    struct Fake(u16, &'static str);
    impl Http for Fake {
        fn get(&self, _url: &str, _bearer: &str) -> Result<Reply, SentrisError> {
            Ok(Reply {
                status: self.0,
                headers: vec![],
                body: self.1.to_string(),
            })
        }
    }

    #[test]
    fn api_scope_is_critical_and_revoked_flag_is_low() {
        let p = GitlabProbe::new(Box::new(Fake(
            200,
            r#"{"active":true,"revoked":false,"scopes":["api","read_user"]}"#,
        )));
        let e = p.probe("glpat-fake").unwrap();
        assert_eq!(e.tier, RiskTier::Critical);

        let prev = GitlabProbe::new(Box::new(Fake(
            200,
            r#"{"active":false,"revoked":true,"scopes":["api"]}"#,
        )));
        let erev = prev.probe("glpat-fake").unwrap();
        assert_eq!(erev.live, LiveStatus::Revoked);
        assert_eq!(erev.tier, RiskTier::Low);
    }
}
