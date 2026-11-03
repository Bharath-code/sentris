use super::http::Http;
use super::{Exposure, ExposureProbe, RiskTier};
use crate::error::SentrisError;
use crate::verifier::LiveStatus;
use serde_json::Value;

const WHOAMI_URL: &str = "https://huggingface.co/api/whoami-v2";
const PROVIDER: &str = "HuggingFace";

pub struct HuggingFaceProbe {
    http: Box<dyn Http>,
}

impl HuggingFaceProbe {
    pub fn new(http: Box<dyn Http>) -> Self {
        Self { http }
    }
}

impl ExposureProbe for HuggingFaceProbe {
    fn provider(&self) -> &'static str {
        PROVIDER
    }

    fn probe(&self, secret: &str) -> Result<Exposure, SentrisError> {
        let token = secret.trim();
        let reply = match self.http.get(WHOAMI_URL, token) {
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
                    capabilities: vec!["rejected by HuggingFace (401)".to_string()],
                    tier: RiskTier::Low,
                    measured_usd: None,
                })
            }
            other => {
                return Ok(Exposure::undecided(
                    PROVIDER,
                    format!("HuggingFace API returned status {other}"),
                    RiskTier::Medium,
                ))
            }
        }
        let Ok(body) = serde_json::from_str::<Value>(&reply.body) else {
            return Ok(Exposure::undecided(
                PROVIDER,
                "unparseable HuggingFace whoami response",
                RiskTier::Medium,
            ));
        };
        let role = body["auth"]["accessToken"]["role"]
            .as_str()
            .unwrap_or("read")
            .to_string();
        let org_count = body["orgs"].as_array().map(Vec::len).unwrap_or(0);
        let tier = match (role.as_str(), org_count > 0) {
            ("write" | "admin", true) => RiskTier::Critical,
            ("write" | "admin" | "fineGrained", false) | ("fineGrained", true) => RiskTier::High,
            _ => RiskTier::Medium,
        };
        let capabilities = vec![
            format!("token role: {role}"),
            format!("member of {org_count} HuggingFace organization(s)"),
        ];
        Ok(Exposure {
            provider: PROVIDER.to_string(),
            live: LiveStatus::Active { scopes: vec![role] },
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
    fn write_token_with_orgs_is_critical_and_401_is_revoked() {
        let p = HuggingFaceProbe::new(Box::new(Fake(
            200,
            r#"{"auth":{"accessToken":{"role":"write"}},"orgs":[{"name":"acme"}]}"#,
        )));
        let e = p.probe("hf_fake").unwrap();
        assert_eq!(e.tier, RiskTier::Critical);

        let p401 = HuggingFaceProbe::new(Box::new(Fake(401, "{}")));
        let e401 = p401.probe("hf_fake").unwrap();
        assert_eq!(e401.live, LiveStatus::Revoked);
        assert_eq!(e401.tier, RiskTier::Low);
    }
}
