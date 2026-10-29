use super::http::Http;
use super::{Exposure, ExposureProbe, RiskTier};
use crate::error::SentrisError;
use crate::verifier::LiveStatus;
use serde_json::Value;

const USER_URL: &str = "https://api.github.com/user";
const ORGS_URL: &str = "https://api.github.com/user/orgs?per_page=100";
const PROVIDER: &str = "GitHub";
const ORG_PAGE: usize = 100;

pub struct GithubProbe {
    http: Box<dyn Http>,
}

impl GithubProbe {
    pub fn new(http: Box<dyn Http>) -> Self {
        Self { http }
    }

    /// Organizations this token can list. `None` when the call failed. Private memberships need `read:org`, so the count is a lower bound.
    fn org_count(&self, token: &str) -> Option<usize> {
        let reply = self.http.get(ORGS_URL, token).ok()?;
        if reply.status != 200 {
            return None;
        }
        serde_json::from_str::<Value>(&reply.body)
            .ok()?
            .as_array()
            .map(Vec::len)
    }
}

impl ExposureProbe for GithubProbe {
    fn provider(&self) -> &'static str {
        PROVIDER
    }

    fn probe(&self, secret: &str) -> Result<Exposure, SentrisError> {
        let token = secret.trim();
        let user = match self.http.get(USER_URL, token) {
            Ok(r) => r,
            Err(e) => {
                return Ok(Exposure::undecided(
                    PROVIDER,
                    e.to_string(),
                    RiskTier::Medium,
                ))
            }
        };
        match user.status {
            200 => {}
            401 => {
                return Ok(Exposure {
                    provider: PROVIDER.to_string(),
                    live: LiveStatus::Revoked,
                    capabilities: vec!["rejected by GitHub (401)".to_string()],
                    tier: RiskTier::Low,
                    measured_usd: None,
                })
            }
            other => {
                return Ok(Exposure::undecided(
                    PROVIDER,
                    format!("GitHub API returned status {other}"),
                    RiskTier::Medium,
                ))
            }
        }
        // Classic and OAuth tokens list their scopes in this header; fine-grained and app tokens send none.
        let scopes: Option<Vec<String>> = user.header("x-oauth-scopes").map(|h| {
            h.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        });
        let orgs = self.org_count(token);
        Ok(Exposure {
            provider: PROVIDER.to_string(),
            live: LiveStatus::Active {
                scopes: scopes.clone().unwrap_or_default(),
            },
            capabilities: capabilities(scopes.as_deref(), orgs),
            tier: tier_for(scopes.as_deref(), orgs),
            measured_usd: None,
        })
    }
}

fn tier_for(scopes: Option<&[String]>, orgs: Option<usize>) -> RiskTier {
    let Some(scopes) = scopes else {
        return RiskTier::Medium;
    };
    let has = |s: &str| scopes.iter().any(|x| x == s);
    if has("admin:org")
        || has("admin:enterprise")
        || has("delete_repo")
        || (has("repo") && orgs.unwrap_or(0) > 0)
    {
        RiskTier::Critical
    } else if has("repo")
        || has("workflow")
        || has("write:packages")
        || has("delete:packages")
        || has("admin:repo_hook")
    {
        RiskTier::High
    } else if scopes.is_empty() {
        RiskTier::Low
    } else {
        RiskTier::Medium
    }
}

fn capabilities(scopes: Option<&[String]>, orgs: Option<usize>) -> Vec<String> {
    let mut out = match scopes {
        None => vec![
            "fine-grained or app token: GitHub does not expose its permissions to the API"
                .to_string(),
        ],
        Some([]) => vec!["classic token with no scopes (public data only)".to_string()],
        Some(s) => s.iter().map(|x| format!("scope {x}")).collect(),
    };
    out.push(match orgs {
        Some(n) if n >= ORG_PAGE => format!("member of at least {n} organizations"),
        Some(n) => format!("member of {n} organization(s) visible to this token (private memberships need read:org)"),
        None => "organization membership not readable with this token".to_string(),
    });
    out
}

#[cfg(test)]
mod tests {
    use super::super::http::Reply;
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    const USER: &str = include_str!("../../tests/fixtures/exposure/github_user.json");
    const ORGS: &str = include_str!("../../tests/fixtures/exposure/github_orgs.json");
    const NO_ORGS: &str = include_str!("../../tests/fixtures/exposure/github_orgs_empty.json");

    type Seen = Rc<RefCell<Vec<String>>>;

    struct Fake {
        /// `None` for the scopes header means the header is absent.
        scopes: Option<&'static str>,
        user_status: u16,
        orgs: (u16, &'static str),
        seen: Seen,
    }

    impl Http for Fake {
        fn get(&self, url: &str, _bearer: &str) -> Result<Reply, SentrisError> {
            self.seen.borrow_mut().push(url.to_string());
            if url == USER_URL {
                let headers = self
                    .scopes
                    .map(|s| vec![("x-oauth-scopes".to_string(), s.to_string())])
                    .unwrap_or_default();
                return Ok(Reply {
                    status: self.user_status,
                    headers,
                    body: USER.to_string(),
                });
            }
            Ok(Reply {
                status: self.orgs.0,
                headers: vec![],
                body: self.orgs.1.to_string(),
            })
        }
    }

    const TOKEN: &str = concat!("ghp_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE");

    fn probe(
        scopes: Option<&'static str>,
        status: u16,
        orgs: (u16, &'static str),
    ) -> (Exposure, Seen) {
        let seen: Seen = Rc::default();
        let p = GithubProbe::new(Box::new(Fake {
            scopes,
            user_status: status,
            orgs,
            seen: seen.clone(),
        }));
        (p.probe(TOKEN).unwrap(), seen)
    }

    #[test]
    fn repo_scope_plus_org_membership_is_critical() {
        let (e, seen) = probe(Some("repo, read:org"), 200, (200, ORGS));
        assert_eq!(e.tier, RiskTier::Critical);
        assert!(e.capabilities.iter().any(|c| c == "scope repo"));
        assert!(e
            .capabilities
            .iter()
            .any(|c| c.starts_with("member of 2 organization")));
        assert_eq!(*seen.borrow(), [USER_URL, ORGS_URL]);
    }

    #[test]
    fn repo_scope_without_orgs_is_high() {
        let (e, _) = probe(Some("repo"), 200, (200, NO_ORGS));
        assert_eq!(e.tier, RiskTier::High);
    }

    #[test]
    fn org_or_repo_deletion_scopes_are_critical_on_their_own() {
        for s in ["admin:org", "delete_repo", "admin:enterprise"] {
            let (e, _) = probe(Some(s), 200, (200, NO_ORGS));
            assert_eq!(e.tier, RiskTier::Critical, "{s}");
        }
    }

    #[test]
    fn read_only_scopes_are_medium_and_no_scopes_is_low() {
        let (e, _) = probe(Some("read:user, user:email"), 200, (200, NO_ORGS));
        assert_eq!(e.tier, RiskTier::Medium);
        let (e, _) = probe(Some(""), 200, (200, NO_ORGS));
        assert_eq!(e.tier, RiskTier::Low);
    }

    #[test]
    fn token_without_scope_header_is_medium_and_says_why() {
        let (e, _) = probe(None, 200, (200, NO_ORGS));
        assert_eq!(e.tier, RiskTier::Medium);
        assert!(e.capabilities[0].contains("does not expose"));
    }

    #[test]
    fn unreadable_org_list_still_classifies_and_says_so() {
        let (e, _) = probe(Some("repo"), 200, (403, "{}"));
        assert_eq!(e.tier, RiskTier::High);
        assert!(e.capabilities.iter().any(|c| c.contains("not readable")));
    }

    #[test]
    fn rejected_token_is_revoked_low_and_skips_the_org_call() {
        let (e, seen) = probe(None, 401, (200, ORGS));
        assert_eq!(e.live, LiveStatus::Revoked);
        assert_eq!(e.tier, RiskTier::Low);
        assert_eq!(*seen.borrow(), [USER_URL]);
    }

    #[test]
    fn other_status_is_unverified_not_safe() {
        let (e, _) = probe(None, 429, (200, ORGS));
        assert!(matches!(&e.live, LiveStatus::Unverified(m) if m.contains("429")));
    }

    #[test]
    fn exposure_never_contains_the_token() {
        let (e, _) = probe(Some("repo"), 200, (200, ORGS));
        assert!(!serde_json::to_string(&e).unwrap().contains(TOKEN));
    }
}
