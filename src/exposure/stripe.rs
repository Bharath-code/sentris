use super::http::Http;
use super::{Exposure, ExposureProbe, RiskTier};
use crate::error::SentrisError;
use crate::verifier::LiveStatus;
use serde_json::Value;

const BALANCE_URL: &str = "https://api.stripe.com/v1/balance";
const PROVIDER: &str = "Stripe";
const NOT_ENUMERATED: &str = "other permissions of a restricted key are not enumerated";

pub struct StripeProbe {
    http: Box<dyn Http>,
}

impl StripeProbe {
    pub fn new(http: Box<dyn Http>) -> Self {
        Self { http }
    }
}

impl ExposureProbe for StripeProbe {
    fn provider(&self) -> &'static str {
        PROVIDER
    }

    fn probe(&self, secret: &str) -> Result<Exposure, SentrisError> {
        let key = secret.trim();
        let restricted = key.starts_with("rk_");
        let test_prefix = key.starts_with("sk_test_") || key.starts_with("rk_test_");
        let reply = match self.http.get(BALANCE_URL, key) {
            Ok(r) => r,
            Err(e) => {
                return Ok(Exposure::undecided(
                    PROVIDER,
                    e.to_string(),
                    RiskTier::Medium,
                ))
            }
        };
        Ok(match reply.status {
            200 => readable(&reply.body, restricted, test_prefix),
            401 => Exposure {
                provider: PROVIDER.to_string(),
                live: LiveStatus::Revoked,
                capabilities: vec!["rejected by Stripe (401)".to_string()],
                tier: RiskTier::Low,
                measured_usd: None,
            },
            // Only a restricted key answers 403 for a missing permission; anything else is not evidence about this key.
            403 if restricted => Exposure {
                provider: PROVIDER.to_string(),
                live: LiveStatus::Active { scopes: Vec::new() },
                capabilities: vec![
                    "restricted, balance not readable".to_string(),
                    NOT_ENUMERATED.to_string(),
                ],
                tier: if test_prefix {
                    RiskTier::Low
                } else {
                    RiskTier::Medium
                },
                measured_usd: None,
            },
            other => Exposure::undecided(
                PROVIDER,
                format!("Stripe API returned status {other}"),
                RiskTier::Medium,
            ),
        })
    }
}

fn readable(body: &str, restricted: bool, test_prefix: bool) -> Exposure {
    let body: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let live_mode = body["livemode"].as_bool().unwrap_or(!test_prefix);
    let mut capabilities = vec![
        if live_mode { "live mode" } else { "test mode" }.to_string(),
        "balance readable".to_string(),
    ];
    capabilities.push(if restricted {
        format!("restricted key; {NOT_ENUMERATED}")
    } else {
        "unrestricted secret key: full API access".to_string()
    });
    let tier = match (live_mode, restricted) {
        (false, _) => RiskTier::Low,
        (true, true) => RiskTier::High,
        (true, false) => RiskTier::Critical,
    };
    let (measured_usd, other) = available(&body);
    if !other.is_empty() {
        capabilities.push(format!("available balance also in: {}", other.join(", ")));
    }
    Exposure {
        provider: PROVIDER.to_string(),
        live: LiveStatus::Active { scopes: Vec::new() },
        capabilities,
        tier,
        measured_usd,
    }
}

/// USD available balance as Stripe reported it (`None` when it listed no USD entry) and the other currencies it listed.
fn available(body: &Value) -> (Option<f64>, Vec<String>) {
    let mut usd: Option<i64> = None;
    let mut other = Vec::new();
    for entry in body["available"].as_array().into_iter().flatten() {
        let (Some(amount), Some(currency)) = (entry["amount"].as_i64(), entry["currency"].as_str())
        else {
            continue;
        };
        if currency.eq_ignore_ascii_case("usd") {
            usd = Some(usd.unwrap_or(0).saturating_add(amount));
        } else if !other.iter().any(|c| c == currency) {
            other.push(currency.to_ascii_lowercase());
        }
    }
    (usd.map(|cents| cents as f64 / 100.0), other)
}

#[cfg(test)]
mod tests {
    use super::super::http::Reply;
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    const LIVE: &str = include_str!("../../tests/fixtures/exposure/stripe_balance_live.json");
    const TEST: &str = include_str!("../../tests/fixtures/exposure/stripe_balance_test.json");
    const EUR: &str = include_str!("../../tests/fixtures/exposure/stripe_balance_eur_only.json");
    const FORBIDDEN: &str =
        include_str!("../../tests/fixtures/exposure/stripe_restricted_403.json");
    const INVALID: &str = include_str!("../../tests/fixtures/exposure/stripe_invalid_401.json");

    type Seen = Rc<RefCell<Vec<(String, String)>>>;

    struct Fake {
        reply: Option<(u16, &'static str)>,
        seen: Seen,
    }

    impl Http for Fake {
        fn get(&self, url: &str, bearer: &str) -> Result<Reply, SentrisError> {
            self.seen
                .borrow_mut()
                .push((url.to_string(), bearer.to_string()));
            match self.reply {
                Some((status, body)) => Ok(Reply {
                    status,
                    headers: vec![],
                    body: body.to_string(),
                }),
                None => Err(SentrisError::Scan("Network probe failed: down".to_string())),
            }
        }
    }

    fn probe(key: &str, reply: Option<(u16, &'static str)>) -> (Exposure, Seen) {
        let seen: Seen = Rc::default();
        let p = StripeProbe::new(Box::new(Fake {
            reply,
            seen: seen.clone(),
        }));
        (p.probe(key).unwrap(), seen)
    }

    const SK: &str = "sk_live_FAKEFAKEFAKEFAKEFAKE";
    const RK: &str = "rk_live_FAKEFAKEFAKEFAKEFAKE";

    #[test]
    fn full_secret_key_with_readable_balance_is_critical_and_reports_the_balance() {
        let (e, seen) = probe(SK, Some((200, LIVE)));
        assert_eq!(e.tier, RiskTier::Critical);
        assert!(matches!(e.live, LiveStatus::Active { .. }));
        assert_eq!(e.measured_usd, Some(12345.67));
        assert!(e.capabilities.iter().any(|c| c == "live mode"));
        let seen = seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0], (BALANCE_URL.to_string(), SK.to_string()));
    }

    #[test]
    fn test_mode_key_is_low() {
        let (e, _) = probe("sk_test_FAKEFAKEFAKEFAKEFAKE", Some((200, TEST)));
        assert_eq!(e.tier, RiskTier::Low);
        assert!(e.capabilities.iter().any(|c| c == "test mode"));
        assert_eq!(e.measured_usd, Some(0.0));
    }

    #[test]
    fn restricted_key_with_readable_balance_is_high_not_critical() {
        let (e, _) = probe(RK, Some((200, LIVE)));
        assert_eq!(e.tier, RiskTier::High);
        assert!(e
            .capabilities
            .iter()
            .any(|c| c.starts_with("restricted key")));
    }

    #[test]
    fn restricted_key_403_is_live_with_unreadable_balance() {
        let (e, _) = probe(RK, Some((403, FORBIDDEN)));
        assert!(matches!(e.live, LiveStatus::Active { .. }));
        assert_eq!(e.tier, RiskTier::Medium);
        assert_eq!(e.measured_usd, None);
        assert!(e
            .capabilities
            .iter()
            .any(|c| c == "restricted, balance not readable"));
    }

    #[test]
    fn unrestricted_key_403_is_not_evidence() {
        let (e, _) = probe(SK, Some((403, FORBIDDEN)));
        assert!(matches!(e.live, LiveStatus::Unverified(_)));
    }

    #[test]
    fn rejected_key_is_revoked_and_low() {
        let (e, _) = probe(SK, Some((401, INVALID)));
        assert_eq!(e.live, LiveStatus::Revoked);
        assert_eq!(e.tier, RiskTier::Low);
    }

    #[test]
    fn other_status_and_transport_failure_are_unverified_not_safe() {
        let (e, _) = probe(SK, Some((500, "")));
        assert!(matches!(&e.live, LiveStatus::Unverified(m) if m.contains("500")));
        let (e, _) = probe(SK, None);
        assert!(matches!(&e.live, LiveStatus::Unverified(m) if m.contains("down")));
    }

    #[test]
    fn measured_usd_is_none_when_stripe_listed_no_usd_balance() {
        let (e, _) = probe(SK, Some((200, EUR)));
        assert_eq!(e.measured_usd, None);
        assert!(e.capabilities.iter().any(|c| c.contains("eur")));
    }

    #[test]
    fn exposure_never_contains_the_secret() {
        for reply in [Some((200, LIVE)), Some((401, INVALID)), None] {
            let (e, _) = probe(SK, reply);
            assert!(!serde_json::to_string(&e).unwrap().contains(SK));
        }
    }
}
