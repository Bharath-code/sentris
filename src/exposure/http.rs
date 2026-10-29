use crate::error::SentrisError;
use std::io::Read;
use std::time::Duration;

const MAX_BODY: u64 = 64 * 1024;

pub struct Reply {
    pub status: u16,
    /// Header names lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// GET-only on purpose: a probe cannot change provider state through this seam.
pub trait Http {
    /// A non-2xx status is a `Reply`; only a transport failure is an `Err`.
    fn get(&self, url: &str, bearer: &str) -> Result<Reply, SentrisError>;
}

pub struct UreqHttp;

impl Http for UreqHttp {
    fn get(&self, url: &str, bearer: &str) -> Result<Reply, SentrisError> {
        let response = ureq::get(url)
            .set("Authorization", &format!("Bearer {bearer}"))
            .set("User-Agent", "Sentris-Security-Scanner/0.1.0")
            .timeout(Duration::from_secs(5))
            .call();
        match response {
            Ok(r) | Err(ureq::Error::Status(_, r)) => Ok(reply_of(r)),
            Err(ureq::Error::Transport(t)) => {
                Err(SentrisError::Scan(format!("Network probe failed: {t}")))
            }
        }
    }
}

fn reply_of(r: ureq::Response) -> Reply {
    let status = r.status();
    let headers = r
        .headers_names()
        .into_iter()
        .filter_map(|n| {
            r.header(&n)
                .map(|v| (n.to_ascii_lowercase(), v.to_string()))
        })
        .collect();
    let mut body = String::new();
    // A truncated or non-UTF-8 body only costs detail; the status already decided the verdict.
    let _ = r.into_reader().take(MAX_BODY).read_to_string(&mut body);
    Reply {
        status,
        headers,
        body,
    }
}
