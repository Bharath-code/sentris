use thiserror::Error;

#[derive(Error, Debug)]
pub enum SentrisError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Regex compilation error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Scan error: {0}")]
    Scan(String),

    #[allow(dead_code)]
    #[error("Configuration error: {0}")]
    Config(String),

    #[allow(dead_code)]
    #[error("Webhook error: {0}")]
    Webhook(String),

    #[allow(dead_code)]
    #[error("Audit error: {0}")]
    Audit(String),
}
