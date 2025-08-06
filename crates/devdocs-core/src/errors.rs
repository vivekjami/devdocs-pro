use thiserror::Error;

#[derive(Error, Debug)]
pub enum DevDocsError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Body too large: {size} > {limit}")]
    BodyTooLarge { size: usize, limit: usize },

    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

pub type Result<T> = std::result::Result<T, DevDocsError>;
