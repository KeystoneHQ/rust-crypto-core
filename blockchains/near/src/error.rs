use thiserror::Error;

#[derive(Error, Debug)]
pub enum NearError {
    #[error("near transaction parse failed, reason: `{0}`")]
    ParseFailed(String),
    #[error("near transaction serialize failed, reason: `{0}`")]
    SerializeFailed(String),
}

pub type Result<T> = std::result::Result<T, NearError>;