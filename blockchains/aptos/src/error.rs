use thiserror::Error;

#[derive(Error, Debug)]
pub enum AptosError {
    #[error("aptos transaction parse failed, reason: `{0}`")]
    ParseFailed(String),
    #[error("aptos transaction serialize failed, reason: `{0}`")]
    SerializeFailed(String),
}

pub type Result<T> = std::result::Result<T, AptosError>;