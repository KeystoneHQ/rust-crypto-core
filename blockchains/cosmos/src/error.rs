use thiserror::Error;

#[derive(Error, Debug)]
pub enum CosmosError {
    #[error("cosmos transaction parse failed, reason: `{0}`")]
    ParseFailed(String),
    #[error("cosmos transaction serialize failed, reason: `{0}`")]
    SerializeFailed(String),
}

pub type Result<T> = std::result::Result<T, CosmosError>;