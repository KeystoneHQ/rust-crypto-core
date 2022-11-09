use std::array::TryFromSliceError;
use std::convert::Infallible;
use thiserror::Error;
use ring::error::{KeyRejected, Unspecified};

#[derive(Debug, Error)]
pub enum AlgError {
    #[error("key rejected: {0}")]
    KeyRejected(#[from] KeyRejected),

    #[error("ring unspecified: {0}")]
    RingUnspecified(#[from] Unspecified),

    #[error("infallible: {0}")]
    Infallible(#[from] Infallible),

    #[error("TryFromSliceError: {0}")]
    TryFromSliceError(#[from] TryFromSliceError),

    #[error("SecretError: {0}")]
    SecretError(String),
}