use bitcoin::bech32;
use bitcoin::bech32::Error;
use cardano_serialization_lib::error::DeserializeError;
use ed25519_bip32_core::DerivationError;
use thiserror;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CardanoError {
    #[error("meet error when encoding address: {0}")]
    AddressEncodingError(String),
    #[error("meet error when derive cardano key, {0}")]
    DerivationError(String),
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("unsupported transaction type: {0}")]
    UnsupportedTransaction(String),
    #[error("error occurs when signing cardano transaction: {0}")]
    SigningFailed(String),
}

pub type R<T> = Result<T, CardanoError>;

impl From<bech32::Error> for CardanoError {
    fn from(value: Error) -> Self {
        Self::AddressEncodingError(value.to_string())
    }
}

impl From<DeserializeError> for CardanoError {
    fn from(value: DeserializeError) -> Self {
        Self::InvalidTransaction(value.to_string())
    }
}

impl From<DerivationError> for CardanoError {
    fn from(value: DerivationError) -> Self {
        Self::DerivationError(value.to_string())
    }
}
