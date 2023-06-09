use alloc::string::{String, ToString};
use thiserror::Error;

pub type Result<T> = core::result::Result<T, SuiError>;

#[derive(Error, Debug)]
pub enum SuiError {
    #[error("Bcs Decoding error: {0}")]
    BcsDecodingError(String),
    #[error("Invalid Transaction")]
    InvalidTransaction,
    #[error("sign failed, reason: {0}")]
    SignFailure(String),
    #[error("Invalid hd_Path: {0}")]
    InvalidHDPath(String),
    #[error("KeystoreError: {0}")]
    KeystoreError(String),
    #[error("Invalid Address: {0}")]
    InvalidAddressError(String),
}

impl From<bcs::Error> for SuiError {
    fn from(value: bcs::Error) -> Self {
        SuiError::BcsDecodingError(value.to_string())
    }
}
