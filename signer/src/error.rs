use std::array::TryFromSliceError;
use std::convert::Infallible;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KSError {
    #[error("SerialManagerError:{0}")]
    SerialManagerError(String),

    #[error("SerialManager Timeout")]
    SerialTimeout,

    #[error("TVLError:{0}")]
    TVLError(String),

    #[error("TVLDeseriliazeError")]
    TVLDeseriliazeError,

    #[error("NoneSupportedCommandError")]
    NoneSupportedCommandError,

    #[error("SEError:{0}")]
    SEError(String),

    #[error("GenerateSigningKeyError: {0}")]
    GenerateSigningKeyError(String),

    #[error("RSASignError")]
    RSASignError,

    #[error("RSAVerifyError")]
    RSAVerifyError,

    #[error("SignDataError: {0}")]
    SignDataError(String),

    #[error("WriteSecretError: {0}")]
    WriteSecretError(String),

    #[error("GetPublicKeyError: {0}")]
    GetPublicKeyError(String),
}