use alloc::string::String;
use thiserror_no_std::Error;

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

}