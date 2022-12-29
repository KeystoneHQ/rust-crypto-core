//! Errors propagated by library functions.
use std::string::{FromUtf8Error};
use thiserror::Error;
use base64::DecodeError;

/// Errors propagated by library functions.
#[derive(Error, Debug)]
pub enum ArweaveError {
    #[error("base64 decode: {0}")]
    Base64Decode(#[from] DecodeError),
    #[error("from utf8: {0}")]
    FromUtf8(#[from] FromUtf8Error)
}