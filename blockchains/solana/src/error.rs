use std::error::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SolanaError {
    #[error("Solana transaction parse failed, reason: `{0}`")]
    ParseFailed(String),

    #[error("Program `{0}` is not supported yet")]
    UnsupportedProgram(String),

    #[error("Meet invalid data when reading `{0}`")]
    InvalidData(String),

    #[error("Error occurred when parsing program instruction, reason: `{0}`")]
    ProgramError(String),

    #[error("Could not found account for `{0}`")]
    AccountNotFound(String),

    #[error("Unknown program instruction")]
    UnknownInstruction
}

pub type Result<T> = std::result::Result<T, SolanaError>;