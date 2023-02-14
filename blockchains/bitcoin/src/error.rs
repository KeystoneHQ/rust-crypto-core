use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum BitcoinError {
    #[error("bitcoin address calculation failed, reason: `{0}`")]
    AddressCalculationFailed(String),
}

pub type Result<T> = std::result::Result<T, BitcoinError>;
