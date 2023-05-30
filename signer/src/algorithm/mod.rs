use crate::{KSError, SigningOption};

pub mod rsa;
pub mod secp256k1;
pub mod bip32_ed25519;

pub trait SecretKey {
    fn from_secret(secret: &[u8]) -> Result<Self, KSError> where Self: Sized;
    fn sign(&self, data: Vec<u8>, signing_option: Option<SigningOption>) -> Result<Vec<u8>, KSError>;
}