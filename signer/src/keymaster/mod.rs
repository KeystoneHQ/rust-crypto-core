use crate::error::KSError;
use crate::algorithm;
pub(crate) mod se;
pub(crate) mod local;
pub(crate) mod hash_wraper;


pub enum EntropyLength {
    Short(u32) ,
    Long(u32),
}

pub enum SigningAlgorithm {
    Secp256k1,
    Secp256R1,
    Ed25519,
    SR25519,
    RSA,
}

pub trait KeyMaster {
    fn generate_entropy(&self, length: EntropyLength) -> Result<Vec<u8>, KSError>;

    fn get_public_key(&self, mnemonic_id: u8, password: Option<String>, algo: SigningAlgorithm, derivation_path: Option<String>) -> Result<Vec<u8>, KSError>;

    fn sign_data(
        &self,
        mnemonic_id: u8,
        password: String,
        data: Vec<u8>,
        algo: SigningAlgorithm,
        derivation_path: String,
    ) -> Result<Vec<u8>, KSError>;

    fn get_version(&self) -> Result<Vec<u8>, KSError>;
}
