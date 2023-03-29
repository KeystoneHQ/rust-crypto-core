use openssl::sign::RsaPssSaltlen;
use crate::error::KSError;
use crate::algorithm;
pub(crate) mod se;
pub(crate) mod local;
pub(crate) mod hash_wraper;


pub enum EntropyLength {
    Short,
    Long,
}

pub enum SigningAlgorithm {
    Secp256k1,
    Secp256R1,
    Ed25519,
    SR25519,
    RSA,
}

pub enum SigningOption {
    RSA { salt_len: i32 }
}

pub trait KeyMaster {
    fn get_rsa_public_key(&self, mnemonic_id: u8, password: String) -> Result<Vec<u8>, KSError>;

    fn sign_data(
        &self,
        mnemonic_id: u8,
        password: String,
        data: Vec<u8>,
        algo: SigningAlgorithm,
        derivation_path: String,
        signing_option: Option<SigningOption>
    ) -> Result<Vec<u8>, KSError>;

    fn get_version(&self) -> Result<Vec<u8>, KSError>;
}
