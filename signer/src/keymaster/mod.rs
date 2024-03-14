use crate::algorithm;
use crate::error::KSError;
use openssl::sign::RsaPssSaltlen;

pub(crate) mod hash_wraper;
pub(crate) mod local;
pub(crate) mod se;

pub enum EntropyLength {
    Short(u32),
    Long(u32),
}

#[derive(Clone, Copy)]
pub enum SigningAlgorithm {
    Secp256k1,
    Secp256R1,
    Ed25519,
    SR25519,
    RSA,
}

#[derive(Clone, Copy)]
pub enum RSASignType {
    Common,
    ARMessage,
}

#[derive(Clone, Copy)]
pub enum SigningOption {
    RSA { salt_len: i32, sign_type: RSASignType},
    ADA
}

pub trait KeyMaster {
    fn generate_entropy(&self, length: EntropyLength) -> Result<Vec<u8>, KSError>;

    fn setup_ada_root_key(&self, mnemonic_id: u8, password: String, passphrase: String) -> Result<bool, KSError>;

    fn get_ada_extended_public_key(&self, mnemonic_id: u8, password: String, path: String) -> Result<String, KSError>;

    fn get_rsa_public_key(&self, mnemonic_id: u8, password: String) -> Result<Vec<u8>, KSError>;

    fn get_ada_root_key(&self, mnemonic_id: u8, password: Vec<u8>) -> Result<Vec<u8>, KSError>;

    fn set_ada_root_key(
        &self,
        mnemonic_id: u8,
        password: String,
        secret: Vec<u8>,
    ) -> Result<bool, KSError>;

    fn sign_data(
        &self,
        mnemonic_id: u8,
        password: String,
        data: Vec<u8>,
        algo: SigningAlgorithm,
        derivation_path: String,
        signing_option: Option<SigningOption>,
    ) -> Result<Vec<u8>, KSError>;

    fn get_version(&self) -> Result<Vec<u8>, KSError>;
}
