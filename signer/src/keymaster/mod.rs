use crate::error::KSError;
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

    fn write_menomic(&self, menomic: String, password: String) -> Result<String, KSError>;

    fn sign_data(
        &self,
        menomic_id: u8,
        password: String,
        data: Vec<u8>,
        algo: SigningAlgorithm,
        derivation_path: String,
    ) -> Result<Vec<u8>, KSError>;

    fn get_version(&self) -> Result<Vec<u8>, KSError>;
}
