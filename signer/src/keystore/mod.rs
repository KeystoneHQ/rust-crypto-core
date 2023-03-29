use crate::{error::KSError, keymaster::EntropyLength};

pub(crate) mod keystore_file;

pub trait Keystore {
    fn generate_entropy(length: EntropyLength) -> Vec<u8>;
    fn entropy_to_memnonic(entropy:&[u8]) -> Result<String, KSError>;
    fn entropy_to_bip39_seed(entropy:&[u8], passpharse: &str) -> Result<[u8;64], KSError>;
    fn save_entropy_seed_data(entropy:Vec<u8>, passpharse: &str, password: &str) -> Result<String, KSError>;
    fn get_seed_data(seed_id: String, password: &str) -> Result<[u8;64], KSError>;   
}