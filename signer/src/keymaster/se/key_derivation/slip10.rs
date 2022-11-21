use crate::{error::KSError, SigningAlgorithm};

pub fn derive(master_seed: &Vec<u8>, derivation_path: String, algo: SigningAlgorithm) -> Result<Vec<u8>, KSError> {
    unimplemented!()
}