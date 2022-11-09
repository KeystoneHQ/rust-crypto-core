
use super::{KeyMaster, SigningAlgorithm, hash_wraper::ShaWrapper};
use crate::error::KSError;
use k256::ecdsa::{recoverable::Signature, signature::DigestSigner, SigningKey, digest::Digest};
use zeroize::Zeroizing;
use crate::SigningAlgorithm::RSA;
use crate::algorithm;

pub struct Mini;

impl KeyMaster for Mini {
    fn generate_entropy(&self, length: super::EntropyLength) -> Result<Vec<u8>, KSError> {
        Err(KSError::SEError("this function is not supported for now".to_string()))
    }

    fn sign_data(
        &self,
        menomic_id: u8,
        password: String,
        data: Vec<u8>,
        algo: super::SigningAlgorithm,
        derivation_path: String,
    ) -> Result<Vec<u8>, KSError> {
        let curve_tag = match algo {
            SigningAlgorithm::Secp256k1 => 0u8,
            SigningAlgorithm::Secp256R1 => 1u8,
            SigningAlgorithm::Ed25519 => 2u8,
            SigningAlgorithm::SR25519 => 3u8,
            SigningAlgorithm::RSA => 5u8,
        };
        // only for testing purpose
        match algo {
            SigningAlgorithm::Secp256k1 => {
                let private_key = hex::decode("cff92a2f2f081fe10c1319cb8cef1e010df9ed53248476c739c2ee5d78fd5e92").map_err(|_e|KSError::SEError("hex key decode error".to_string()))?;
                let zeroize_private_key = Zeroizing::new(private_key);
                let signing_key = SigningKey::from_bytes(zeroize_private_key.as_slice())
                    .map_err(|_e| KSError::SEError("error generate the signing key".to_string()))?;
                let mut hash_wrapper = ShaWrapper::new();
                hash_wrapper.update(data);
                let signature: Signature = signing_key
                    .try_sign_digest(hash_wrapper)
                    .map_err(|_e| KSError::SEError("signing digest error".to_string()))?;
                Ok(signature.as_ref().to_vec())
            },
            SigningAlgorithm::RSA => {
                let master_seed = hex::decode("cff92a2f2f081fe10c1319cb8cef1e010df9ed53248476c739c2ee5d78fd5e92").map_err(|_e|KSError::SEError("hex key decode error".to_string()))?;
                let zeroize_master_seed = Zeroizing::new(master_seed);
                let rsa = algorithm::rsa::RSA::new(&zeroize_master_seed).map_err(|_e| KSError::SEError("initialize rsa error".to_string()))?;
                let signature = rsa.sign(&data).map_err(|_e| KSError::SEError("signing rsa error".to_string()))?;
                Ok(signature)
            }
            _ => Err(KSError::SEError("signing algo is not supported".to_string()))
        }
    }

    fn get_version(&self) -> Result<Vec<u8>, KSError> {
        Err(KSError::SEError("this function is not supported for now".to_string()))
    }
}
