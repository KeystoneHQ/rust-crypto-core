
use super::{KeyMaster, SigningAlgorithm, hash_wraper::ShaWrapper};
use crate::error::KSError;
use alloc::{string::{String, ToString}, vec::Vec};
use k256::ecdsa::{recoverable::Signature, signature::DigestSigner, SigningKey, digest::Digest};
use zeroize::Zeroizing;
use hex;

pub struct Mini {
    key: String
}

impl Mini {
    pub fn new(key:String) -> Self {
        Mini {
            key
        }
    }
}

impl KeyMaster for Mini {

    fn generate_entropy(&self, length: super::EntropyLength) -> Result<Vec<u8>, KSError> {
        Err(KSError::SEError("this function is not supported for now".to_string()))
    }

    fn write_menomic(&self, menomic: String, password: String) -> Result<String, KSError> {
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
        let private_key = hex::decode(self.key).map_err(|_e|KSError::SEError("hex key decode error".to_string()))?;
        let zeroize_private_key = Zeroizing::new(private_key);
        match algo {
            SigningAlgorithm::Secp256k1 => {
                let signing_key = SigningKey::from_bytes(zeroize_private_key.as_slice())
                    .map_err(|_e| KSError::SEError("error generate the signing key".to_string()))?;
                let mut hash_wrapper = ShaWrapper::new();
                hash_wrapper.update(data);
                let signature: Signature = signing_key
                    .try_sign_digest(hash_wrapper)
                    .map_err(|_e| KSError::SEError("signing digest error".to_string()))?;
                Ok(signature.as_ref().to_vec())
            },
            _ => Err(KSError::SEError("signing algo is not supported".to_string()))
        }
    }

    fn get_version(&self) -> Result<Vec<u8>, KSError> {
        Err(KSError::SEError("this function is not supported for now".to_string()))
    }
}
