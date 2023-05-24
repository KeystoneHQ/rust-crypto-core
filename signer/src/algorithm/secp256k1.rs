use zeroize::Zeroizing;
use crate::algorithm::SecretKey;
use crate::{KSError, SigningOption};
use k256::ecdsa::SigningKey;
use crate::keymaster::hash_wraper::ShaWrapper;
use k256::ecdsa::{recoverable::Signature, signature::DigestSigner,digest::Digest};

impl SecretKey for SigningKey {
    fn from_secret(secret: &[u8]) -> Result<SigningKey, KSError> {
        let base58_key = String::from_utf8(secret.to_vec()).map_err(|_e| KSError::SEError("decode bs58 key error".to_string()))?;
        let key = bs58::decode(base58_key)
            .into_vec()
            .map_err(|_| KSError::SEError("decode bs58 key error".to_string()))?;
        let start = key.len() - (32 + 4);
        let end = key.len() - 4;
        let zeroize_private_key = Zeroizing::new(key[start..end].to_vec());
        let signing_key = SigningKey::from_bytes(zeroize_private_key.as_slice())
            .map_err(|_e| KSError::GenerateSigningKeyError("secp256k1".to_string()))?;
        Ok(signing_key)
    }

    fn sign(&self, data: Vec<u8>, signing_option: Option<SigningOption>) -> Result<Vec<u8>, KSError> {
        let mut hash_wrapper = ShaWrapper::new();
        hash_wrapper.update(data);
        let signature: Signature = self.try_sign_digest(hash_wrapper).map_err(|e| KSError::SignDataError(e.to_string()))?;
        Ok(signature.as_ref().to_vec())
    }
}