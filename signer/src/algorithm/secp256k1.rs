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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    #[test]
    fn test_from_secret() {
        /*
           Test Vector:
           mnemonic words, for testing "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
           hd_path: m/44'/60'/0'/0/0
           xprivKey: xprvA46yrWykFh3LjMHn1eqk7A8WNBt7JzJqEeBX1RNz2bx9Ditu6peK7MJWR8tfXUqPjWNuL7LwLvphdgkWShNpYXiJBuvi9agxJUWiHGHtoNk
         */
        let secret = hex::decode("78707276413436797257796b4668334c6a4d486e3165716b374138574e4274374a7a4a714565425831524e7a32627839446974753670654b374d4a5752387466585571506a574e754c374c774c76706864676b5753684e705958694a42757669396167784a555769484748746f4e6b").unwrap();
        let signing_key = SigningKey::from_secret(secret.as_slice()).unwrap();
        let expected = SigningKey::from_bytes(hex::decode("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727").unwrap().as_slice()).unwrap();
        assert_eq!(signing_key, expected);
    }
}