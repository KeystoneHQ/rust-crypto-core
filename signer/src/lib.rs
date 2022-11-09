mod error;
mod keymaster;
mod algorithm;

use error::KSError;
use keymaster::{se::SecureElement, KeyMaster, local::Mini};
pub use keymaster::SigningAlgorithm;

pub struct Signer {
    inner: Box<dyn KeyMaster>,
}

impl Signer {
    pub fn new_with_se(port_name: String) -> Self {
        Self {
            inner: Box::new(SecureElement::new(port_name)),
        }
    }

    fn new_with_mini() -> Self {
        Self { inner: Box::new(Mini{})}
    }
    

    pub fn sign_data(
        &self,
        menomic_id: u8,
        password: String,
        data: Vec<u8>,
        algo: SigningAlgorithm,
        derivation_path: String,
    ) -> Result<Vec<u8>, KSError> {
        self.inner
            .sign_data(menomic_id, password, data, algo, derivation_path)
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::signature::Signature as _;
    use k256::ecdsa::digest::Digest;
    use k256::ecdsa::{recoverable::Signature, SigningKey};
    use super::keymaster::hash_wraper::ShaWrapper;
    use super::*;
    use crate::algorithm;
    #[test]
    fn it_should_pass_test_sign_256k1() {
        let fake_signer = Signer::new_with_mini();
        let path = "m/44'/60'/0'/0/0".to_string();

        let data: Vec<u8> = hex::decode(
            "af1dee894786c304604a039b041463c9ab8defb393403ea03cf2c85b1eb8cbfd".to_string(),
        )
        .unwrap();

        let signature = fake_signer
            .sign_data(0, "test_pass".to_string(), data, SigningAlgorithm::Secp256k1, path)
            .unwrap();

        let sig :Signature = Signature::from_bytes(signature.as_slice()).unwrap();
        let sk_bytes = hex::decode("cff92a2f2f081fe10c1319cb8cef1e010df9ed53248476c739c2ee5d78fd5e92").unwrap();
        let sk = SigningKey::from_bytes(sk_bytes.as_slice()).unwrap();
        let data2: Vec<u8> = hex::decode(
            "af1dee894786c304604a039b041463c9ab8defb393403ea03cf2c85b1eb8cbfd".to_string(),
        )
        .unwrap();
        let mut hash = ShaWrapper::new();
        hash.update(data2.as_slice());
        
        let recover_pk = sig.recover_verifying_key_from_digest(hash).unwrap();

        let pk = sk.verifying_key();
        assert_eq!(&pk, &recover_pk);
    }

    #[test]
    fn it_should_pass_test_sign_rsa() {
        let fake_signer = Signer::new_with_mini();
        let path = "m/44'/472'".to_string();

        let data: Vec<u8> = hex::decode(
            "af1dee894786c304604a039b041463c9ab8defb393403ea03cf2c85b1eb8cbfd".to_string(),
        ).unwrap();

        let signature = fake_signer
            .sign_data(0, "test_pass".to_string(), data, SigningAlgorithm::RSA, path)
            .unwrap();
        let data2: Vec<u8> = hex::decode("af1dee894786c304604a039b041463c9ab8defb393403ea03cf2c85b1eb8cbfd".to_string()).unwrap();
        let sk_bytes = hex::decode("cff92a2f2f081fe10c1319cb8cef1e010df9ed53248476c739c2ee5d78fd5e92").unwrap();
        let rsa = algorithm::rsa::RSA::new(&sk_bytes).unwrap();
        let result = rsa.verify(&signature.as_ref(), &data2);
        assert_eq!(result.ok(), Some(()));
    }
}
