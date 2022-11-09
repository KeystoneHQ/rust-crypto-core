mod command;
mod serial_manager;
mod tags;
mod tvl;

use std::convert::TryFrom;

use self::command::CommandBuilder;
use bs58;
use k256::ecdsa::digest::Digest;
use k256::ecdsa::{recoverable::Signature, signature::DigestSigner, SigningKey};
use zeroize::Zeroizing;

use super::hash_wraper::ShaWrapper;
use super::KeyMaster;
use super::SigningAlgorithm;
use crate::error::KSError;
use command::{
    parse_result, ClearTokenCommand, Command, CommandParams, GETKeyCommand, GenerateEntropyCommand,
    GenerateTokenCommand, GetFirmwareStatusCommand, SignTxCommand,
};
use serial_manager::SerialManager;
use tags::result;
use tvl::Packet;
use crate::algorithm::error::AlgError;
use crate::algorithm::rsa::RSA;
use crate::keymaster::se::command::SetSecretCommand;
use super::algorithm;


pub struct SecureElement {
    version: String,
    port: String,
}

impl SecureElement {
    pub fn new(port_name:String) -> Self {
        SecureElement {
            version: "1.0.0".to_string(),
            port: port_name
        }
    }
    
    fn get_se_result(&self, command: Command, response: u16) -> Result<Vec<u8>, KSError> {
        let timeout = 100000;
        let sem = SerialManager::new(&self.port, timeout);
        let data = sem.send_data(command.to_vec())?;
        let result_packet = Packet::try_from(data)?;
        if parse_result(&result_packet, command.tag) {
            if let Some(v) = result_packet.payloads.get(&response) {
                return Ok(v.value.to_vec());
            } else {
                Err(KSError::SEError("required field is missing".to_string()))
            }
        } else {
            Err(KSError::SEError("error from chip!".to_string()))
        }
    }

    fn get_key(
        &self,
        menomic_id: u8,
        path: String,
        auth_token: Option<Vec<u8>>,
        curve: u8,
        is_master_seed: bool,
    ) -> Result<Vec<u8>, KSError> {
        let params = CommandParams {
            wallet_id: Some(menomic_id),
            path: Some(path),
            auth_token,
            curve: Some(curve),
            ..Default::default()
        };

        let key = self.get_se_result(
            GETKeyCommand::build(Some(params))
                .ok_or(KSError::SEError("compose command error".to_string()))?,
            result::MASTER_SEED,
        )?;

        Ok(key)
    }

    fn get_master_seed(
        &self,
        mnemonic_id: u8,
        path: String,
        auth_token: Option<Vec<u8>>,
        curve: u8,
    ) -> Result<Vec<u8>, KSError> {
        let params = CommandParams {
            wallet_id: Some(mnemonic_id),
            path: Some(path),
            auth_token,
            curve: Some(curve),
            is_master_seed: Some(true),
            ..Default::default()
        };

        let master_seed = self.get_se_result(
                GETKeyCommand::build(Some(params))
                    .ok_or(KSError::SEError("compose command error".to_string()))?,
                result::MASTER_SEED,
            )?;

        Ok(master_seed)
    }

    fn test_sign(
        &self,
        menomic_id: u8,
        path: String,
        auth_token: Vec<u8>,
        curve: u8,
        tx_hash: [u8; 128],
    ) -> Result<Vec<u8>, KSError> {
        let params = CommandParams {
            wallet_id: Some(menomic_id),
            path: Some(path),
            auth_token: Some(auth_token),
            curve: Some(curve),
            hash: Some(tx_hash),
            ..Default::default()
        };

        self.get_se_result(
            SignTxCommand::build(Some(params))
                .ok_or(KSError::SEError("compose command error".to_string()))?,
            result::EXT_KET,
        )
    }

    pub(crate) fn generate_token(&self, password: String) -> Result<Vec<u8>, KSError> {
        let password_bytes = hex::decode(&password).unwrap();
        let params = CommandParams {
            password: Some(password_bytes),
            ..Default::default()
        };

        self.get_se_result(
            GenerateTokenCommand::build(Some(params))
                .ok_or(KSError::SEError("compose command error".to_string()))?,
            result::AUTH_TOKEN,
        )
    }

    pub(crate) fn clear_token(&self) -> Result<Vec<u8>, KSError> {
        self.get_se_result(
            ClearTokenCommand::build(None)
                .ok_or(KSError::SEError("compose command error".to_string()))?,
            result::AUTH_TOKEN,
        )
    }
}

impl KeyMaster for SecureElement {
    fn generate_entropy(&self, length: super::EntropyLength) -> Result<Vec<u8>, KSError> {
        self.get_se_result(
            GenerateEntropyCommand::build(None)
                .ok_or(KSError::SEError("compose command error".to_string()))?,
            result::ENTROPY,
        )
    }

    fn write_secret(&self, secret: String, password: String) -> Result<(), KSError> {
        let password_bytes = hex::decode(&password).unwrap();
        let secret_bytes = hex::decode(&secret).unwrap();
        let params = CommandParams {
            secret: Some(secret_bytes),
            password: Some(password_bytes),
            ..Default::default()
        };
        self.get_se_result(
            SetSecretCommand::build(Some(params))
                .ok_or(KSError::SEError("compose command error".to_string()))?,
            result::SUCCEED,
        )?;
        Ok(())
    }

    fn sign_data(
        &self,
        menomic_id: u8,
        password: String,
        data: Vec<u8>,
        algo: super::SigningAlgorithm,
        derivation_path: String,
    ) -> Result<Vec<u8>, KSError> {
        // get key from se

        let auth_token = hex::decode(password).map_err(|_e| KSError::SEError("".to_string()))?;

        let curve_tag = match algo {
            SigningAlgorithm::Secp256k1 => 0u8,
            SigningAlgorithm::Secp256R1 => 1u8,
            SigningAlgorithm::Ed25519 => 2u8,
            SigningAlgorithm::SR25519 => 3u8,
            SigningAlgorithm::RSA => 5u8,
        };

        match algo {
            SigningAlgorithm::Secp256k1 => {
                let private_key = self.get_key(menomic_id, derivation_path, Some(auth_token), curve_tag, false)?;
                let base58_key = String::from_utf8(private_key).map_err(|_e| KSError::SEError("decode bs58 key error".to_string()))?;
                let key = bs58::decode(base58_key)
                    .into_vec()
                    .map_err(|_| KSError::SEError("decode bs58 key error".to_string()))?;
                let start = key.len() - (32 + 4);
                let end = key.len() - 4;
                let zeroize_private_key = Zeroizing::new(key[start..end].to_vec());
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
                let private_key = self.get_key(menomic_id, derivation_path, Some(auth_token), curve_tag, true)?;
                let zeroize_private_key = Zeroizing::new(private_key);
                let rsa = RSA::from_secret(zeroize_private_key.as_slice())?;
                let signature = rsa.sign(&data).map_err(|_e| KSError::SEError("signing digest error".to_string()))?;
                Ok(signature)
            }
            _ => Err(KSError::SEError("signing algo is not supported".to_string()))
        }
    }

    fn get_version(&self) -> Result<Vec<u8>, KSError> {
        self.get_se_result(
            GetFirmwareStatusCommand::build(None)
                .ok_or(KSError::SEError("compose command error".to_string()))?,
            result::FIRMWARE_APP_VERSION,
        )
    }
}

#[cfg(all(test, target_os = "android"))]
mod tests {
    use super::*;
    use crate::keymaster::EntropyLength;
    #[test]
    // this test function rely on secure element
    fn it_should_get_right_version_from_chip() {
        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let version = se.get_version().unwrap();
        let a = String::from_utf8(version).unwrap();
        assert_eq!(a.as_str(), "1.2.0.000000");
    }

    #[test]
    // this test function rely on secure element
    fn it_should_get_right_entropy_from_chip() {
        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let entropy = se.generate_entropy(EntropyLength::Short(12)).unwrap();
        assert_eq!(32, entropy.len());
    }

    #[test]
    fn it_should_test_get_key() {
        let password =
            "f6cda9bc3afff095f7c96a78455b2925c6339db3ce3563013e7fb75cc0e4829d".to_string();

        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let token = se.generate_token(password).unwrap();

        let path = "m/44'/60'/0'/0/0".to_string();

        let key = se.get_key(0, path, Some(token), 0).unwrap();
        se.clear_token();
        assert_eq!(32, key.len());
    }

    #[test]
    fn it_should_test_get_key_error_with_token() {
        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());

        let path = "m/44'/60'/0'/0/0".to_string();
        let key = se.get_key(0, path, None, 0).unwrap_err().to_string();
        se.clear_token();
        assert_eq!("SEError:error from chip!", key);
    }

    #[test]
    fn it_should_test_get_key__without_token() {
        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());

        let path = "M/44'/60'/0'/0/0".to_string();
        let key = se.get_key(0, path, None, 0).unwrap();
        se.clear_token();
        assert_eq!(32, key.len());
    }

    #[test]
    fn it_should_sign_right_data() {
        use k256::ecdsa::{recoverable, SigningKey};
        let password =
            "f6cda9bc3afff095f7c96a78455b2925c6339db3ce3563013e7fb75cc0e4829d".to_string();

        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let token = se.generate_token(password).unwrap();

        let token_string = hex::encode(token);

        let path = "m/44'/60'/0'/0/0".to_string();

        let data: Vec<u8> = hex::decode(
            "af1dee894786c304604a039b041463c9ab8defb393403ea03cf2c85b1eb8cbfd".to_string(),
        )
        .unwrap();

        let signature = se
            .sign_data(0, token_string, data, SigningAlgorithm::Secp256k1, path)
            .unwrap();
        se.clear_token();
        let expected = "c127cf3bbd7f6e405995797d4d05bb122688598bf98d7c4b2f7813d84735363a5f7347e3c29d83244b00ff62ae0c717c0c4f7aa9de2bf96da29c1f80ac05d20600".to_string();
        assert_eq!(hex::encode(signature), expected);
    }
}
