mod command;
mod serial_manager;
mod tags;
mod tvl;

use std::convert::TryFrom;

use self::command::CommandBuilder;
use self::tags::RESPONSE_TAG;
use bytes::BytesMut;
use ed25519_bip32_core::XPrv;
use zeroize::Zeroizing;

use super::KeyMaster;
use super::SigningAlgorithm;
use crate::algorithm;
use crate::algorithm::SecretKey;
use crate::error::KSError;
use crate::keymaster::se::command::SetSecretCommand;
use crate::keymaster::SigningOption;
use command::{
    parse_result, ClearTokenCommand, Command, CommandParams, GETKeyCommand, GenerateEntropyCommand,
    GenerateTokenCommand, GetFirmwareStatusCommand, SignTxCommand,
};
use k256::ecdsa::SigningKey;
use serial_manager::SerialManager;
use tags::result;
use tvl::Packet;

pub struct SecureElement {
    version: String,
    port: String,
}

pub enum GetKeyType {
    MasterSeed,
    RSASecret,
    ExtendedPrivateKey,
    ExtendedPublicKey,
    Entropy,
    ADARootKey,
}

impl SecureElement {
    pub fn new(port_name: String) -> Self {
        SecureElement {
            version: "1.0.0".to_string(),
            port: port_name,
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

    fn set_se_result(&self, command: Command) -> Result<(), KSError> {
        let timeout = 100000;
        let sem = SerialManager::new(&self.port, timeout);
        let data = sem.send_data(command.to_vec())?;
        let result_packet = Packet::try_from(data)?;
        Ok(())
    }

    fn write_secret(&self, secret: Vec<u8>, password: String) -> Result<(), KSError> {
        let password_bytes = hex::decode(&password)
            .map_err(|_| KSError::WriteSecretError("decode password bytes failed".to_string()))?;
        let params = CommandParams {
            secret: Some(secret),
            password: Some(password_bytes),
            ..Default::default()
        };
        self.set_se_result(
            SetSecretCommand::build(Some(params))
                .ok_or(KSError::SEError("compose command error".to_string()))?,
        )
    }

    fn get_key(
        &self,
        mnemonic_id: u8,
        path: String,
        auth_token: Option<Vec<u8>>,
        algo: SigningAlgorithm,
        key_type: GetKeyType,
    ) -> Result<Vec<u8>, KSError> {
        let curve_tag = match algo {
            SigningAlgorithm::Secp256k1 => 0u8,
            SigningAlgorithm::Secp256R1 => 1u8,
            SigningAlgorithm::Ed25519 => 2u8,
            SigningAlgorithm::SR25519 => 3u8,
            SigningAlgorithm::RSA => 5u8,
        };
        let mut result_tag: u16 = result::EXT_KET;

        let mut params = CommandParams {
            wallet_id: Some(mnemonic_id),
            path: Some(path),
            auth_token,
            curve: Some(curve_tag),
            ..Default::default()
        };
        match key_type {
            GetKeyType::MasterSeed => {
                params = CommandParams {
                    is_master_seed: Some(true),
                    ..params
                };
                result_tag = result::EXT_MASTER_SEED;
            }
            GetKeyType::RSASecret => {
                params = CommandParams {
                    is_rsa_secret: Some(true),
                    ..params
                };
                result_tag = result::EXT_RSA_SECRET;
            }
            GetKeyType::ExtendedPrivateKey | GetKeyType::ExtendedPublicKey => {}
            GetKeyType::Entropy => {
                params = CommandParams {
                    is_entropy: Some(true),
                    ..params
                };
                result_tag = result::EXT_ENTROPY
            }
            GetKeyType::ADARootKey => {
                params = CommandParams {
                    is_ada_root: Some(true),
                    ..params
                };
                result_tag = result::EXT_ADA_ROOT_KEY
            }
            _ => Err(KSError::SEError(
                "get key type is not supported".to_string(),
            ))?,
        };
        let key = self.get_se_result(
            GETKeyCommand::build(Some(params))
                .ok_or(KSError::SEError("compose command error".to_string()))?,
            result_tag,
        )?;

        Ok(key)
    }

    fn test_sign(
        &self,
        mnemonic_id: u8,
        path: String,
        auth_token: Vec<u8>,
        curve: u8,
        tx_hash: [u8; 128],
    ) -> Result<Vec<u8>, KSError> {
        let params = CommandParams {
            wallet_id: Some(mnemonic_id),
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
        let password_bytes =
            hex::decode(&password).map_err(|_| KSError::SEError(format!("invalid password")))?;
        let params = CommandParams {
            password: Some(password_bytes),
            ..Default::default()
        };
        let command = GenerateTokenCommand::build(Some(params))
            .ok_or(KSError::SEError("compose command error".to_string()))?;
        self.get_se_result(command, result::AUTH_TOKEN)
    }

    pub(crate) fn clear_token(&self) -> Result<bool, KSError> {
        let result = self.get_se_result(
            ClearTokenCommand::build(None)
                .ok_or(KSError::SEError("compose command error".to_string()))?,
            RESPONSE_TAG,
        )?;
        let result_value = u16::from_ne_bytes(
            result[0..2]
                .try_into()
                .map_err(|_| KSError::SEError("process response tvl result error".to_string()))?,
        );
        if result_value == 0 {
            return Ok(true);
        } else {
            return Ok(false);
        }
    }

    pub fn get_entropy(&self, mnemonic_id: u8, auth_token: Vec<u8>) -> Result<Vec<u8>, KSError> {
        const FAKE_PATH: &str = "m'/1'";
        // get entropy
        let entropy = self.get_key(
            mnemonic_id,
            FAKE_PATH.to_string(),
            Some(auth_token),
            SigningAlgorithm::Secp256k1,
            GetKeyType::Entropy,
        )?;
        Ok(entropy)
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

    fn setup_ada_root_key(
        &self,
        mnemonic_id: u8,
        password: String,
        passphrase: String,
    ) -> Result<bool, KSError> {
        let zeroize_password = Zeroizing::new(password.clone());
        let token = self.generate_token(zeroize_password.as_str().to_string())?;
        let entropy = self.get_entropy(mnemonic_id, token)?;
        let passphrase = passphrase.as_bytes();
        let root_key = algorithm::bip32_ed25519::get_icarus_master_key(&entropy, passphrase)
            .as_ref()
            .to_vec();
        self.set_ada_root_key(mnemonic_id, zeroize_password.as_str().to_string(), root_key)?;
        self.clear_token()?;
        Ok(true)
    }

    fn get_ada_extended_public_key(
        &self,
        mnemonic_id: u8,
        password: String,
        path: String,
    ) -> Result<String, KSError> {
        let zeroize_password = Zeroizing::new(password.clone());
        let token = self.generate_token(zeroize_password.as_str().to_string())?;
        let root_key = self.get_ada_root_key(mnemonic_id, token)?;
        let root_xprv = XPrv::from_slice_verified(&root_key)
            .map_err(|e| KSError::GetPublicKeyError(e.to_string()))?;
        let xpub = algorithm::bip32_ed25519::get_extended_public_key(path, root_xprv)
            .map_err(|e| KSError::GetPublicKeyError(e))?;
        self.clear_token()?;
        Ok(xpub.to_string())
    }

    fn get_rsa_public_key(&self, mnemonic_id: u8, password: String) -> Result<Vec<u8>, KSError> {
        let zeroize_password = Zeroizing::new(password);
        let mut public_key = BytesMut::with_capacity(512);
        let token = self.generate_token(zeroize_password.as_str().to_string())?;
        // get master_seed
        let master_seed = self.get_key(
            mnemonic_id,
            algorithm::rsa::RSA_DERIVATION_PATH.to_string(),
            Some(token),
            SigningAlgorithm::RSA,
            GetKeyType::MasterSeed,
        )?;
        let zeroize_master_seed = Zeroizing::new(master_seed);
        let secret =
            algorithm::rsa::RSA::from_seed(zeroize_master_seed.as_slice()).map_err(|_| {
                KSError::GenerateSigningKeyError("init rsa key pair failed".to_string())
            })?;
        // save rsa secret
        self.write_secret(secret.clone(), zeroize_password.as_str().to_string())?;
        let rsa = algorithm::rsa::RSA::from_secret(&secret)?;
        public_key.extend_from_slice(&rsa.keypair_modulus());
        Ok(public_key.to_vec())
    }

    fn get_ada_root_key(&self, mnemonic_id: u8, auth_token: Vec<u8>) -> Result<Vec<u8>, KSError> {
        const ADA_FAKE_PATH: &str = "m/1852'";
        // get root_key
        let ada_root_key = self.get_key(
            mnemonic_id,
            ADA_FAKE_PATH.to_string(),
            Some(auth_token),
            SigningAlgorithm::Ed25519,
            GetKeyType::ADARootKey,
        )?;
        Ok(ada_root_key)
    }

    fn set_ada_root_key(
        &self,
        mnemonic_id: u8,
        password: String,
        secret: Vec<u8>,
    ) -> Result<bool, KSError> {
        let password_bytes = hex::decode(&password)
            .map_err(|_| KSError::WriteSecretError("decode password bytes failed".to_string()))?;
        let params = CommandParams {
            secret: Some(secret),
            password: Some(password_bytes),
            is_ada_root: Some(true),
            ..Default::default()
        };

        let command = SetSecretCommand::build(Some(params))
            .ok_or(KSError::SEError("compose command error".to_string()))?;
        let result = self.get_se_result(command, RESPONSE_TAG)?;
        let result_value = u16::from_ne_bytes(
            result[0..2]
                .try_into()
                .map_err(|_| KSError::SEError("process response tvl result error".to_string()))?,
        );
        if result_value == 0 {
            return Ok(true);
        } else {
            return Ok(false);
        }
    }

    fn sign_data(
        &self,
        mnemonic_id: u8,
        password: String,
        data: Vec<u8>,
        algo: super::SigningAlgorithm,
        derivation_path: String,
        signing_option: Option<SigningOption>,
    ) -> Result<Vec<u8>, KSError> {
        // get key from se
        let auth_token = hex::decode(password).map_err(|_e| KSError::SEError("".to_string()))?;
        if let (SigningAlgorithm::Ed25519, (Some(SigningOption::ADA))) = (algo, signing_option) {
            // sign with bip32_ed25519
            let ada_root_key = self.get_ada_root_key(mnemonic_id, auth_token)?;
            let signature =
                algorithm::bip32_ed25519::sign_message(&data, derivation_path, &ada_root_key)
                    .map_err(|e| KSError::SignDataError(e))?;
            return Ok(signature.to_vec());
        }
        match algo {
            SigningAlgorithm::Secp256k1 => {
                let private_key = self.get_key(
                    mnemonic_id,
                    derivation_path,
                    Some(auth_token),
                    algo,
                    GetKeyType::ExtendedPrivateKey,
                )?;
                let zeroize_secret = Zeroizing::new(private_key);
                let secp256k1 = SigningKey::from_secret(zeroize_secret.as_slice())?;
                let signature = secp256k1.sign(data, None)?;
                Ok(signature)
            }
            SigningAlgorithm::RSA => {
                // get rsa secret from SE
                let secret = self.get_key(
                    mnemonic_id,
                    derivation_path,
                    Some(auth_token),
                    algo,
                    GetKeyType::RSASecret,
                )?;
                let zeroize_secret = Zeroizing::new(secret);
                let rsa = algorithm::rsa::RSA::from_secret(zeroize_secret.as_slice())?;
                match signing_option {
                    Some(SigningOption::RSA { salt_len }) => {
                        let signature = rsa.sign(data, Some(SigningOption::RSA { salt_len }))?;
                        Ok(signature)
                    }
                    _ => Err(KSError::RSASignError),
                }
            }
            _ => Err(KSError::SEError(
                "signing algo is not supported".to_string(),
            )),
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
    use base64;

    #[test]
    fn it_should_get_entropy() {
        let password =
            "f6cda9bc3afff095f7c96a78455b2925c6339db3ce3563013e7fb75cc0e4829d".to_string();
        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let token = se.generate_token(password).unwrap();
        let mut se = SecureElement::new(port_name.to_string());
        let a = se.get_entropy(0, token).unwrap();
        assert_eq!(
            hex::encode(a),
            "ffffffffffffffffffffffffffffffff".to_string()
        );
    }

    #[test]
    fn it_should_set_the_ada_root_key() {
        let password =
            "f6cda9bc3afff095f7c96a78455b2925c6339db3ce3563013e7fb75cc0e4829d".to_string();
        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let v = vec![0x02; 96];
        let r = se.set_ada_root_key(0, password, v).unwrap();
        assert_eq!(r, true);
    }

    #[test]
    fn it_should_get_the_ada_root_key() {
        let password =
            "f6cda9bc3afff095f7c96a78455b2925c6339db3ce3563013e7fb75cc0e4829d".to_string();
        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let token = se.generate_token(password).unwrap();

        let r = se.get_ada_root_key(0, token).unwrap();
        assert_eq!(hex::encode(r), "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202".to_string());
    }

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
    fn it_should_test_get_private_key() {
        let password =
            "f6cda9bc3afff095f7c96a78455b2925c6339db3ce3563013e7fb75cc0e4829d".to_string();

        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let token = se.generate_token(password).unwrap();

        let path = "m/44'/60'/0'/0/0".to_string();

        let key = se
            .get_key(
                0,
                path,
                Some(token),
                SigningAlgorithm::Secp256k1,
                GetKeyType::ExtendedPrivateKey,
            )
            .unwrap();
        se.clear_token();
        let base58_key = String::from_utf8(key.to_vec())
            .map_err(|_e| KSError::SEError("decode bs58 key error".to_string()))
            .unwrap();
        assert_eq!("xprvA46yrWykFh3LjMHn1eqk7A8WNBt7JzJqEeBX1RNz2bx9Ditu6peK7MJWR8tfXUqPjWNuL7LwLvphdgkWShNpYXiJBuvi9agxJUWiHGHtoNk", base58_key);
    }

    #[test]
    fn it_should_test_get_master_seed() {
        let password =
            "f6cda9bc3afff095f7c96a78455b2925c6339db3ce3563013e7fb75cc0e4829d".to_string();

        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let token = se.generate_token(password).unwrap();
        let path = "m/44'/472'".to_string();

        let key = se
            .get_key(
                0,
                path,
                Some(token),
                SigningAlgorithm::RSA,
                GetKeyType::MasterSeed,
            )
            .unwrap();
        se.clear_token();
        assert_eq!(key.len(), 64);
        assert_eq!(hex::encode(key), "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
    }

    #[test]
    fn it_should_test_get_rsa_public_key() {
        let password =
            "f6cda9bc3afff095f7c96a78455b2925c6339db3ce3563013e7fb75cc0e4829d".to_string();

        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let path = "m/44'/472'".to_string();

        let key = se.get_rsa_public_key(0, password).unwrap();
        se.clear_token();
        assert_eq!(key.len(), 512);
        assert_eq!(hex::encode(key), "c41a50ed2155a5740b45df8e3815774d6b8d193e5ad80c9efaaf6d6d0253f350c85becf39eb7056d75841f6a064acf8381383eceb218e16859ef72be7273321a2b4855b87bc6f14c734e2a9c90850c34a8a0a4279ac9be3186b086db5b302fb68176b4c1fee337456c42f972c7993f618fdedc0bf1658c2d59cf2c0c6ac31a61ac1260e0fd4a761ca3707e27611c14b4c6b6abe698c11009ddf5d1511ae47ea271079b6892d229a27d0822e0c7aa12a4cf7f7c28fe23d201eae2adb7f403c9c5a1762c2d8cc96898ce41fe529ab0ef8184e50063e6fc62e0a808e8602254c142c9e7f7e94e6ef2c767ac0e99810d09a44bfde8db46298bc0e25b4a333b4ef86cd7ce658ff661ab0d1789b603b8770a6b433851a91c8ff07a7a8a0767702f6887098ea34bf4a8309eaab9baadd16d45cdd9b1899b6a303a2dce23745cec9fc2ecd9735a66c77fdea1bfd4cdb2be7bfb407a4fd5d3405c3cb33b5316e16559f0c4bf0bc7d1a3ada78917217b289c4d75eb60e0396f03035fd8d553727c790189cfd8dabcee8a4ae6607925b9a27ff7ad7ede26b98f8acd2532cf3175693f3eede9989a0aeedbdb3ff14fec823017531aead4cd22733ab30dbce76cebcdac64424128d6eeff3cdc1825d7cdb7113e74db126e6d931544467c6979aa8d50ac803f36084ed7077f34acfcf3f77bb13d5ebb723fc5d3f45212d2dd6ef20ea757fb4c95");
    }

    #[test]
    fn it_should_test_get_rsa_private_key() {
        let password =
            "f6cda9bc3afff095f7c96a78455b2925c6339db3ce3563013e7fb75cc0e4829d".to_string();

        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let token = se.generate_token(password).unwrap();
        let path = "m/44'/472'".to_string();

        let key = se
            .get_key(
                0,
                path,
                Some(token),
                SigningAlgorithm::RSA,
                GetKeyType::RSASecret,
            )
            .unwrap();
        assert_eq!(key.len(), 1536);
        assert_eq!(hex::encode(key), "fdec3a1aee520780ca4058402d0422b5cd5950b715728f532499dd4bbcb68e5d44650818b43656782237316c4b0e2faa2b15c245fb82d10cf4f5b420f1f293ba75b2c8d8cef6ad899c34ce9de482cb248cc5ab802fd93094a63577590d812d5dd781846ef7d4f5d9018199c293966371c2349b0f847c818ec99caad800116e02085d35a39a913bc735327705161761ae30a4ec775f127fbb5165418c0fe08e54ae0aff8b2dab2b82d3b4b9c807de5fae116096075cf6d5b77450d743d743e7dcc56e7cafdcc555f228e57b363488e171d099876993e93e37a94983ccc12dba894c58ca84ac154c1343922c6a99008fabd0fa7010d3cc34f69884fec902984771c5b50031ba31ab7c8b76453ce771f048b84fb89a3e4d44c222c3d8c823c683988b0dbf354d8b8cbf65f3db53e1365d3c5e043f0155b41d1ebeca6e20b2d6778600b5c98ffdba33961dae73b018307ef2bce9d217bbdf32964080f8db6f0cf7ef27ac825fcaf98d5143690a5d7e138f4875280ed6de581e66ed17f83371c268a073e4594814bcc88a33cbb4ec8819cc722ea15490312b85fed06e39274c4f73ac91c7f4d1b899729691cce616fb1a5feee1972456addcb51ac830e947fcc1b823468f0eefbaf195ac3b34f0baf96afc6fa77ee2e176081d6d91ce8c93c3d0f3547e48d059c9da447ba05ee3984703bebfd6d704b7f327ffaea7d0f63d0d3c6d65542fd4042926629451ee9a4dace812428b6494acbf45370ddd2308c01e9ab9bf3974b561d5064f6f315f1a39632024bc18f2738c3acb11a1c1d25919477b0acc4f3e8b865aa50a9c3e781535079a06a668aa262ed675bb8ff979b93b5c877044528a0a89aa0a13855b37d96d1c213f237c2739a26aeca46427c517ecf0bc778becda2afb0be236988ed5d162c87ecca8db123af41129f8dfb3893f66293c64dd09d7313190ae66af5a2bef053ed25594a97bda6aa2c7eff560c815b9fe28ce2b68e89988a88322c34ef0e7e4c0822b2018545379900553d18c71de88bed451ef814c739296586d238bef428945ecb9f1eda9c098ba2345daf59229659b1588f2374438e978f94cf03ece881ded34790416d0f746b0701f7096aa74f381a21725dba3702b32670a5db7693763e95e751ae0ef5cd875ac38a4427dd716dd1d61d6c0e234ff64f80dbf0f1c2632883ac74b9e9387ad58e5ca928b7880d9844b513b448447c31b94d04160cfa83b0381b4e59b23deafd1cca01639e405bc494fa63758246eab4d25f94a6c2dfed72be6127217d7f806b05b573070850307a8c594233851a7efdb55e27f1624f2a9ca2a0c3e803024b1cbce919e7ae7e0b730d357a6ca62cd15978940f7998524404cb5837ccc93bca22caeb5156aa36abd92c83e047addef10d2e8f78e8c94a50fc305f9fe35a7f45f76271bd794b2f111db2eae41c41a50ed2155a5740b45df8e3815774d6b8d193e5ad80c9efaaf6d6d0253f350c85becf39eb7056d75841f6a064acf8381383eceb218e16859ef72be7273321a2b4855b87bc6f14c734e2a9c90850c34a8a0a4279ac9be3186b086db5b302fb68176b4c1fee337456c42f972c7993f618fdedc0bf1658c2d59cf2c0c6ac31a61ac1260e0fd4a761ca3707e27611c14b4c6b6abe698c11009ddf5d1511ae47ea271079b6892d229a27d0822e0c7aa12a4cf7f7c28fe23d201eae2adb7f403c9c5a1762c2d8cc96898ce41fe529ab0ef8184e50063e6fc62e0a808e8602254c142c9e7f7e94e6ef2c767ac0e99810d09a44bfde8db46298bc0e25b4a333b4ef86cd7ce658ff661ab0d1789b603b8770a6b433851a91c8ff07a7a8a0767702f6887098ea34bf4a8309eaab9baadd16d45cdd9b1899b6a303a2dce23745cec9fc2ecd9735a66c77fdea1bfd4cdb2be7bfb407a4fd5d3405c3cb33b5316e16559f0c4bf0bc7d1a3ada78917217b289c4d75eb60e0396f03035fd8d553727c790189cfd8dabcee8a4ae6607925b9a27ff7ad7ede26b98f8acd2532cf3175693f3eede9989a0aeedbdb3ff14fec823017531aead4cd22733ab30dbce76cebcdac64424128d6eeff3cdc1825d7cdb7113e74db126e6d931544467c6979aa8d50ac803f36084ed7077f34acfcf3f77bb13d5ebb723fc5d3f45212d2dd6ef20ea757fb4c95");
    }

    #[test]
    fn it_should_test_get_extend_private_key_error_without_token() {
        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());

        let path = "m/44'/60'/0'/0/0".to_string();
        let key = se
            .get_key(
                0,
                path,
                None,
                SigningAlgorithm::Secp256k1,
                GetKeyType::ExtendedPrivateKey,
            )
            .unwrap_err()
            .to_string();
        se.clear_token();
        assert_eq!("SEError:required field is missing", key);
    }

    #[test]
    fn it_should_test_get_extended_public_key_without_token() {
        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());

        let path = "M/44'/60'/0'/0".to_string();
        let key = se
            .get_key(
                0,
                path,
                None,
                SigningAlgorithm::Secp256k1,
                GetKeyType::ExtendedPublicKey,
            )
            .unwrap();
        se.clear_token();
        let base58_key = String::from_utf8(key.to_vec())
            .map_err(|_e| KSError::SEError("decode bs58 key error".to_string()))
            .unwrap();
        assert_eq!("xpub6EF8jXqFeFEW5bwMU7RpQtHkzE4KJxcqJtvkCjJumzW8CPpacXkb92ek4WzLQXjL93HycJwTPUAcuNxCqFPKKU5m5Z2Vq4nCyh5CyPeBFFr", base58_key);
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
            .sign_data(
                0,
                token_string,
                data,
                SigningAlgorithm::Secp256k1,
                path,
                None,
            )
            .unwrap();
        se.clear_token();
        let expected = "b836ae2bac525ae9d2799928cf6f52919cb2ed5e5e52ca26e3b3cdbeb136ca2f618da0e6413a6aa3aaa722fbc2bcc87f591b8b427ee6915916f257de8125810e00".to_string();
        assert_eq!(hex::encode(signature), expected);
    }

    #[test]
    fn it_should_sign_right_data_rsa_salt_zero() {
        let password =
            "f6cda9bc3afff095f7c96a78455b2925c6339db3ce3563013e7fb75cc0e4829d".to_string();

        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let token = se.generate_token(password).unwrap();

        let token_string = hex::encode(token.clone());

        let path = "m/44'/472'".to_string();

        let data: Vec<u8> = hex::decode(
            "af1dee894786c304604a039b041463c9ab8defb393403ea03cf2c85b1eb8cbfd".to_string(),
        )
            .unwrap();
        let signing_option = SigningOption::RSA { salt_len: 0 };
        let signature = se
            .sign_data(
                0,
                token_string,
                data,
                SigningAlgorithm::RSA,
                path.clone(),
                Some(signing_option),
            )
            .unwrap();
        assert_eq!(signature.len(), 512);
        assert_eq!(hex::encode(signature.clone()), "a466677c060a23d64d581d61dfa2e5f205e79181fc5daaa002a0185d49399b1c2aff2b4993e97f6a4d395e7eba1f5e3ac2c1e350a4fbf9be6b7f1bfc3af19634b0fbfba63c0e0857f45b18de702dd603312e4f585baf70c82f90114a3a4cf7bccd19bc14360fbf5afda08c031b30f79cfac2a755f3479279b3e99e1be1d2d6b8b3e289bfaf2adde389f4353cda4d82d48811765775eb9ea4a0d177ebd13e103bac861b1d9977c87412bf049f5d34cd8a3d43ac3047d6b2d358eea15f65bca24947d5cba4b2addf9bc2fc996e0fa9bc759cff1bbef4a02e69bed3d79fe77fe1640a9eacbb149b6abcf9c53c82a387b8f55bd2a751bf92a536b376c027d4a419237f52feca12960cc230343d7ec746ba6dd035ccb6d7555e4722629a7b0a63804dc986dc5a5d419a93333bff258ac13352a4d30566942dfd5e72a187359540040be816da5ec629dd429ee6c09c3deeacc8ae7a884cb2627438874ae3deb10c6f1318452b936b93ca3d11dde17d6e4ebbb0cee1b96ae9dc0ab1f8ec3f3580d6e11a0ab3d9b75ec4169322ae116697a5f2aa1235e9c2cea14182b03c6effa45e8bff30282434b2a73fef392a8ed576732e638a10b3a5da27ffda39578716a692f13da11983bd650207d10ebdd92ef0026bd30801f42e30aa21cee1f466eb761582019804b0c4d702284c5b44219f0596d51b2c6e69eeba90f2e3861fd05877245e6c");
        let secret = se
            .get_key(
                0,
                path,
                Some(token),
                SigningAlgorithm::RSA,
                GetKeyType::RSASecret,
            )
            .unwrap();
        let rsa = algorithm::rsa::RSA::from_secret(secret.as_slice()).unwrap();
        let data2: Vec<u8> = hex::decode(
            "af1dee894786c304604a039b041463c9ab8defb393403ea03cf2c85b1eb8cbfd".to_string(),
        )
            .unwrap();
        let result = rsa.verify(
            &signature.as_ref(),
            &data2,
            SigningOption::RSA { salt_len: 0 },
        );
        se.clear_token();
        assert_eq!(result.ok(), Some(()));
    }

    #[test]
    fn it_should_sign_right_data_rsa_salt_digest() {
        use k256::ecdsa::{recoverable, SigningKey};
        let password =
            "f6cda9bc3afff095f7c96a78455b2925c6339db3ce3563013e7fb75cc0e4829d".to_string();

        let port_name = "/dev/ttyMT1";
        let mut se = SecureElement::new(port_name.to_string());
        let token = se.generate_token(password).unwrap();

        let token_string = hex::encode(token.clone());

        let path = "m/44'/472'".to_string();

        let data: Vec<u8> = hex::decode(
            "af1dee894786c304604a039b041463c9ab8defb393403ea03cf2c85b1eb8cbfd".to_string(),
        )
            .unwrap();
        let signing_option = SigningOption::RSA { salt_len: 32 };
        let signature = se
            .sign_data(
                0,
                token_string,
                data,
                SigningAlgorithm::RSA,
                path.clone(),
                Some(signing_option),
            )
            .unwrap();
        assert_eq!(signature.len(), 512);
        let secret = se
            .get_key(
                0,
                path,
                Some(token),
                SigningAlgorithm::RSA,
                GetKeyType::RSASecret,
            )
            .unwrap();
        let rsa = algorithm::rsa::RSA::from_secret(secret.as_slice()).unwrap();
        let data2: Vec<u8> = hex::decode(
            "af1dee894786c304604a039b041463c9ab8defb393403ea03cf2c85b1eb8cbfd".to_string(),
        )
            .unwrap();
        let result = rsa.verify(
            &signature.as_ref(),
            &data2,
            SigningOption::RSA { salt_len: 32 },
        );
        se.clear_token();
        assert_eq!(result.ok(), Some(()));
    }
}
