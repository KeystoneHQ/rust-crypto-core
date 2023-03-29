use rand::{thread_rng, RngCore};
use bip39::Mnemonic;
use crc32fast::Hasher;
use serde::{Serialize, Deserialize};
use std::fs::{File, self};
use std::io::Write;
use std::path::Path;

use crate::keystore::Keystore;
use crate::keymaster::EntropyLength;
use crate::error::KSError;
pub struct KeyManager;

use argon2::Argon2;
use aes_gcm::{
    Key,
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce // Or `Aes128Gcm`
};


#[derive(Serialize, Deserialize)]
struct KeyStorage {
    id: String,
    aes_nonce_seed: Vec<u8>,
    password_salt_seed: Vec<u8>,
    encrypted_seed: Vec<u8>,
    password_salt_entropy: Vec<u8>,
    aes_nonce_entropy: Vec<u8>,
    encrypted_entropy: Vec<u8>,
}

impl Keystore for KeyManager  {
    fn generate_entropy(length: EntropyLength) -> Vec<u8> {
        match length {
           EntropyLength::Short => {
            random_generator(16)
           },
           EntropyLength::Long => {
            random_generator(32)
           }
        }
    }

    fn entropy_to_memnonic(entropy:&[u8]) -> Result<String, crate::error::KSError> {
        let mnemonic = Mnemonic::from_entropy(entropy).map_err(|_| KSError::MnemonicError("entropy to Mnemonice error".to_string()))?;
        Ok(mnemonic.to_string())
    }

    fn entropy_to_bip39_seed(entropy:&[u8], passphrase: &str) -> Result<[u8;64], crate::error::KSError> {
        let mnemonic = Mnemonic::from_entropy(entropy).map_err(|_| KSError::MnemonicError("entropy to Mnemonice error".to_string()))?;
        let seed = mnemonic.to_seed_normalized(passphrase);
        Ok(seed)
    }

    fn save_entropy_seed_data(entropy: Vec<u8>, passphrase: &str, password: &str) -> Result<String, crate::error::KSError> {
        
        let seed = KeyManager::entropy_to_bip39_seed(&entropy, passphrase)?;
        let (key_seed, salt_seed) = generate_password_encryption_key(password, None)?;
        let (ciphertext_seed, nonce_seed) = encrypt_data(&seed, &key_seed)?;

        let (key_entropy, salt_entropy) = generate_password_encryption_key(password, None)?;
        let (ciphertext_entropy, nonce_entropy) = encrypt_data(&entropy, &key_entropy)?;

        let mut hasher = Hasher::new();
        hasher.update(&entropy);
        let checksum = hasher.finalize();
        
        let storage = KeyStorage {
            id: checksum.to_string(),
            aes_nonce_seed: nonce_seed,
            password_salt_seed: salt_seed,
            encrypted_seed: ciphertext_seed,
            aes_nonce_entropy: nonce_entropy,
            password_salt_entropy: salt_entropy,
            encrypted_entropy: ciphertext_entropy,   
        };

        serialize_key_storage(&storage);
        Ok(checksum.to_string())

    }

    fn get_seed_data(seed_id: String, password: &str) -> Result<[u8;64], KSError> {
        
        let filename = format!("{}.json", seed_id);
    
    match Path::new(&filename).try_exists() {
        Ok(result) => {
            if result {
                let content = fs::read_to_string(&filename).map_err(|e| KSError::GetPublicKeyError((e.to_string())))?;
                let keystorage: KeyStorage = serde_json::from_str(&content).map_err(|e| KSError::GetPublicKeyError((e.to_string())))?;
                let (key, _) = generate_password_encryption_key(password, Some(keystorage.password_salt_seed))?;
                let a = decrypt_data(&keystorage.encrypted_seed, &key, &keystorage.aes_nonce_seed)?;
                let seed:[u8;64] = a.as_slice().try_into().map_err(|e| KSError::EntropyError("".to_string()))?;
                Ok(seed)
            } else {
                Err(KSError::EntropyError("".to_string()))
            }
            
        },
        Err(_) => Err(KSError::GetPublicKeyError("()".to_string()))
    }
        
    }
}

fn generate_password_encryption_key(password: &str, salt: Option<Vec<u8>>) -> Result<([u8;32], Vec<u8>), KSError> {
    let password_bytes = password.as_bytes();
    let password_salt:Vec<u8>;
    if let Some(i) = salt {
        password_salt = i
    } else {
        password_salt = random_generator(32);
    }
    
    let mut key_material = [0u8; 32];
    Argon2::default().hash_password_into(password_bytes, &password_salt, &mut key_material).map_err(|e| KSError::GetPublicKeyError((e.to_string())))?;

    Ok((key_material, password_salt))
}

fn encrypt_data(content:&[u8], key:&[u8]) -> Result<(Vec<u8>, Vec<u8>), KSError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| KSError::GetPublicKeyError("".to_string()))?;
    let nonce_source = random_generator(12);
    let nonce = Nonce::from_slice(&nonce_source); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(nonce, content.as_ref()).map_err(|_| KSError::EntropyError("".to_string()))?;
    Ok((ciphertext, nonce_source))
}

fn decrypt_data(ciphertext: &[u8], key: &[u8], nonce_source: &[u8])  -> Result<Vec<u8>, KSError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| KSError::GetPublicKeyError("".to_string()))?;
    let nonce = Nonce::from_slice(nonce_source); // 96-bits; unique per message
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| KSError::EntropyError("".to_string()))?;
    Ok(plaintext)
}

fn random_generator(length:u8) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut random_number = vec![0; length.into()];
    rng.fill_bytes(&mut random_number);
    random_number
}

fn serialize_key_storage(key_storage: &KeyStorage) -> Result<(), KSError> {
    let key_json = serde_json::to_vec(key_storage).map_err(|_| KSError::EntropyError("".to_string()))?;
    let filename = format!("{}.json", key_storage.id);
    
    match Path::new(&filename).try_exists() {
        Ok(result) => {
            if result {
                fs::remove_file(&filename).map_err(|_| KSError::EntropyError("".to_string()))?   
            }
            let mut f = File::create(&filename).map_err(|_|KSError::GetPublicKeyError("()".to_string()))?;
            f.write_all(&key_json);
            Ok(())
        },
        Err(_) => Err(KSError::GetPublicKeyError("()".to_string()))
    }
    
}


mod tests {
    use super::*;
    use hex;
    
    #[test]
    fn test_generate_entropy() {
        let entropy = KeyManager::generate_entropy(EntropyLength::Long);
        assert_eq!(entropy.len(), 32);
        let entropy = KeyManager::generate_entropy(EntropyLength::Short);
        assert_eq!(entropy.len(), 16);
    }

    #[test]
    fn test_entropy_to_memnonic() {
        let tmp_entropy = [0u8; 16];
        let memnonic = KeyManager::entropy_to_memnonic(&tmp_entropy).unwrap();
        assert_eq!(memnonic, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string())
    }

    #[test]
    fn test_entropy_to_bip39_seed() {
        let tmp_entropy = [0u8; 16];
        let seed = KeyManager::entropy_to_bip39_seed(&tmp_entropy, "").unwrap();
        let seed_hex = hex::encode(&seed);
        assert_eq!(seed_hex, "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4".to_string())
    }

    #[test]
    fn save_entropy_seed_data_get_data() {
        let entropy = [0u8;16].to_vec();
        let passpharse = "";
        let password = "password";
        let id = KeyManager::save_entropy_seed_data(entropy, passpharse, password).unwrap();
        let content = KeyManager::get_seed_data(id, password).unwrap();
        assert_eq!(hex::encode(content), "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4".to_string())
    }
}