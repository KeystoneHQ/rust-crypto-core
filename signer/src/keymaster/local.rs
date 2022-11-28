
use super::{KeyMaster, SigningAlgorithm, hash_wraper::ShaWrapper};
use crate::error::KSError;
use k256::ecdsa::{recoverable::Signature, signature::DigestSigner, SigningKey, digest::Digest};
use openssl::sign::RsaPssSaltlen;
use zeroize::Zeroizing;
use crate::SigningAlgorithm::RSA;
use crate::{algorithm, SigningOption};
use crate::algorithm::SecretKey;
use crate::keymaster::se::GetKeyType;

pub struct Mini;

impl KeyMaster for Mini {
    fn generate_entropy(&self, length: super::EntropyLength) -> Result<Vec<u8>, KSError> {
        Err(KSError::SEError("this function is not supported for now".to_string()))
    }
    fn get_rsa_public_key(&self, mnemonic_id: u8, password: String) -> Result<Vec<u8>, KSError> {
        Ok(vec![])
    }

    fn sign_data(
        &self,
        mnemonic_id: u8,
        password: String,
        data: Vec<u8>,
        algo: super::SigningAlgorithm,
        derivation_path: String,
        signing_option: Option<SigningOption>
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
                let private_key = hex::decode("78707276413436797257796b4668334c6a4d486e3165716b374138574e4274374a7a4a714565425831524e7a32627839446974753670654b374d4a5752387466585571506a574e754c374c774c76706864676b5753684e705958694a42757669396167784a555769484748746f4e6b").map_err(|_e|KSError::SEError("hex key decode error".to_string()))?;
                let zeroize_secret = Zeroizing::new(private_key);
                let secp245k1 = SigningKey::from_secret(zeroize_secret.as_slice())?;
                let signature = secp245k1.sign(data, None)?;
                Ok(signature)
            },
            SigningAlgorithm::RSA => {
                // get rsa secret from SE
                let secret = hex::decode("ecb84da6962da6b6d00841f4e14a6ca8397ab3c01ba89c23ebea59df4c6de6c6e65fa0d7488e6e00d88664e7b6dbe3f0e26fdff085d1436c27b59423ab57b25b2eec6261cfb95adf57998999b569f648d74bd333dc0f48368b74fde766b9ca1d2ab0ee3d1af225900952707563b4f0d0e2c93c011325dc5b225b02e00b9c15c93fe2d69e303769922854f082e0a3b25c2b1fda767145a6c4fd692eacee023e38bf8011591768c96ad980be3bc039c179a31db84fbb0a7bda943dedf8ef0660838cfda7d5e9f72c2544ef36bd6ec2e6f70a4b12996948b5501d4bf411154d9d19f8dde7b07c00b8ae11319b69fe6cae77e8384c49630da95c086d1fc1e15af0e5d32c0cc5a870a34a42138d5d5db729176706cd9dea01f321385ec2430600983392db2e376262e54aad9635e3b62e758a436ab72c038d168237a1c439f512aff4b10709a56171f53b8029672b7805d3d828f2518366d1b8e76ce2dd8896e309840329f3c0f9c0c7f2a730eb72581ffafe9792a59775895c3a1b3c37025afc9b857f28570d69efbf964713af4c8b69a6053c60cccba7b26a457fbc9567f7820cf085d2eb6acb509664f43783e7d90222244b1cf6c62e0fc1341397d1e048e80c5d37637dee7f5dc339d91bca5084bdf0ecb037980a866a78ddbeb38631d4c7cc671661949d3e9c878de8ac545dc9910b3317755b84e12567a8ffc0e8ce90e193215ca82353e2a92f636376152b7392d066a14da70b03bf0162f31ad5c28c3eaf19ec5ea28701b3424a38b885e2d02d67c28fb5242e711348384d861bd70d30e0ddef0de8e271e1727decf36430996ba0254868ac4d394bc8feabea77d3414a2c0a75399524681de69c37489453902001155d901cc67dcd485920af624ec74a1e33b9d0894b0ac07c3281109da0b3eea30c39de7c694845fb1c5944b03146197109b3446590a3e18a21ba5dacea8e07c02675d8eecba306df57e8cd3db3e621fa4db333d7c15df500afb7bbcc5705bf063648d9238ae0a3d3e3645c5349b973c2865fa6b3f8470d8ecd3f3bcf424ff01c6183812dbf0103c71f692732ecb36cb5171cef4431f6a5331a06a8352b180941a91c1dda2564580b290329b3d70a0e1ffbd3e05d7053a582d5f723b6c8a67a038aff992d594af11875355f812c3da5a858ab60875b1b8b5bba361b2ab3e074bc97d2df5235cf4dd5e06014d32acc2818320f60da505ca117594db59b55fd716a18c4d2c1cea358f4df8a6f09d5801e4022c8d6750c3ebbe663db77c5d89f3dd8a37067c6bfb9eb284aa92e64637fa8f8af7060f1feec6c481bf86c1ce53da1e7d957f606b50496d0145b1824073754d96fbd6b3c80674f21e978c0f26c06523f9d4889c126fe1f1d939f5fe46bb1f2e06fb3622dc2dd852a89bde8509ad802c1cfd6cd88f5d2718a4843befff246098d01c344a37d0fa21b12591531c89688851b8687c402a83f21f2d5310db9d8ba12589288f06c0a076036397b73e29cb4f900a34160c18776d4f9d71f81cbc061d8b4f8f7f2d4e740ebc2aee46e9b09fedc4392ba3f5e90fdb28a4e47956cfc24873dbbf883099be26b8722e4d8f6ff73ffd8bd0d80da55be3a2bc520efb3af87ec5b68a1a312c0c1f02fa84e184766ae58a21ce67ba4b222a2a6c05788fb189a6d0d0efbad429380d0a8e4843bcca804ba0786292a5de4a8484cdb03c209e0893f8840af012dccfb19581a4e3ce84adcd0dfc5a584418fbcbb6bb19013043455c715b37bdb2d8c4e383b41283597724c1111f61c5c87968564a3644de030c933e1f12334dafc0847ab62025ef2ed65a678612fea7b842c66ce4da3ce4796c14f71f03f8a89e9f20014c6ce84a3fc0e03e5519e4e78e75c2950c794e79ba2c852db57981c89f0b9db9ab3376ddc5d04cef1b25ba0b9089b34af3e30a096dc88654bd5cb79220c3b34341c9abd1736b7e453e5dc37ae9194415fded017c7a5017d0d2f89d354cfac549c6357ae4fa227a19a71e8efcb9f8d9b9b23e37aff383ece2bb7dbc6aefcdf0bcc3f0a0fb1879b1225fe7103c3e79fcd921eccd13f5b86c30c7c53a86fb4574887fb6a968392c1af6b6fd29b1cf91d91dac736b1d0987b33e8225718a3c6d0fd3cab46e2e9bb2cbf7d54fed561a169d08d283fb50519ce518c85").map_err(|_e|KSError::SEError("hex key decode error".to_string()))?;
                let zeroize_secret = Zeroizing::new(secret);
                let rsa = algorithm::rsa::RSA::from_secret(zeroize_secret.as_slice())?;
                match signing_option {
                    Some(SigningOption::RSA {salt_len}) => {
                        let signature = rsa.sign(data, Some(SigningOption::RSA{salt_len}))?;
                        Ok(signature)
                    }
                    _ => Err(KSError::RSASignError)
                }
            }
            _ => Err(KSError::SEError("signing algo is not supported".to_string()))
        }
    }

    fn get_version(&self) -> Result<Vec<u8>, KSError> {
        Err(KSError::SEError("this function is not supported for now".to_string()))
    }
}
