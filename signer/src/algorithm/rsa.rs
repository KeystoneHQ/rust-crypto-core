use bytes::BytesMut;
use rsa::{BigUint, pkcs8::{EncodePrivateKey}, PublicKeyParts, rand_core, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::pss::{VerifyingKey, Signature};
use crate::algorithm::SecretKey;
use crate::{KSError, SigningOption};
use rsa::signature::{RandomizedDigestSigner, Verifier,SignatureEncoding};

pub const MODULUS_LENGTH: usize = 4096;
// secret = p || q || d || n
pub const PRIME_LENGTH_IN_BYTE: usize = MODULUS_LENGTH / 8 / 2;
pub const MODULUS_LENGTH_IN_BYTE: usize = MODULUS_LENGTH / 8;
pub const SECRET_LENGTH_IN_BYTE: usize = PRIME_LENGTH_IN_BYTE * 2 + MODULUS_LENGTH_IN_BYTE * 2;
pub const RSA_DERIVATION_PATH: &str = "m/44'/472'";

pub struct RSA {
    private_key: RsaPrivateKey,
}

impl SecretKey for RSA {
    fn from_secret(secret: &[u8]) -> Result<RSA, KSError> {
        if secret.len() != SECRET_LENGTH_IN_BYTE {
            return Err(KSError::GenerateSigningKeyError("invalid secret length".to_string()));
        }
        let mut p = BytesMut::with_capacity(PRIME_LENGTH_IN_BYTE);
        p.extend_from_slice(&secret[0..PRIME_LENGTH_IN_BYTE]);
        let mut q = BytesMut::with_capacity(PRIME_LENGTH_IN_BYTE);
        q.extend_from_slice(&secret[PRIME_LENGTH_IN_BYTE..PRIME_LENGTH_IN_BYTE * 2]);
        let mut d = BytesMut::with_capacity(MODULUS_LENGTH_IN_BYTE);
        d.extend_from_slice(&secret[PRIME_LENGTH_IN_BYTE * 2..PRIME_LENGTH_IN_BYTE * 2 + MODULUS_LENGTH_IN_BYTE]);
        let mut n = BytesMut::with_capacity(MODULUS_LENGTH_IN_BYTE);
        n.extend_from_slice(&secret[PRIME_LENGTH_IN_BYTE * 2 + MODULUS_LENGTH_IN_BYTE..PRIME_LENGTH_IN_BYTE * 2 + MODULUS_LENGTH_IN_BYTE * 2]);
        let e = vec![01, 00, 01];
        let private_key = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&n),
            BigUint::from_bytes_be(&e),
            BigUint::from_bytes_be(&d),
            [BigUint::from_bytes_be(&p), BigUint::from_bytes_be(&q)].to_vec(),
        ).map_err(|_| KSError::GenerateSigningKeyError("failed to compose rsa signing key".to_string()))?;
        Ok(Self {
            private_key
        })
    }

    fn sign(&self, data: Vec<u8>, signing_option: Option<SigningOption>) -> Result<Vec<u8>, KSError> {
        match signing_option {
            Some(SigningOption::RSA {salt_len})=>{
                let parsed_salt_len: usize = salt_len.try_into().map_err(|_|KSError::RSASignError)?;
                let signing_key = rsa::pss::SigningKey::<sha2::Sha256>::new_with_salt_len(self.private_key.clone(), parsed_salt_len);
                let mut rng = ChaCha20Rng::from_seed([42; 32]);
                let mut digest = sha2::Sha256::new();
                digest.update(data);
                let signature = signing_key.sign_digest_with_rng(&mut rng, digest);
                Ok(signature.to_vec())
            }
            _=>Err(KSError::RSASignError)
        }

    }
}

impl RSA {
    pub fn from_seed(seed: &[u8]) -> Result<Vec<u8>, KSError> {
        let mut intermediate;
        let mut hash = &seed[..];
        for _ in 0..2 {
            intermediate = Sha256::digest(&hash);
            hash = &intermediate[..];
        }
        let rng_seed: [u8; 32] = hash.try_into().map_err(|_| KSError::GenerateSigningKeyError("rsa generate chacha20 rng_seed failed".to_string()))?;
        let mut rng = ChaCha20Rng::from_seed(rng_seed);
        let private_key =
            RsaPrivateKey::new(&mut rng, MODULUS_LENGTH).map_err(|_| KSError::GenerateSigningKeyError("generate rsa private key failed".to_string()))?;
        let mut secret = BytesMut::with_capacity(PRIME_LENGTH_IN_BYTE * 2 + MODULUS_LENGTH_IN_BYTE * 2);
        secret.extend_from_slice(&private_key.primes()[0].to_bytes_be());
        secret.extend_from_slice(&private_key.primes()[1].to_bytes_be());
        secret.extend_from_slice(&private_key.d().to_bytes_be());
        secret.extend_from_slice(&private_key.n().to_bytes_be());
        Ok(secret.to_vec())
    }

    pub fn keypair_modulus(&self) -> Vec<u8> {
        self.private_key.n().to_bytes_be()
    }

    pub fn verify(&self, signature: &[u8], message: &[u8]) -> Result<(), KSError> {
        let pub_key: RsaPublicKey = self.private_key.clone().into();
        let verifying_key: VerifyingKey<sha2::Sha256> = VerifyingKey::new(pub_key);
        verifying_key.verify(
            message,
            &Signature::try_from(signature).unwrap(),
        ).map_err(|_| KSError::RSAVerifyError)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use hex;
    use super::*;

    #[test]
    fn test_sign_verify_salt_zero() {
        let seed_bytes = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        let secret = RSA::from_seed(&seed_bytes).unwrap();
        let rsa = RSA::from_secret(&secret).unwrap();
        let message = hex::decode("00f41cfa7bfad3d7b097fcc28ed08cb4ca7d0c544ec760cc6cc5c4f3780d0ec43cc011eaaab0868393c3c813ab8c04df").unwrap();
        let signing_option = SigningOption::RSA {salt_len: 0};
        let signature = rsa.sign(message.clone(), Some(signing_option)).unwrap();
        assert_eq!(hex::encode(signature.clone()), "a8e58c9aa9a74039f239f49adca18ea5d54b9d28852b7d39b098a96230ebe4b07bf1f66eea2ef3ee29ab912f90508917703ca9838f228b0f75014ea5d41101f7dff194d8086010aa92b6e6d04a56ed6cb7bd63c3dc15f833c0fcbeb03a16892ed715f7b178c20dbb6cd9923ddd0ab4b1c8753a554a8165ff34224fb630445582d3b588581deca41dbcf2144dcf10a362510178af9923e9f6cdf30dfaafa5642a20f777a4a9bff7170517d9a4347a2f0e360a38bf90a8b5d10f80f2581422798aa7b77d959f237a77d71b35558349e35f9c1193154bcf252d79171abeec6f37858584f878503af44a3553eb218b86dc31dfcca66dea947364580515bb2543d2403d53866ee16bba1b8e51ba060a5ecfef3ef4617d96fa3a3f67176621e638ad7e33bf08c56409f0ce01ef345ac4b49ba4fd94dbaf11b544f4ce089d9adcebf5b592afd2f8cecf22f21539975e50441fe3bf5f77d7d0fcfa2bd3c6e2cbf1bb59ed141b5c0f257be5958c5b46c9f08ec1e912b7fa6ff7182aa9010ce9f0cd6fc4845760a37f97197ea8ad3fa8a75b742e9ad61f877acd5771e7c43e0c75a422eb7d96153d4c561469c0f6011d0fe74f718b2db26894e3c5daf72784d34374c4dab78c3ff7619f883085a45efe1781cfcdb80b64b4c8aa96f86225144ca9430a499e96c607a77538ad7fb920fdd1126cdc8c5574ed3c2b1fb1dadac51ad4e13fdd9d");
        let result = rsa.verify(&signature.as_ref(), message.as_slice());
        assert_eq!(result.ok(), Some(()));
    }

    #[test]
    fn test_sign_verify_salt_digest() {
        let seed_bytes = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        let secret = RSA::from_seed(&seed_bytes).unwrap();
        let rsa = RSA::from_secret(&secret).unwrap();
        let message = hex::decode("00f41cfa7bfad3d7b097fcc28ed08cb4ca7d0c544ec760cc6cc5c4f3780d0ec43cc011eaaab0868393c3c813ab8c04df").unwrap();
        let signing_option = SigningOption::RSA {salt_len: 32};
        let signature = rsa.sign(message.clone(), Some(signing_option)).unwrap();
        let result = rsa.verify(&signature.as_ref(), message.as_slice());
        assert_eq!(result.ok(), Some(()));
    }

    #[test]
    fn test_private_key_recover() {
        let d = hex::decode("542fd4042926629451ee9a4dace812428b6494acbf45370ddd2308c01e9ab9bf3974b561d5064f6f315f1a39632024bc18f2738c3acb11a1c1d25919477b0acc4f3e8b865aa50a9c3e781535079a06a668aa262ed675bb8ff979b93b5c877044528a0a89aa0a13855b37d96d1c213f237c2739a26aeca46427c517ecf0bc778becda2afb0be236988ed5d162c87ecca8db123af41129f8dfb3893f66293c64dd09d7313190ae66af5a2bef053ed25594a97bda6aa2c7eff560c815b9fe28ce2b68e89988a88322c34ef0e7e4c0822b2018545379900553d18c71de88bed451ef814c739296586d238bef428945ecb9f1eda9c098ba2345daf59229659b1588f2374438e978f94cf03ece881ded34790416d0f746b0701f7096aa74f381a21725dba3702b32670a5db7693763e95e751ae0ef5cd875ac38a4427dd716dd1d61d6c0e234ff64f80dbf0f1c2632883ac74b9e9387ad58e5ca928b7880d9844b513b448447c31b94d04160cfa83b0381b4e59b23deafd1cca01639e405bc494fa63758246eab4d25f94a6c2dfed72be6127217d7f806b05b573070850307a8c594233851a7efdb55e27f1624f2a9ca2a0c3e803024b1cbce919e7ae7e0b730d357a6ca62cd15978940f7998524404cb5837ccc93bca22caeb5156aa36abd92c83e047addef10d2e8f78e8c94a50fc305f9fe35a7f45f76271bd794b2f111db2eae41").unwrap();
        let n = hex::decode("c41a50ed2155a5740b45df8e3815774d6b8d193e5ad80c9efaaf6d6d0253f350c85becf39eb7056d75841f6a064acf8381383eceb218e16859ef72be7273321a2b4855b87bc6f14c734e2a9c90850c34a8a0a4279ac9be3186b086db5b302fb68176b4c1fee337456c42f972c7993f618fdedc0bf1658c2d59cf2c0c6ac31a61ac1260e0fd4a761ca3707e27611c14b4c6b6abe698c11009ddf5d1511ae47ea271079b6892d229a27d0822e0c7aa12a4cf7f7c28fe23d201eae2adb7f403c9c5a1762c2d8cc96898ce41fe529ab0ef8184e50063e6fc62e0a808e8602254c142c9e7f7e94e6ef2c767ac0e99810d09a44bfde8db46298bc0e25b4a333b4ef86cd7ce658ff661ab0d1789b603b8770a6b433851a91c8ff07a7a8a0767702f6887098ea34bf4a8309eaab9baadd16d45cdd9b1899b6a303a2dce23745cec9fc2ecd9735a66c77fdea1bfd4cdb2be7bfb407a4fd5d3405c3cb33b5316e16559f0c4bf0bc7d1a3ada78917217b289c4d75eb60e0396f03035fd8d553727c790189cfd8dabcee8a4ae6607925b9a27ff7ad7ede26b98f8acd2532cf3175693f3eede9989a0aeedbdb3ff14fec823017531aead4cd22733ab30dbce76cebcdac64424128d6eeff3cdc1825d7cdb7113e74db126e6d931544467c6979aa8d50ac803f36084ed7077f34acfcf3f77bb13d5ebb723fc5d3f45212d2dd6ef20ea757fb4c95").unwrap();
        let p = hex::decode("fdec3a1aee520780ca4058402d0422b5cd5950b715728f532499dd4bbcb68e5d44650818b43656782237316c4b0e2faa2b15c245fb82d10cf4f5b420f1f293ba75b2c8d8cef6ad899c34ce9de482cb248cc5ab802fd93094a63577590d812d5dd781846ef7d4f5d9018199c293966371c2349b0f847c818ec99caad800116e02085d35a39a913bc735327705161761ae30a4ec775f127fbb5165418c0fe08e54ae0aff8b2dab2b82d3b4b9c807de5fae116096075cf6d5b77450d743d743e7dcc56e7cafdcc555f228e57b363488e171d099876993e93e37a94983ccc12dba894c58ca84ac154c1343922c6a99008fabd0fa7010d3cc34f69884fec902984771").unwrap();
        let q = hex::decode("c5b50031ba31ab7c8b76453ce771f048b84fb89a3e4d44c222c3d8c823c683988b0dbf354d8b8cbf65f3db53e1365d3c5e043f0155b41d1ebeca6e20b2d6778600b5c98ffdba33961dae73b018307ef2bce9d217bbdf32964080f8db6f0cf7ef27ac825fcaf98d5143690a5d7e138f4875280ed6de581e66ed17f83371c268a073e4594814bcc88a33cbb4ec8819cc722ea15490312b85fed06e39274c4f73ac91c7f4d1b899729691cce616fb1a5feee1972456addcb51ac830e947fcc1b823468f0eefbaf195ac3b34f0baf96afc6fa77ee2e176081d6d91ce8c93c3d0f3547e48d059c9da447ba05ee3984703bebfd6d704b7f327ffaea7d0f63d0d3c6d65").unwrap();
        let e = base64::decode("AQAB").unwrap();
        let priv_key = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&n),
            BigUint::from_bytes_be(&e),
            BigUint::from_bytes_be(&d),
            [BigUint::from_bytes_be(&p), BigUint::from_bytes_be(&q)].to_vec(),
        );
        let seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        let mut intermediate;
        let mut hash = seed.as_slice();

        for _ in 0..2 {
            intermediate = sha2::Sha256::digest(&hash);
            hash = &intermediate[..];
        }

        let rng_seed: [u8; 32] = hash.try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(rng_seed);
        let expected =
            RsaPrivateKey::new(&mut rng, MODULUS_LENGTH);
        assert_eq!(priv_key == expected, true);
    }
}