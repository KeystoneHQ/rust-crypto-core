use bytes::BytesMut;
use ring::{
    digest::{Context, SHA256, SHA384},
    rand::{self, SecureRandom},
    signature::{self, KeyPair, RsaKeyPair},
};

use rsa::{BigUint, PaddingScheme, pkcs8::{EncodePrivateKey, LineEnding}, PublicKey, PublicKeyParts, rand_core, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use rsa::pkcs1::EncodeRsaPublicKey;
use rand_core::SeedableRng;
use hex;
use rand_chacha::ChaCha20Rng;
use crate::algorithm::error::AlgError;
use crate::keymaster::hash_wraper::ShaWrapper;

const MODULUS_LENGTH: usize = 4096;

pub struct RSA {
    keypair: RsaKeyPair
}

impl RSA {
    pub fn new(seed: &[u8]) -> Result<Self, AlgError> {
        let mut intermediate;
        let mut hash = &seed[..];

        for _ in 0..2 {
            intermediate = Sha256::digest(&hash);
            hash = &intermediate[..];
        }

        let rng_seed: [u8;32] = hash.try_into()?;
        let mut rng = ChaCha20Rng::from_seed(rng_seed);
        let private_key =
            RsaPrivateKey::new(&mut rng, MODULUS_LENGTH).expect("failed to generate a key");
        println!("private_key pem {:?}", private_key.to_pkcs1_pem(LineEnding::CR).unwrap());
        println!("private key d {:?}, n {:?}, primes1 {:?} primes2 {:?}",hex::encode(private_key.d().to_bytes_be()), hex::encode(private_key.n().to_bytes_be()), hex::encode(private_key.primes()[0].to_bytes_be()), hex::encode(private_key.primes()[1].to_bytes_be()));
        let private_key_der = private_key.to_pkcs8_der().expect("failed to convert key to der format");
        let keypair = RsaKeyPair::from_pkcs8(&private_key_der.as_bytes())?;
        Ok(Self {
            keypair
        })
    }

    pub fn keypair_modulus(&self) -> Result<Vec<u8>, AlgError> {
        let modulus = self
            .keypair
            .public_key()
            .modulus()
            .big_endian_without_leading_zero();
        Ok(modulus.to_vec())
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AlgError> {
        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; self.keypair.public_modulus_len()];
        self.keypair
            .sign(&signature::RSA_PSS_SHA256, &rng, message, &mut signature)?;
        Ok(signature)
    }

    pub fn verify(&self, signature: &[u8], message: &[u8]) -> Result<(), AlgError> {
        let public_key = signature::UnparsedPublicKey::new(
            &signature::RSA_PSS_2048_8192_SHA256,
            self.keypair.public_key().as_ref(),
        );
        public_key.verify(message, signature)?;
        Ok(())
    }
    pub fn from_secret(secret: &[u8]) -> Result<Self, AlgError> {
        if (secret.len() != 1536){
            return Err(AlgError::SecretError(format!("invalid rsa secret {:?}", secret.len())));
        }
        let secret_slice: [u8;1536] = secret.try_into()?;
        let mut p = BytesMut::with_capacity(256);
        p.extend_from_slice(&secret[0..256]);
        let mut q = BytesMut::with_capacity(256);
        q.extend_from_slice(&secret[256..512]);
        let mut n = BytesMut::with_capacity(512);
        n.extend_from_slice(&secret[512..1024]);
        let mut d = BytesMut::with_capacity(512);
        d.extend_from_slice(&secret[1024..1536]);
        let e = vec![01,00,01];
        let private_key = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&n),
            BigUint::from_bytes_be(&e),
            BigUint::from_bytes_be(&d),
            [BigUint::from_bytes_be(&p),BigUint::from_bytes_be(&q)].to_vec()
        ).map_err(|e| AlgError::SecretError(format!("failed to compose rsa private key {:?}", e)))?;
        let private_key_der = private_key.to_pkcs8_der().map_err(|e| AlgError::SecretError("failed to convert private key to der format".to_string()))?;
        let keypair = RsaKeyPair::from_pkcs8(&private_key_der.as_bytes())?;
        Ok(Self {
            keypair
        })
    }
}

#[cfg(test)]
mod tests {
    use ring::test::from_hex;
    use rsa::BigUint;
    use hex;
    use super::*;
    use base64;

    #[test]
    fn test_sign_verify() {
        let seed_bytes = hex::decode("a54e6b29511e6782eaace0a157dae976b14d34dc0bcd736c8a6551f795b71ea8").unwrap();
        let rsa = RSA::new(&seed_bytes).unwrap();
        let message = String::from("hello, world");
        let signature = rsa.sign(&message.as_bytes()).unwrap();
        println!("signature: {:}",hex::encode(signature.clone()));
        let result = rsa.verify(&signature.as_ref(), &message.as_bytes());
        assert_eq!(result.ok(), Some(()));
    }

    #[test]
    fn test_private_key_recover(){
        let d = from_hex("66f6241e0021d609eabc0cfd5fb767d65821baeeecfedcb3b6adc57e68257993821c4ddfc37cc27445fdc06d1ee763cfbb87c7f39dc59f2cd094bb1c9a7966188efa3748274ab97d7c8fd6bc1ad58db60767774d02c83ea246d7218b5bf1c88eda7330019c93fddaf8f8961036f7877f26ae7a7eb2dc4e629859bbf53cdbc4aabbd86d5fd7988a3ee7afd5cbd9b4b50a251fd7d7975efadc5850a3a9e6951372edef7cab630c01881804f8c27a2d9107bfa7fb58c1de2f0ae26bbde2a277e0938a019abccad7f612faf81c2fea077791001e918d4dd8c272cb7bb7ff550571f5e8bd6c420348fe205a9714ab2084a628ebab1fea761dd51d97a24f46f3651771cbe6165822804281c21fafc32b2b5c60bd3ecc6df745df6a69337f3a2382c1e833cd90f587be5b833232e4d707b9095a34c7dc7b29dc29f961c900e097516f02216f8a329068826d95b6f9704862a39a2d1d60450bef9518b37216d6f82bff834d043a75531f9ddc19a63529c0453f82060a30f1e6053220ef5996daf46b4e4aef3283fe1d7e45975706a8f08313f2e7c1bb7e6be7d8c5a7b348b1e40d78ddb33ae61bcfc263dd03a53d1d71280499be9e0952fe5d2165557179303ecaedcf145279efd813b5e0f4029a121bfb5ba998a7dab7cf20ba3683d3a40680abd56dfa0bee2cd8fa8f123182ee2c37af0f97bdda17ecb22207d8f197e3cfee218cd501").unwrap();
        let n = from_hex("b0feeb5f684b922b3fd4f808402c50c76807380f8641c3953a7bcc3054e71cd3bbaae8866a4994f1afcf7b104ca25bbf35be3791975ce32464ae3ca8806e057055a5bd599f0e448c2414dd8301618803cb7210859d3ec7da6ee2e9db81f47b05948566e0cafd5b734d07dd08b59fabb490cfcb7184ae2ab31795c5999dc0ff5185cf3b1ebbe9c5c3afa093ce93242bef4ecafc43405f873511bbe9142fcdadb3ac89454a5f66d2a955874c328418adc3ad7c3151c4e6c8eafa89cadc4e493d737cbe855fe65aa18019dc1c186e2ca6cd5047e3493e0f4fe0b8ad6e02d3bd8ace8402d3b45c262678dfa15763b6149e903fbd093259489f9f9b01bd12f43c589517c60a2685f5b5481f6f9b9524d9a4bdb19119bbb365723bd1bff90530fc08be403a7bb53319a9b6845bf0df5ef855cfbcb806d1dc98429717609edc5d04e3cc6d141b65d486e59dc115d488bdc29b8675c233cc8c7a6ae1b96396851a6d3837f9621c26e4233dc37d4d019f9d2f845c5a42beccda6fdf91d72382a43f118eae10f8d53a82ccc224634ceb7d365df251621818ac5390f844baafb469de531d9883c9e537a98fd98fbbe7a7f3158aa086dae8b5c4bd39039784eb7118a0ea923caa8e4e2d5b67966756e117322f10fb6c8520abfe46c899a54bcb6ad9699b772ee7760b3911a7a42ab567ad3564bb01f5401c4117146f4ef0fd644ff15fa97641").unwrap();
        let p = from_hex("ccb4700a90a2304b3d93e8b8f8889a9ee97349fdf6a9dc423768d5e14ea3e43bd058eb6526ba837f54e2eb516b3f93b536a5f36c86ea37c053e759b16f83393e4fda9b37119b352d5099ae248020111608b281bcd33ec84c651162e654e059a294cdcba59f1b67c29e2cfd3bf751cc50a5ed7ab47e7939ead0a330b4acc80a7c36e9f0d19e23f1d5dfccedb53cc1cafe4d48af1a94edd27dc8542583ec17b64ecaf1f1c9b46921ecd4ed6ec79727ca6dd215f8e8c533474cdc566e13fdd3979f8f146553027bb15b611031e4c2cd83fd73385aee17de39ef9a39e3d57a85b50ab8cef9f97d042c02cb8f9d785a8afc544bd552426ac0b8ae1521c3b3d7dfc489").unwrap();
        let q = from_hex("dd58fae58fcb39fb5fb690dd034fc7b8eb32c71652958fb01c4d4000de182e1afd1fdf872fc606e9df25ec96c21c820c5ab483cf7114cf09eed60d7a0e20a21fc57d52efcfc40d553ac302f7f4fc931c00484e79e60ebedd5d0f0298171a72fcfcbe2a5a8dde2b7ff2be787a2c70a4a18b5edc9aa2c592c8592f751e4fedb10ff1df7d81837a75c072ce80a5b3b0e721bc56dd6b58cebb164f95c83d1c3c06dc66222c476d0e39aae42dcd871a36e1c97a39af22d2ee453af41eecc744a59e1151a318c8b418da7a690e9d54da6aeac4727fcec7fb1137d6126cf4f97164edbcf9712799f0d21ea0e8b0eebe02f7990671dc7818d08201b7a92f1362aadfa5f9").unwrap();
        let e = base64::decode("AQAB").unwrap();
        let priv_key = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&n),
            BigUint::from_bytes_be(&e),
            BigUint::from_bytes_be(&d),
            [BigUint::from_bytes_be(&p),BigUint::from_bytes_be(&q)].to_vec()
        );
        let seed_bytes = hex::decode("a54e6b29511e6782eaace0a157dae976b14d34dc0bcd736c8a6551f795b71ea8").unwrap();
        let rng_seed: [u8;32] = seed_bytes.try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(rng_seed);
        let expected =
            RsaPrivateKey::new(&mut rng, MODULUS_LENGTH);
        assert_eq!(priv_key==expected,true);
    }
}