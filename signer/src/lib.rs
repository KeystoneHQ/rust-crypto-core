#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

include!("../build/rust/bindings.rs");

mod error;
mod keymaster;
mod my_alloc;

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use error::KSError;

#[cfg(target_os = "android")]
use keymaster::se::SecureElement;
pub use keymaster::SigningAlgorithm;
use keymaster::{local::Mini, KeyMaster};

pub struct Signer {
    inner: Box<dyn KeyMaster>,
}

impl Signer {
    #[cfg(target_os = "android")]
    pub fn new_with_se(port_name: String) -> Self {
        Self {
            inner: Box::new(SecureElement::new(port_name)),
        }
    }

    pub fn new_with_mini(key: String) -> Self {
        Self {
            inner: Box::new(Mini::new(key)),
        }
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

use core::alloc::Layout;
use core::panic::PanicInfo;
use cstr_core::{c_char, CStr, CString};

#[no_mangle]
pub extern "C" fn test_rust_sign(data: *const c_char, key: *const c_char) -> *mut c_char {
    let data_tmp: &str;
    let key_tmp: &str;
    unsafe {
        let a = CStr::from_ptr(data);
        data_tmp = a.to_str().unwrap();
        let b = CStr::from_ptr(key);
        key_tmp = b.to_str().unwrap();
    }

    let fake_signer = Signer::new_with_mini(key_tmp.to_string());
        let path = "m/44'/60'/0'/0/0".to_string();

        let data: Vec<u8> = hex::decode(
            data_tmp.to_string(),
        )
        .unwrap();

        let signature = fake_signer
            .sign_data(0, "test_pass".to_string(), data, SigningAlgorithm::Secp256k1, path)
            .unwrap();

    let mut sig = [0u8; 65];
    for i in 0..65 {
        sig[i] = signature.get(i).unwrap().clone();
    }
    let result = Box::new(sig);
    Box::into_raw(result) as *mut _
}

#[alloc_error_handler]
fn oom(_: Layout) -> ! {
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {

    }
}

#[cfg(all(test))]
mod tests {
    use super::keymaster::hash_wraper::ShaWrapper;
    use super::*;
    use alloc::string::ToString;
    use k256::ecdsa::digest::Digest;
    use k256::ecdsa::signature::Signature as _;
    use k256::ecdsa::{recoverable::Signature, SigningKey};

    #[test]
    fn it_should_pass_test_sign() {
        let key = "cff92a2f2f081fe10c1319cb8cef1e010df9ed53248476c739c2ee5d78fd5e92".to_string();
        let fake_signer = Signer::new_with_mini(key);
        let path = "m/44'/60'/0'/0/0".to_string();

        let data: Vec<u8> = hex::decode(
            "af1dee894786c304604a039b041463c9ab8defb393403ea03cf2c85b1eb8cbfd".to_string(),
        )
        .unwrap();

        let signature = fake_signer
            .sign_data(
                0,
                "test_pass".to_string(),
                data,
                SigningAlgorithm::Secp256k1,
                path,
            )
            .unwrap();

        let sig: Signature = Signature::from_bytes(signature.as_slice()).unwrap();
        let sk_bytes =
            hex::decode("cff92a2f2f081fe10c1319cb8cef1e010df9ed53248476c739c2ee5d78fd5e92")
                .unwrap();
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
}
