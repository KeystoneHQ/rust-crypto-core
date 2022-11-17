#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod error;
mod keymaster;

use alloc::{vec::Vec, string::{String, ToString}, boxed::Box};
use error::KSError;

use keymaster::{KeyMaster, local::Mini};
#[cfg(target_os = "android")]
use keymaster::se::SecureElement;
pub use keymaster::SigningAlgorithm;

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

    pub fn new_with_mini() -> Self {
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


use alloc_cortex_m::CortexMHeap;
use core::{alloc::Layout};
use core::panic::PanicInfo;
use cstr_core::{CString, c_char};


#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

#[no_mangle]
pub extern "C" fn test_rust_sign() -> *mut c_char {
    
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 1024;
        static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { ALLOCATOR.init(HEAP.as_ptr() as usize, HEAP_SIZE) }
    }


    let fake_signer = Signer::new_with_mini();
        let path = "m/44'/60'/0'/0/0".to_string();

        let data: Vec<u8> = hex::decode(
            "af1dee894786c304604a039b041463c9ab8defb393403ea03cf2c85b1eb8cbfd".to_string(),
        )
        .unwrap();

        let signature = fake_signer
            .sign_data(0, "test_pass".to_string(), data, SigningAlgorithm::Secp256k1, path)
            .unwrap();

        let c_string_sig = CString::new(signature).unwrap();
        c_string_sig.into_raw()
}


#[alloc_error_handler]
fn oom(_: Layout) -> ! {
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}


#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use k256::ecdsa::signature::Signature as _;
    use k256::ecdsa::digest::Digest;
    use k256::ecdsa::{recoverable::Signature, SigningKey};
    use super::keymaster::hash_wraper::ShaWrapper;
    use super::*;
    
    #[test]
    fn it_should_pass_test_sign() {        
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
}
