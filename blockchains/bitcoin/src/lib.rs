#![no_std]

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate core as std;
extern crate alloc;

use alloc::string::{ToString, String};
use crate::error::{BitcoinError, Result};
use std::str::{FromStr};
use bitcoin::util::{base58};
use bitcoin::util::bip32::{ExtendedPubKey, DerivationPath};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address};
use xyzpub::{convert_version, Version};

mod error;

pub fn derive_address(xpub: String, path: String, script_type: String) -> Result<String> {
    let converted_xpub = convert_version(xpub, &Version::Xpub)
        .map_err(|_| BitcoinError::AddressCalculationFailed(String::from("xpub is not valid")))?;
    let xpub_key = base58::from_check(&converted_xpub)
        .map_err(|_| BitcoinError::AddressCalculationFailed(String::from("xpub is not valid")))?;
    let extended_pub_key = ExtendedPubKey::decode(&xpub_key)
        .map_err(|_| BitcoinError::AddressCalculationFailed(String::from("xpub is not valid")))?;

    let secp = Secp256k1::new();
    let path = DerivationPath::from_str(path.as_str())
        .map_err(|_| BitcoinError::AddressCalculationFailed(String::from("path is not valid")))?;
    let address_xpub = extended_pub_key.derive_pub(&secp, &path)
        .map_err(|_| BitcoinError::AddressCalculationFailed(String::from("error occurs in derivation")))?;
    let address_pubkey = address_xpub.to_pub();

    let address: Result<String> = match script_type.as_str() {
        "P2PKH" => Ok(Address::p2pkh(&address_pubkey, extended_pub_key.network).to_string()),
        "P2SH-P2WPKH" => Ok(Address::p2shwpkh(&address_pubkey, extended_pub_key.network)
            .map_err(|_| BitcoinError::AddressCalculationFailed(String::from("error occurs for derive P2SH-P2WPKH")))?.to_string()),
        "P2WPKH" => Ok(Address::p2wpkh(&address_pubkey, extended_pub_key.network)
            .map_err(|_| BitcoinError::AddressCalculationFailed(String::from("error occurs for derive P2WPKH")))?.to_string()),
        _ => Err(BitcoinError::AddressCalculationFailed(String::from("script type is not supported")))
    };
    address
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::std::string::String;

    // they audit color point vague response vital voice slogan coil depth vehicle
    #[test]
    fn test_derive_p2pkh_address() {
        let xpub = String::from("xpub6CPbc6auq3b8rEkXz6y78esTJ1SXLZwTJezUxoE8B7KZDfKo1qwJkHziR8MMat7P6RNf3aUPrUpMuKFQ8TRbfenCk6UvzCJXs1dHBdz2vcE");
        let path = String::from("m/0/0");
        let script_type = String::from("P2PKH");

        let address = derive_address(xpub, path, script_type).unwrap();
        assert_eq!(address.as_str(), "1Kw42PtjJV4VWYzDfaPekqy1V4kgXEpqz8");
    }

    #[test]
    fn test_derive_p2sh_p2wpkh_address() {
        let xpub = String::from("ypub6XK3HDTWbMt2TR2psR2sdrS5n6Kxd5P2zWKnPNRyZ3nK7fxvjkshnn6pmzmY7aKyf4LzvokW9pZTyHddMVy1utGgVRR22QZAEiDtm4orKqC");
        let path = String::from("m/0/1");
        let script_type = String::from("P2SH-P2WPKH");

        let address = derive_address(xpub, path, script_type).unwrap();
        assert_eq!(address.as_str(), "33TNSSsGqqrUKd7gnNvW2zfFSZ2UHqcZ3Z");
    }

    #[test]
    fn test_derive_p2wpkh_address() {
        let xpub = String::from("zpub6rMTvPvUKBmiHGygNQo2znmhF38gUvcu9WNdARryhdAewa1G2gWJiSvngKd99SpvgiQaiKdo5ymxjtc4HUmaQdDXPMzM2NyohatdNayrVZE");
        let path = String::from("m/0/2");
        let script_type = String::from("P2WPKH");

        let address = derive_address(xpub, path, script_type).unwrap();
        assert_eq!(address.as_str(), "bc1qucfwrtt6ey9643kemey92qvqcf7jkdxyts7dh5");
    }

    #[test]
    fn test_derive_address_error() {
        let xpub = String::from("xpub6CPbc6auq3b8rEkXz6y78esTJ1SXLZwTJezUxoE8");
        let path = String::from("m/0/1");
        let script_type = String::from("P2PKH");

        let address = derive_address(xpub, path, script_type).unwrap_err();
        let expected = BitcoinError::AddressCalculationFailed(String::from("xpub is not valid"));
        assert_eq!(expected, address);
    }
}
