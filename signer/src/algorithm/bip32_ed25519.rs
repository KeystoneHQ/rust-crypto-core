use std::str::FromStr;
use bitcoin::bip32::{ChildNumber, DerivationPath};
use ed25519_bip32_core::{DerivationScheme, XPrv, XPub};
use cryptoxide::sha2::Sha512;
use cryptoxide::{pbkdf2, hmac};

pub fn get_icarus_master_key(entropy: &[u8], passphrase: &[u8]) -> XPrv {
    let mut hash = [0u8; 96];
    let digest = Sha512::new();
    let iter_count = 4096;
    pbkdf2::pbkdf2(
        &mut hmac::Hmac::new(digest, passphrase),
        entropy,
        iter_count,
        &mut hash,
    );
    XPrv::normalize_bytes_force3rd(hash)
}

pub fn get_extended_private_key(path: &String, icarus_master_key: XPrv) -> Result<XPrv, String> {
    let path = normalize_path(path);
    let derivation_path = DerivationPath::from_str(path.as_str())
        .map_err(|e| format!("{}", e))?;
    let childrens: Vec<ChildNumber> = derivation_path.into();
    let key = childrens
        .iter()
        .fold(icarus_master_key, |acc, cur| match cur {
            ChildNumber::Hardened { index } => acc.derive(DerivationScheme::V2, index + 0x80000000),
            ChildNumber::Normal { index } => acc.derive(DerivationScheme::V2, index.clone()),
        });
    Ok(key)
}

pub fn get_extended_public_key(path: &String, icarus_master_key: XPrv) -> Result<XPub, String> {
    let xprv = get_extended_private_key(path, icarus_master_key)?;
    Ok(xprv.public())
}

pub fn sign_message(message: &[u8], path: &String, icarus_master_key: XPrv) -> Result<[u8; 64], String> {
    let xprv = get_extended_private_key(path, icarus_master_key: XPrv)?;
    let sig = xprv.sign::<Vec<u8>>(message);
    Ok(sig.to_bytes().clone())
}

pub fn normalize_path(path: &String) -> String {
    let mut p = path.to_lowercase();
    if !p.starts_with("m") {
        p = format!("{}{}", "m/", p);
    }
    p
}
