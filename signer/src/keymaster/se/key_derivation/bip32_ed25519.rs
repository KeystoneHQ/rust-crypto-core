use ed25519_bip32::{DerivationIndex, DerivationScheme};
use hmac::Hmac;
use sha2::Sha512;

use crate::error::KSError;

// implementation reference: https://cips.cardano.org/cips/cip3/icarus.md
pub fn derive(
    bip39entropy: &Vec<u8>,
    bip39passphrase: &Vec<u8>,
    derivation_path: &String,
) -> Result<Vec<u8>, KSError> {
    let mut pbkdf2_result = [0u8; 96];
    let iter = 4096;
    pbkdf2::pbkdf2::<Hmac<Sha512>>(
        bip39passphrase.as_slice(),
        bip39entropy.as_slice(),
        iter,
        &mut pbkdf2_result,
    );

    let mut xprv = ed25519_bip32::XPrv::normalize_bytes_force3rd(pbkdf2_result);

    let is_public = derivation_path
        .chars()
        .next()
        .ok_or(KSError::KeyDerivationError(format!(
            "invalid path: {}",
            derivation_path
        )))
        .map(|v| v == 'M')?;

    if derivation_path == "m" {
        let mut key = match is_public {
            true => xprv.public().public_key().to_vec(),
            false => xprv.extended_secret_key().to_vec(),
        };
        key.extend(xprv.chain_code().to_vec());
        return Ok(key);
    }

    let remove_prefix = derivation_path.replace("M/", "").replace("m/", "");

    let result = remove_prefix
        .split('/')
        .map(|v| match v.chars().last() {
            Some('\'') => {
                let mut remove_quote = v.to_string();
                remove_quote.pop();
                remove_quote
                    .parse()
                    .map(|n: u32| n + 0x80000000)
                    .map_err(|_| KSError::KeyDerivationError(format!("")))
            }
            Some(_) => {
                let num = v.to_string();
                num.parse()
                    .map_err(|_| KSError::KeyDerivationError(format!("Invalid index: {}", num)))
            }
            _ => Err(KSError::KeyDerivationError(format!("invalid index"))),
        })
        .collect::<Result<Vec<DerivationIndex>, KSError>>()?;

    result
        .iter()
        .for_each(|v| xprv = xprv.derive(DerivationScheme::V2, v.clone()));

    let mut key = match is_public {
        true => xprv.public().public_key().to_vec(),
        false => xprv.extended_secret_key().to_vec(),
    };
    key.extend(xprv.chain_code().to_vec());
    Ok(key)
}

#[cfg(test)]
mod tests {
    use crate::keymaster::se::key_derivation::bip32_ed25519::derive;
    use std::vec;

    #[test]
    fn test_derive() {
        // eight country switch draw meat scout mystery blade tip drift useless good keep usage title
        let bip39entropy = hex::decode("46e62370a138a182a498b8e2885bc032379ddf38").unwrap();
        let bip39passphrase = vec![];
        let derivation_path = "m".to_string();

        let root = derive(&bip39entropy, &bip39passphrase, &derivation_path).unwrap();
        assert_eq!("c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620", hex::encode(root));

        let h0_path = "m/0'".to_string();
        let h0 = derive(&bip39entropy, &bip39passphrase, &h0_path).unwrap();
        assert_eq!("107d01cbcbfee7899c4c2cbcbd476ebcf2cdc7fe8310eb38e943487ef456d245cfff2ce00c52e546177288ce6e8e9349c842183255fa155220dcb6e9a8bc5dea255a0598c4d1d5de7070ddc1a6b16c4f5a06c13e19a1c1fcb24ea7a978d61086", hex::encode(h0));

        let root_passphrase = b"foo".to_vec();
        let root_1 = derive(&bip39entropy, &root_passphrase, &derivation_path).unwrap();
        assert_eq!("70531039904019351e1afb361cd1b312a4d0565d4ff9f8062d38acf4b15cce41d7b5738d9c893feea55512a3004acb0d222c35d3e3d5cde943a15a9824cbac59443cf67e589614076ba01e354b1a432e0e6db3b59e37fc56b5fb0222970a010e", hex::encode(root_1));
    }
}
