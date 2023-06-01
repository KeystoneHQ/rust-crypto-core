use crate::errors::{CardanoError, R};
use bitcoin::bech32;
use bitcoin::bech32::{ToBase32, Variant};

use cryptoxide::hashing::blake2b_224;
use ed25519_bip32_core::{DerivationScheme, XPub};
use hex;

use cardano_serialization_lib::address::{BaseAddress, RewardAddress, StakeCredential};
use cardano_serialization_lib::crypto::Ed25519KeyHash;

pub enum AddressType {
    Base,
    Stake,
}

pub trait AddressGenerator {
    fn to_bech32(&self) -> R<String>;
}

pub struct CardanoAddress {
    prefix: String,
    header: u8,
    payment: Option<Vec<u8>>,
    stake: Option<Vec<u8>>,
}

impl AddressGenerator for CardanoAddress {
    fn to_bech32(&self) -> R<String> {
        let mut buf = vec![];
        buf.push(self.header);
        if let Some(key) = &self.payment {
            buf.extend(blake2b_224(key))
        }
        if let Some(key) = &self.stake {
            buf.extend(blake2b_224(key))
        }
        Ok(bech32::encode(
            self.prefix.as_str(),
            buf.to_base32(),
            Variant::Bech32,
        )?)
    }
}

impl CardanoAddress {
    pub fn new_mainnet_base_address(payment_key: &[u8], stake_key: &[u8]) -> Self {
        CardanoAddress {
            prefix: "addr".to_string(),
            // 0 | stake type |payment type |  network tag
            header: 0b0000_0001,
            payment: Some(payment_key.to_vec()),
            stake: Some(stake_key.to_vec()),
        }
    }

    pub fn new_mainnet_reward_address(stake_key: &[u8]) -> Self {
        CardanoAddress {
            prefix: "stake".to_string(),
            // 111 | stake type | network tag
            header: 0b1110_0001,
            payment: None,
            stake: Some(stake_key.to_vec()),
        }
    }
}

pub(crate) fn generate_address_by_xpub(xpub: String, index: u32) -> R<CardanoAddress> {
    let xpub_bytes = hex::decode(xpub).map_err(|e| CardanoError::DerivationError(e.to_string()))?;
    let xpub =
        XPub::from_slice(&xpub_bytes).map_err(|e| CardanoError::DerivationError(e.to_string()))?;
    let payment_key = xpub
        .derive(DerivationScheme::V2, 0)?
        .derive(DerivationScheme::V2, index)?
        .public_key();
    let stake_key = xpub
        .derive(DerivationScheme::V2, 2)?
        .derive(DerivationScheme::V2, index)?
        .public_key();
    Ok(CardanoAddress::new_mainnet_base_address(
        &payment_key,
        &stake_key,
    ))
}

pub fn derive_address(xpub: String, index: u32, address_type: AddressType, network: u8) -> R<String> {
    let xpub_bytes = hex::decode(xpub).map_err(|e| CardanoError::DerivationError(e.to_string()))?;
    let xpub =
        XPub::from_slice(&xpub_bytes).map_err(|e| CardanoError::DerivationError(e.to_string()))?;
    match address_type {
        AddressType::Base => {
            let payment_key = xpub
                .derive(DerivationScheme::V2, 0)?
                .derive(DerivationScheme::V2, index.clone())?
                .public_key();
            let payment_key_hash = blake2b_224(&payment_key);
            let stake_key = xpub
                .derive(DerivationScheme::V2, 2)?
                .derive(DerivationScheme::V2, index.clone())?
                .public_key();
            let stake_key_hash = blake2b_224(&stake_key);
            let address = BaseAddress::new(
                network,
                &StakeCredential::from_keyhash(&Ed25519KeyHash::from(payment_key_hash)),
                &StakeCredential::from_keyhash(&Ed25519KeyHash::from(stake_key_hash)),
            );
            address
                .to_address()
                .to_bech32(None)
                .map_err(|e| CardanoError::AddressEncodingError(e.to_string()))
        }
        AddressType::Stake => {
            let stake_key = xpub
                .derive(DerivationScheme::V2, 2)?
                .derive(DerivationScheme::V2, index.clone())?
                .public_key();
            let stake_key_hash = blake2b_224(&stake_key);
            let address = RewardAddress::new(
                network,
                &StakeCredential::from_keyhash(&Ed25519KeyHash::from(stake_key_hash)),
            );
            address
                .to_address()
                .to_bech32(None)
                .map_err(|e| CardanoError::AddressEncodingError(e.to_string()))
        }
    }
}
