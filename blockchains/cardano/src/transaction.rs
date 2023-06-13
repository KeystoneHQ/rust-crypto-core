use crate::errors::{CardanoError, R};
use crate::structs::{CardanoSignarure, ParseContext, ParsedCardanoTx};
use cardano_serialization_lib;
use cardano_serialization_lib::crypto::{Ed25519Signature, PublicKey, Vkey, Vkeywitness};
use crate::traits::ToJSON;

pub fn parse_tx(tx: Vec<u8>, context: ParseContext) -> R<ParsedCardanoTx> {
    let cardano_tx = cardano_serialization_lib::Transaction::from_bytes(tx)?;
    ParsedCardanoTx::from_cardano_tx(cardano_tx, context)
}

pub fn parse_tx_to_json(tx: Vec<u8>, context: ParseContext) -> R<String> {
    let cardano_tx = parse_tx(tx, context)?;
    Ok(cardano_tx.to_json().to_string())
}

pub fn compose_witness_set(signatures: Vec<CardanoSignarure>) -> R<String> {
    let mut witness_set = cardano_serialization_lib::TransactionWitnessSet::new();
    let mut vkeys = cardano_serialization_lib::crypto::Vkeywitnesses::new();
    for signature in signatures {
        let v = Vkeywitness::new(
            &Vkey::new(
                &PublicKey::from_bytes(&signature.get_public_key())
                    .map_err(|e| CardanoError::SigningFailed(e.to_string()))?,
            ),


            &Ed25519Signature::from_bytes(signature.get_signature())
                .map_err(|e| CardanoError::SigningFailed(e.to_string()))?,
        );
        vkeys.add(&v);
    }

    witness_set.set_vkeys(&vkeys);
    Ok(hex::encode(witness_set.to_bytes()))
}