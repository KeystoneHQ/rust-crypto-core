use crate::errors::R;
use crate::structs::{ParseContext, ParsedCardanoTx};
use cardano_serialization_lib;
use serde_json::json;

pub fn parse_tx(tx: Vec<u8>, context: ParseContext) -> R<ParsedCardanoTx> {
    let cardano_tx = cardano_serialization_lib::Transaction::from_bytes(tx)?;
    ParsedCardanoTx::from_cardano_tx(cardano_tx, context)
}

pub fn parse_tx_to_json(tx: Vec<u8>, context: ParseContext) -> R<String> {
    let cardano_tx = parse_tx(tx, context)?;

    todo!()
}