use crate::errors::{R};
use crate::structs::{ParseContext, ParsedCardanoTx};
use cardano_serialization_lib;



pub fn parse_tx(tx: Vec<u8>, context: ParseContext) -> R<ParsedCardanoTx> {
    let cardano_tx = cardano_serialization_lib::Transaction::from_bytes(tx)?;
    ParsedCardanoTx::from_cardano_tx(cardano_tx, context)
}
