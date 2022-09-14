use signer;
use transaction_parsing;
use transaction_parsing::TransactionAction;
use serde_json;
use serde_json::json;
use crate::wrapped_transaction_action::WrappedTransactionAction;

pub mod scanner;
mod wrapped_transaction_action;
mod wrapped_card;
mod wrapped_transaction_card;
mod wrapped_transaction_card_set;
pub mod transaction_parser;
mod traits;

pub fn init_polkadot_db(db_name: String) -> String {
    match signer::history_init_history_with_cert(db_name.as_str()) {
        Ok(_) => json!({"status": "success"}),
        Err(e) => json!({"status": "failed", "reason": e})
    }.to_string()
}
