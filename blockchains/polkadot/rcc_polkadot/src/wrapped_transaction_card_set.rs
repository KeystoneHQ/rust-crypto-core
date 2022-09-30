use serde_json::{json, Value};
use definitions::navigation::{TransactionCard, TransactionCardSet};
use crate::traits::ToJSON;
use crate::wrapped_transaction_card::WrappedTransactionCard;

pub struct WrappedTransactionCardSet {
    pub tcs: TransactionCardSet,
}

impl ToJSON for WrappedTransactionCardSet {
    fn to_json(&self) -> Value {
        let concat = |v1: Vec<TransactionCard>, v2: &Vec<TransactionCard>| [v1, v2.to_vec()].concat();

        let mut cards: Vec<TransactionCard> = vec![];
        if let Some(v) = self.tcs.author.as_ref() {
            cards = concat(cards, v);
        }
        if let Some(v) = self.tcs.error.as_ref() {
            cards = concat(cards, v);
        }
        if let Some(v) = self.tcs.extensions.as_ref() {
            cards = concat(cards, v);
        }
        if let Some(v) = self.tcs.importing_derivations.as_ref() {
            cards = concat(cards, v);
        }
        if let Some(v) = self.tcs.message.as_ref() {
            cards = concat(cards, v);
        }
        if let Some(v) = self.tcs.meta.as_ref() {
            cards = concat(cards, v);
        }
        if let Some(v) = self.tcs.method.as_ref() {
            cards = concat(cards, v);
        }
        if let Some(v) = self.tcs.new_specs.as_ref() {
            cards = concat(cards, v);
        }
        if let Some(v) = self.tcs.verifier.as_ref() {
            cards = concat(cards, v);
        }
        if let Some(v) = self.tcs.warning.as_ref() {
            cards = concat(cards, v);
        }
        if let Some(v) = self.tcs.types_info.as_ref() {
            cards = concat(cards, v);
        }
        let result = cards.iter().map(|v| WrappedTransactionCard{tc: v.clone()}.to_json()).collect::<Vec<Value>>();
        json!(result)
    }
}
