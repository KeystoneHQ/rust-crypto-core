use serde_json::{json, Value};
use definitions::navigation::TransactionCard;

use crate::traits::ToJSON;
use crate::wrapped_card::WrappedCard;

pub struct WrappedTransactionCard {
    tc: TransactionCard,
}

impl ToJSON for WrappedTransactionCard {
    fn to_json(&self) -> Value {
        let wrapped_card = WrappedCard {
            c: self.tc.card.clone(),
        };
        let card_json = wrapped_card.to_json();
        json!({
            "index": self.tc.index,
            "indent": self.tc.indent,
            "card": card_json,
        })
    }
}