use serde_json::{json, Value};
use definitions::navigation::TransactionCardSet;
use crate::traits::ToJSON;
use crate::wrapped_transaction_card::WrappedTransactionCard;

pub struct WrappedTransactionCardSet {
    pub tcs: TransactionCardSet,
}

impl ToJSON for WrappedTransactionCardSet {
    fn to_json(&self) -> Value {
        let author = self.tcs.author.as_ref().map(|v| v.iter().map(|v| WrappedTransactionCard {
            tc: v.clone()
        }.to_json()).collect::<Vec<Value>>());
        let error = self.tcs.error.as_ref().map(|v| v.iter().map(|v| WrappedTransactionCard {
            tc: v.clone()
        }.to_json()).collect::<Vec<Value>>());
        let extensions = self.tcs.extensions.as_ref().map(|v| v.iter().map(|v| WrappedTransactionCard {
            tc: v.clone()
        }.to_json()).collect::<Vec<Value>>());
        let importing_derivations = self.tcs.importing_derivations.as_ref().map(|v| v.iter().map(|v| WrappedTransactionCard {
            tc: v.clone()
        }.to_json()).collect::<Vec<Value>>());
        let message = self.tcs.message.as_ref().map(|v| v.iter().map(|v| WrappedTransactionCard {
            tc: v.clone()
        }.to_json()).collect::<Vec<Value>>());
        let meta = self.tcs.meta.as_ref().map(|v| v.iter().map(|v| WrappedTransactionCard {
            tc: v.clone()
        }.to_json()).collect::<Vec<Value>>());
        let method = self.tcs.method.as_ref().map(|v| v.iter().map(|v| WrappedTransactionCard {
            tc: v.clone()
        }.to_json()).collect::<Vec<Value>>());
        let new_specs = self.tcs.new_specs.as_ref().map(|v| v.iter().map(|v| WrappedTransactionCard {
            tc: v.clone()
        }.to_json()).collect::<Vec<Value>>());
        let verifier = self.tcs.verifier.as_ref().map(|v| v.iter().map(|v| WrappedTransactionCard {
            tc: v.clone()
        }.to_json()).collect::<Vec<Value>>());
        let warning = self.tcs.warning.as_ref().map(|v| v.iter().map(|v| WrappedTransactionCard {
            tc: v.clone()
        }.to_json()).collect::<Vec<Value>>());
        let types_info = self.tcs.types_info.as_ref().map(|v| v.iter().map(|v| WrappedTransactionCard {
            tc: v.clone()
        }.to_json()).collect::<Vec<Value>>());
        json!({
            "author": author,
            "error": error,
            "extensions": extensions,
            "importing_derivations": importing_derivations,
            "message": message,
            "meta": meta,
            "method": method,
            "new_specs": new_specs,
            "verifier": verifier,
            "warning": warning,
            "types_info": types_info,
        })
    }
}
