use serde_json::{json, Value};
use definitions::navigation::TransactionCardSet;
use crate::traits::ToJSON;

pub struct WrappedTransactionCardSet {
    pub tcs: TransactionCardSet
}

impl ToJSON for WrappedTransactionCardSet {
    fn to_json(&self) -> Value{
        let author = self.tcs.author.map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
        let error = self.tcs.error.map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
        let extensions = self.tcs.extensions.map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
        let importing_derivations = self.tcs.importing_derivations.map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
        let message = self.tcs.message.map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
        let meta = self.tcs.meta.map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
        let method = self.tcs.method.map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
        let new_specs = self.tcs.new_specs.map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
        let verifier = self.tcs.verifier.map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
        let warning = self.tcs.warning.map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
        let types_info = self.tcs.types_info.map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
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
