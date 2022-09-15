use serde_json::{json, Value};
use definitions::navigation::{Address, MSCNetworkInfo, MTransaction, TransactionType};
use transaction_parsing::TransactionAction;
use crate::traits::ToJSON;
use crate::wrapped_transaction_card_set::WrappedTransactionCardSet;

pub struct WrappedTransactionAction {
    pub(crate) t: TransactionAction,
}

impl ToJSON for MTransaction {
    fn to_json(&self) -> Value{
        let transaction_type = match self.ttype {
            TransactionType::Stub => "Stub",
            TransactionType::Read => "Read",
            TransactionType::Sign => "Sign",
            TransactionType::ImportDerivations => "ImportDerivations",
            TransactionType::Done => "Done",
        };
        let wrapped_content = WrappedTransactionCardSet {
            tcs: self.content.clone(),
        };
        json!({
            "content": wrapped_content.to_json(),
            "transaction_type": transaction_type,
            "author_info": self.author_info.as_ref().map(|v| v.to_json()),
            "network_info": self.network_info.as_ref().map(|v| v.to_json()),
        })
    }
}

impl ToJSON for Address {
    fn to_json(&self) -> Value {
        json!({
            "base58": self.base58,
            "path": self.path,
        })
    }
}

impl ToJSON for MSCNetworkInfo {
    fn to_json(&self) -> Value {
        json!({
            "network_title": self.network_title,
        })
    }
}

impl WrappedTransactionAction {
    pub fn to_json(&self) -> Value {
        let (content, ttype, author_info, network_info) = match &self.t {
            TransactionAction::Derivations {
                content,
                network_info,
                ..
            } => (
                content,
                TransactionType::ImportDerivations,
                None,
                Some(network_info),
            ),
            TransactionAction::Sign {
                content,
                author_info,
                network_info,
                ..
            } => (
                content,
                TransactionType::Sign,
                Some(author_info),
                Some(network_info),
            ),
            TransactionAction::Stub { s, .. } => (s, TransactionType::Stub, None, None),
            TransactionAction::Read { r } => (r, TransactionType::Read, None, None),
        };
        let result = MTransaction {
            content: content.clone(),
            ttype,
            author_info: author_info.cloned(),
            network_info: network_info.map(|i| MSCNetworkInfo {
                network_title: i.clone().title,
                network_logo: i.clone().logo,
            }),
        };
        result.to_json()
    }
}