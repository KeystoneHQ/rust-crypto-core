use near_primitives::transaction;
use near_primitives::borsh::BorshDeserialize;
use serde_json::Value;
use crate::error::{Result, NearError};
use crate::parser::{NearTx, Tx};
use hex::ToHex;

pub struct PrimitivesTxParser;


impl PrimitivesTxParser {
    pub fn deserialize(data: &Vec<u8>) -> Result<NearTx> {
        match transaction::Transaction::try_from_slice(data) {
            Ok(tx) => {
                Ok(Box::new(PrimitivesTx::new(tx)))
            }
            Err(err) => Err(NearError::ParseFailed(format!("borsh deserialize failed {}", err.to_string())))
        }
    }
}

pub struct PrimitivesTx {
    tx: transaction::Transaction,
}


impl Tx for PrimitivesTx {
    fn get_raw_json(&self) -> Result<String> {
        self.to_json_str()
    }

    fn get_formatted_json(&self) -> Result<String> {
        self.to_json_str()
    }
}

impl PrimitivesTx {
    pub fn new(tx: transaction::Transaction) -> Self {
        PrimitivesTx { tx }
    }

    fn to_json_str(&self) -> Result<String> {
        let json_str: String;
        match serde_json::to_string(&self.tx) {
            Ok(data) => json_str = data,
            Err(e) =>
                return Err(NearError::SerializeFailed(format!("to json failed {}", e.to_string())))
        }

        let mut json_value: Value;
        match serde_json::from_str::<Value>(&json_str) {
            Ok(value) => json_value = value,
            Err(e) => return Err(NearError::SerializeFailed(format!("to json failed {}", e.to_string())))
        }

        if let Some(map) = json_value.as_object_mut() {
            map.insert("hash".to_string(), Value::String(self.get_hash()));
            Ok(json_value.to_string())
        } else {
            Err(NearError::SerializeFailed(format!("to json failed reason: as_object_mut failed")))
        }
    }

    fn get_hash(&self) -> String {
        let (hash, _) = self.tx.get_hash_and_size();
        Vec::encode_hex(&hash.0.to_vec())
    }
}
