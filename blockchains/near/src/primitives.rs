use near_primitives::transaction;
use near_primitives::borsh::{BorshDeserialize, BorshSerialize};
use hex::{FromHex, ToHex};
use serde_json::Value;
use crate::error::{Result, NearError};
use crate::parser::{TxParser, Tx, NearTx};


pub struct PrimitivesTxParser;

impl PrimitivesTxParser {
    pub fn new() -> Self {
        PrimitivesTxParser
    }
}

impl TxParser for PrimitivesTxParser {
    fn deserialize(&self, data: &Vec<u8>) -> Result<NearTx> {
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


#[test]
fn test() {
    let data = "40000000353862633234353938303464326564383736343166626465343062306439363334316362663033313362376466346263346636306661326634326336303263330058bc2459804d2ed87641fbde40b0d96341cbf0313b7df4bc4f60fa2f42c602c389772d10bc5400001000000064656d6f303631372e746573746e65746ce5b0c72ea21d29c9cf8cde859d2ddd466a70e1f8f1069742876e259fb157440100000003000000ed95c28f055a2a000000000000";
    let buf_message = Vec::from_hex(data).unwrap();
    let tx = transaction::Transaction::try_from_slice(&buf_message).unwrap();
    let serialize_data = tx.try_to_vec().unwrap();
    let buf: String = Vec::encode_hex(&serialize_data);
    assert_eq!(data, buf);
}