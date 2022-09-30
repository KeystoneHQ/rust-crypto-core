use transaction_parsing;
use transaction_parsing::TransactionAction;
use serde_json;
use serde_json::json;
use db_handling::db_transactions::SignContent;
use crate::wrapped_transaction_action::WrappedTransactionAction;
use transaction_signing;
use transaction_signing::sign_content;
use parity_scale_codec::Encode;
use hex;

pub mod scanner;
mod wrapped_transaction_action;
mod wrapped_card;
mod wrapped_transaction_card;
mod wrapped_transaction_card_set;
pub mod transaction_parser;
mod traits;

pub fn init_polkadot_db(db_name: String) -> String {
    match db_handling::cold_default::signer_init_with_cert(db_name.as_str()).map_err(|e| e.to_string()) {
        Ok(_) => json!({"status": "success"}),
        Err(e) => json!({"status": "failed", "reason": e})
    }.to_string()
}

pub fn handle_stub(db_name: String, checksum: u32) -> String {
    match transaction_signing::handle_stub(checksum, db_name.as_str()).map_err(|e| e.to_string()) {
        Ok(..) => json!({"status": "success"}),
        Err(e) => json!({"status": "failed", "reason": e})
    }.to_string()
}

pub fn import_address(db_name: String, public_key: String, path: String) -> String {
    match db_handling::identities::try_import_address(public_key.as_str(), path.as_str(), db_name).map_err(|e| e.to_string()) {
        Ok(..) => json!({"status": "success"}),
        Err(e) => json!({"status": "failed", "reason": e})
    }.to_string()
}

pub fn get_sign_content(db_name: String, checksum: u32) -> String {
    match db_handling::db_transactions::TrDbColdSign::from_storage(db_name, checksum).map_err(|v| v.to_string()) {
        Ok(v) => {
            let value = match v.content() {
                SignContent::Transaction { method, extensions } => {
                    [method.to_vec(), extensions.to_vec()].concat()
                }
                SignContent::Message(a) => a.encode(),
            };
            let sign_content = hex::encode(value);
            json!({"status": "success", "value": sign_content})
        }
        Err(e) => {
            json!({"status": "failed", "reason": e})
        }
    }.to_string()
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use crate::{init_polkadot_db, scanner, handle_stub, import_address, get_sign_content};
    use crate::transaction_parser::parse_transaction;
    use db_handling;
    use generate_message;
    use generate_message::parser::{Command, Show};
    use transaction_signing;
    use fs_extra;
    use fs_extra::dir::CopyOptions;
    use std::fs;
    use serde_json::Value;
    use hex;

    fn get_db_path() -> String {
        "./test_data/database".to_string()
    }

    fn initial_data_base() {
        let db_origin_path = "./test_data/database_origin";
        let db_path = get_db_path();
        let option = CopyOptions {
            overwrite: true,
            skip_exist: false,
            buffer_size: 64000,
            copy_inside: true,
            content_only: false,
            depth: 0,
        };
        fs_extra::dir::copy(db_origin_path, db_path, &option);
    }

    fn remove() {
        let db_path = get_db_path();
        let items = vec![db_path];
        fs_extra::remove_items(&items);
    }

    fn init() {
        let db_path = get_db_path();
        initial_data_base();
        init_polkadot_db(db_path.clone());
    }

    fn add_meta() {
        let db_path = get_db_path();
        let payload = fs::read_to_string("./test_data/metadata_polkadot_v9270").unwrap();
        let result = parse_transaction(payload, db_path.clone());
        let json: Value = serde_json::from_str(result.as_str()).unwrap();
        let i = &json["checksum"];
        if let Value::Number(i) = i {
            handle_stub(db_path.to_string(), i.as_u64().unwrap() as u32);
        }
    }

    fn add_address() {
        let db_path = get_db_path();
        let public_key = "28b9ffce010cff941262f1b5fa5a884a65b2f7324854082abd68aa3d93b0827f";
        let path = "//polkadot";
        import_address(db_path.clone(), public_key.to_string(), path.to_string());
    }

    #[test]
    fn parse_read_metadata() {
        init();
        let db_path = get_db_path();
        let payload = fs::read_to_string("./test_data/metadata_polkadot_v9270").unwrap();
        let result = parse_transaction(payload, db_path.clone());
        let json: Value = serde_json::from_str(result.as_str()).unwrap();
        assert_eq!(json["content"][0]["card"]["type"], "Meta");
        remove();
    }

    #[test]
    fn test_parse_transfer_without_address() {
        init();
        add_meta();
        let db_path = get_db_path();
        let tx = fs::read_to_string("./test_data/transactions/transfer").unwrap();
        let result = parse_transaction(tx, db_path);
        let json: Value = serde_json::from_str(result.as_str()).unwrap();
        assert_eq!("Read", json["transaction_type"]);
        remove();
    }

    #[test]
    fn test_parse_transfer_with_address() {
        init();
        add_meta();
        add_address();
        let db_path = get_db_path();
        let tx = fs::read_to_string("./test_data/transactions/transfer").unwrap();
        let result = parse_transaction(tx, db_path);
        let json: Value = serde_json::from_str(result.as_str()).unwrap();
        assert_eq!("Sign", json["transaction_type"]);
        println!("{}", json);
        remove();
    }

    #[test]
    fn test_get_sign_content() {
        init();
        add_meta();
        add_address();
        let db_path = get_db_path();
        let tx = fs::read_to_string("./test_data/transactions/transfer").unwrap();
        let result = parse_transaction(tx, db_path.clone());
        let json: Value = serde_json::from_str(result.as_str()).unwrap();
        let checksum = json["checksum"].as_u64().unwrap();
        let sign_content = get_sign_content(db_path.clone(), checksum.clone() as u32);
        let json2: Value = serde_json::from_str(sign_content.as_str()).unwrap();
        let result2 = json2["value"].as_str().unwrap();
        assert_eq!("05030028b9ffce010cff941262f1b5fa5a884a65b2f7324854082abd68aa3d93b0827f0700e40b54025501c90100362400000d00000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3e5dc2cf7ac2ab8940ce2607ce9df3ec7bc59f513ea23dba5b956165518c1d4fc",
                   result2);
        remove();
    }
}