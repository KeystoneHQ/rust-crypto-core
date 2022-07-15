use crate::types::message::Message;
use crate::types::read::Read;
use rust_crypto_core_chain::Chain;

mod types;
mod error;

pub struct Sol {}

impl Sol {
    fn parse_message(message: &mut Vec<u8>) -> Result<types::message::Message, String> {
        Message::read(message).map_err(|e| e.to_string())
    }
    pub fn parse_message_to_json(message: &mut Vec<u8>) -> Result<String, String> {
        Sol::parse_message(message).map(|v| v.to_json_str())
    }

    pub fn validate_message(message: &mut Vec<u8>) -> bool {
        Message::validate(message)
    }
}

impl Chain for Sol {
    fn parse(data: &Vec<u8>) -> Result<String, String> {
        Sol::parse_message(data.clone().to_vec().as_mut()).map(|v| v.to_json_str())
    }
}