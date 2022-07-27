use crate::message::Message;
use crate::read::Read;
use rust_crypto_core_chain::Chain;

mod error;
mod compact;
mod instruction;
pub mod message;
pub(crate) mod read;
mod resolvers;


pub struct Sol {}

impl Sol {
    fn parse_message(message: &mut Vec<u8>) -> Result<message::Message, String> {
        Message::read(message).map_err(|e| e.to_string())
    }
    pub fn parse_message_to_json(message: &mut Vec<u8>) -> Result<String, String> {
        Sol::parse_message(message).and_then(|v| v.to_json_str().map_err(|e| e.to_string()))
    }

    pub fn validate_message(message: &mut Vec<u8>) -> bool {
        Message::validate(message)
    }
}

impl Chain for Sol {
    fn parse(data: &Vec<u8>) -> Result<String, String> {
        Sol::parse_message(data.clone().to_vec().as_mut())
            .and_then(|v| v.to_json_str().map_err(|e| e.to_string()))
    }
}
