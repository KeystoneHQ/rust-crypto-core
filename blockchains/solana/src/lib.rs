use crate::error::SolanaError;
use crate::message::Message;
use crate::read::Read;

use rcc_trait_chain::Chain;

mod compact;
mod error;
mod instruction;
pub mod message;
pub(crate) mod read;
mod resolvers;
mod solana_lib;

pub struct Sol {}

impl Sol {
    fn parse_message(message: &mut Vec<u8>) -> Result<message::Message, SolanaError> {
        Message::read(message)
    }
    pub fn parse_message_to_json(message: &mut Vec<u8>) -> Result<String, SolanaError> {
        Sol::parse_message(message).and_then(|v| v.to_json_str())
    }

    pub fn validate_message(message: &mut Vec<u8>) -> bool {
        Message::validate(message)
    }
}

impl Chain<SolanaError> for Sol {
    fn parse(data: &Vec<u8>) -> Result<String, SolanaError> {
        Sol::parse_message(data.clone().to_vec().as_mut()).and_then(|v| v.to_json_str())
    }
}
