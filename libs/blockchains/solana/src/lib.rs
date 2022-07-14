use crate::types::message::Message;
use crate::types::read::Read;

mod types;

pub struct Sol {}

impl Sol {
    fn parse_message(message: &mut Vec<u8>) -> Result<types::message::Message, String> {
        Message::read(message)
    }
    pub fn parse_message_to_json(message: &mut Vec<u8>) -> Result<String, String> {
        Sol::parse_message(message).map(|v| v.to_json_str())
    }

    pub fn validate_message(message: &mut Vec<u8>) -> bool {
        Message::validate(message)
    }
}
