use crate::error::Result;
use crate::primitives::PrimitivesTxParser;

pub type NearTx = Box<dyn Tx>;
pub type Parser = Box<dyn TxParser>;

pub trait Tx {
    fn get_raw_json(&self) -> Result<String>;
    fn get_formatted_json(&self) -> Result<String>;
}

pub trait TxParser {
    fn deserialize(&self, data: &Vec<u8>) -> Result<NearTx>;
}

pub struct ParserFactory;

impl ParserFactory {
    pub fn create_parser() -> Parser {
        Box::new(PrimitivesTxParser::new())
    }
}


