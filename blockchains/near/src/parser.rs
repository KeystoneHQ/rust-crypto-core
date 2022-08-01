use crate::error::Result;
use crate::primitives::PrimitivesTxParser;

pub type NearTx = Box<dyn Tx>;

pub trait Tx {
    fn get_result(&self) -> Result<String>;
}


pub struct Parser;

impl Parser {
    pub fn parse(data: &Vec<u8>) -> Result<NearTx> {
        PrimitivesTxParser::deserialize(data)
    }
}


