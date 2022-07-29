use std::error::Error;

pub trait Chain<E: Error> {
    fn parse(data: &Vec<u8>) -> Result<String, E>;
}
