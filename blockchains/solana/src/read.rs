use crate::error::Result;

pub trait Read<T> {
    fn read(raw: &mut Vec<u8>) -> Result<T>;
}
