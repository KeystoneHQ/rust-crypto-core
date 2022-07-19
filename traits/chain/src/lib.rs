pub trait Chain {
    fn parse(data: &Vec<u8>) -> Result<String, String>;
}
