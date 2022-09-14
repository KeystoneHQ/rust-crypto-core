use serde_json::Value;

pub trait ToJSON {
    fn to_json(&self) -> Value;
}