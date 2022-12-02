use serde::{Serialize, Serializer};
use serde::ser::Error;
use serde_json::Value;
use crate::Result as CosmosResult;

pub trait SerializeJson {
    fn to_json(&self) -> CosmosResult<Value>;
}

pub trait Msg: SerializeJson {}

impl Serialize for dyn Msg {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
        where
            S: Serializer,
    {
        let json_value = self.to_json().map_err(|err| Error::custom(err.to_string()))?;
        json_value.serialize(serializer)
    }
}


