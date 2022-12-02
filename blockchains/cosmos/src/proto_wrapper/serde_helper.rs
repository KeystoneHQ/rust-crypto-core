use base64;

pub fn from_base64(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    base64::decode(s).map_err(|err| err.into())
}

pub fn to_base64<T: AsRef<[u8]>>(input: T) -> String {
    base64::encode(&input)
}

pub mod base64_format {
    use serde::de;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{from_base64, to_base64};

    pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            T: AsRef<[u8]>,
    {
        serializer.serialize_str(&to_base64(data))
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where
            D: Deserializer<'de>,
            T: From<Vec<u8>>,
    {
        let s = String::deserialize(deserializer)?;
        from_base64(&s).map_err(|err| de::Error::custom(err.to_string())).map(Into::into)
    }
}