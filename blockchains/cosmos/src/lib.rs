use rcc_trait_chain::Chain;
use crate::error::{CosmosError, Result};
use crate::proto_wrapper::sign_doc::SignDoc;

mod proto_wrapper;
mod error;

pub struct Cosmos;

impl Chain<CosmosError> for Cosmos {
    fn parse(data: &Vec<u8>) -> Result<String> {
        SignDoc::parse(data)
            .map(|doc| serde_json::to_string(&doc)
                .map_err(|err| CosmosError::SerializeFailed(err.to_string())))?
    }
}


#[cfg(test)]
mod tests {
    use hex::FromHex;
    use rcc_trait_chain::Chain;
    use crate::Cosmos;

    #[test]
    fn test() {
        let hex_data = "0a8f010a8c010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e64126c0a2d636f736d6f7331786573766b723664306a39366a357a64637735666d717861766a767576717832796779376d70122d636f736d6f7331786573766b723664306a39366a357a64637735666d717861766a767576717832796779376d701a0c0a057374616b65120331303012580a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21035bc6eee695a089c273b690d7123c84cf6dbcb91e613c8b60b79422a1ee68490612040a0208011803120410c09a0c1a04746573742001";
        let buf_message = Vec::from_hex(hex_data).unwrap();
        let json = r#"{"body":{"msgs":[{"type":"/cosmos.bank.v1beta1.MsgSend","value":{"amount":[{"amount":"100","denom":"stake"}],"from_address":"cosmos1xesvkr6d0j96j5zdcw5fmqxavjvuvqx2ygy7mp","to_address":"cosmos1xesvkr6d0j96j5zdcw5fmqxavjvuvqx2ygy7mp"}}],"memo":"","timeout_height":0},"auth_info":{"signer_infos":[{"public_key":{"Single":{"type_url":"/cosmos.crypto.secp256k1.PubKey","key":"A1vG7uaVoInCc7aQ1xI8hM9tvLkeYTyLYLeUIqHuaEkG"}},"mode_info":{"Single":{"mode":"SIGN_MODE_DIRECT"}},"sequence":3}],"fee":{"amount":[],"gas":200000,"payer":"","granter":""}},"chain_id":"test","account_number":1}"#;
        let parse_result = Cosmos::parse(&buf_message).expect("TODO: panic message");
        assert_eq!(json, parse_result);

    }
}