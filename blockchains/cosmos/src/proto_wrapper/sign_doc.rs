use cosmos_sdk_proto as proto;
use cosmos_sdk_proto::prost::bytes::Bytes;
use cosmos_sdk_proto::traits::Message;
use serde::Serialize;
use crate::{CosmosError, Result};
use crate::proto_wrapper::auth_info::AuthInfo;
use crate::proto_wrapper::body::Body;

#[derive(Serialize)]
pub struct SignDoc {
    pub body: Body,
    pub auth_info: AuthInfo,
    pub chain_id: String,
    pub account_number: u64,
}


impl SignDoc {
    fn from(proto: proto::cosmos::tx::v1beta1::SignDoc) -> Result<SignDoc> {
        let tx_body: proto::cosmos::tx::v1beta1::TxBody = Message::decode(Bytes::from(proto.body_bytes)).map_err(|e| CosmosError::ParseFailed(format!("proto TxBody deserialize failed {}", e.to_string())))?;
        let body = Body::try_from(tx_body)?;

        let auth_info : proto::cosmos::tx::v1beta1::AuthInfo = Message::decode(Bytes::from(proto.auth_info_bytes)).map_err(|e| CosmosError::ParseFailed(format!("proto AuthInfo deserialize failed {}", e.to_string())))?;
        let auth_info = AuthInfo::try_from(auth_info)?;

        Ok(SignDoc {
            body,
            auth_info,
            chain_id: proto.chain_id,
            account_number: proto.account_number,
        })
    }

    pub fn parse(data: &Vec<u8>) -> Result<SignDoc> {
        let proto_sign_doc: proto::cosmos::tx::v1beta1::SignDoc = Message::decode(Bytes::from(data.clone())).map_err(|e| CosmosError::ParseFailed(format!("proto SignDoc deserialize failed {}", e.to_string())))?;
        SignDoc::from(proto_sign_doc)
    }
}
