#![no_std]
#![feature(error_in_core)]
extern crate alloc;

pub mod errors;

use sui_types::transaction::TransactionData;
use sui_types::message::PersonalMessage;
use alloc::vec::Vec;
use bcs;
use errors::{Result, SuiError};

pub type Bytes = Vec<u8>;

pub fn parse_tx(tx: Bytes) -> Result<TransactionData> {
  let tx:TransactionData = bcs::from_bytes(&tx).map_err(|err| SuiError::from(err))?;
  Ok(tx)
}

pub fn parse_msg(msg: Bytes) -> Result<PersonalMessage> {
  let msg: PersonalMessage = bcs::from_bytes(&msg).map_err(|err| SuiError::from(err))?;
  Ok(msg)
}


#[cfg(test)]
mod tests {
  extern crate std;

  use alloc::string::ToString;
  use serde_json::json;
  use super::*;

  #[test]
  fn test_parse_tx() {
    // TransferObjects
    let tx_bytes = hex::decode("000002002086ac6179ca6ad9a7b1ccb47202d06ae09a131e66309944922af9c73d3c203b660100d833a8eabc697a0b2e23740aca7be9b0b9e1560a39d2f390cf2534e94429f91ced0c00000000000020190ca0d64215ac63f50dbffa47563404182304e0c10ea30b5e4d671b7173a34c0101010101000100000e4d9313fb5b3f166bb6f2aea587edbe21fb1c094472ccd002f34b9d0633c71901280f4809b93ed87cc06f3397cd42a800a1034316e80d05443bce08e810817a96f50c0000000000002051c8eb5d437fb66c8d296e1cdf446c91be29fbc89f8430a2407acb0179a503880e4d9313fb5b3f166bb6f2aea587edbe21fb1c094472ccd002f34b9d0633c719e803000000000000d00700000000000000").unwrap();
    let tx = parse_tx(tx_bytes);
    assert_eq!(json!(tx.unwrap()).to_string(), "{\"V1\":{\"expiration\":\"None\",\"gas_data\":{\"budget\":2000,\"owner\":\"0x0e4d9313fb5b3f166bb6f2aea587edbe21fb1c094472ccd002f34b9d0633c719\",\"payment\":[[\"0x280f4809b93ed87cc06f3397cd42a800a1034316e80d05443bce08e810817a96\",3317,\"6WFidAcGkUzUEPvSChbMXg9AZUHj3gzJL4U7HkxJA43H\"]],\"price\":1000},\"kind\":{\"ProgrammableTransaction\":{\"commands\":[{\"TransferObjects\":[[{\"Input\":1}],{\"Input\":0}]}],\"inputs\":[{\"Pure\":[134,172,97,121,202,106,217,167,177,204,180,114,2,208,106,224,154,19,30,102,48,153,68,146,42,249,199,61,60,32,59,102]},{\"Object\":{\"ImmOrOwnedObject\":[\"0xd833a8eabc697a0b2e23740aca7be9b0b9e1560a39d2f390cf2534e94429f91c\",3309,\"2gnMwEZqfMY1Q2Ree5iW3cAt7rhauevfBDY74SH3Ef1D\"]}}]}},\"sender\":\"0x0e4d9313fb5b3f166bb6f2aea587edbe21fb1c094472ccd002f34b9d0633c719\"}}");

    // MoveCall
    let tx_bytes = hex::decode("0000020100d833a8eabc697a0b2e23740aca7be9b0b9e1560a39d2f390cf2534e94429f91ced0c00000000000020190ca0d64215ac63f50dbffa47563404182304e0c10ea30b5e4d671b7173a34c00090140420f000000000001000000000000000000000000000000000000000000000000000000000000000002037061790973706c69745f76656301070000000000000000000000000000000000000000000000000000000000000002037375690353554900020100000101000e4d9313fb5b3f166bb6f2aea587edbe21fb1c094472ccd002f34b9d0633c71901280f4809b93ed87cc06f3397cd42a800a1034316e80d05443bce08e810817a96f50c0000000000002051c8eb5d437fb66c8d296e1cdf446c91be29fbc89f8430a2407acb0179a503880e4d9313fb5b3f166bb6f2aea587edbe21fb1c094472ccd002f34b9d0633c719e803000000000000e80300000000000000").unwrap();
    let tx = parse_tx(tx_bytes);
    assert_eq!(json!(tx.unwrap()).to_string(), "{\"V1\":{\"expiration\":\"None\",\"gas_data\":{\"budget\":1000,\"owner\":\"0x0e4d9313fb5b3f166bb6f2aea587edbe21fb1c094472ccd002f34b9d0633c719\",\"payment\":[[\"0x280f4809b93ed87cc06f3397cd42a800a1034316e80d05443bce08e810817a96\",3317,\"6WFidAcGkUzUEPvSChbMXg9AZUHj3gzJL4U7HkxJA43H\"]],\"price\":1000},\"kind\":{\"ProgrammableTransaction\":{\"commands\":[{\"MoveCall\":{\"arguments\":[{\"Input\":0},{\"Input\":1}],\"function\":\"split_vec\",\"module\":\"pay\",\"package\":\"0x0000000000000000000000000000000000000000000000000000000000000002\",\"type_arguments\":[{\"struct\":{\"address\":\"0000000000000000000000000000000000000000000000000000000000000002\",\"module\":\"sui\",\"name\":\"SUI\",\"type_args\":[]}}]}}],\"inputs\":[{\"Object\":{\"ImmOrOwnedObject\":[\"0xd833a8eabc697a0b2e23740aca7be9b0b9e1560a39d2f390cf2534e94429f91c\",3309,\"2gnMwEZqfMY1Q2Ree5iW3cAt7rhauevfBDY74SH3Ef1D\"]}},{\"Pure\":[1,64,66,15,0,0,0,0,0]}]}},\"sender\":\"0x0e4d9313fb5b3f166bb6f2aea587edbe21fb1c094472ccd002f34b9d0633c719\"}}");

    // SplitCoins
    let tx_bytes = hex::decode("00000200201ff915a5e9e32fdbe0135535b6c69a00a9809aaf7f7c0275d3239ca79db20d6400081027000000000000020200010101000101020000010000ebe623e33b7307f1350f8934beb3fb16baef0fc1b3f1b92868eec3944093886901a2e3e42930675d9571a467eb5d4b22553c93ccb84e9097972e02c490b4e7a22ab73200000000000020176c4727433105da34209f04ac3f22e192a2573d7948cb2fabde7d13a7f4f149ebe623e33b7307f1350f8934beb3fb16baef0fc1b3f1b92868eec39440938869e803000000000000640000000000000000").unwrap();
    let tx = parse_tx(tx_bytes);
    assert_eq!(json!(tx.unwrap()).to_string(), "{\"V1\":{\"expiration\":\"None\",\"gas_data\":{\"budget\":100,\"owner\":\"0xebe623e33b7307f1350f8934beb3fb16baef0fc1b3f1b92868eec39440938869\",\"payment\":[[\"0xa2e3e42930675d9571a467eb5d4b22553c93ccb84e9097972e02c490b4e7a22a\",12983,\"2aS93HVFS54TNKfAFunntFgoRMbMCzp1bDfqSTRPRYpg\"]],\"price\":1000},\"kind\":{\"ProgrammableTransaction\":{\"commands\":[{\"SplitCoins\":[\"GasCoin\",[{\"Input\":1}]]},{\"TransferObjects\":[[{\"Result\":0}],{\"Input\":0}]}],\"inputs\":[{\"Pure\":[31,249,21,165,233,227,47,219,224,19,85,53,182,198,154,0,169,128,154,175,127,124,2,117,211,35,156,167,157,178,13,100]},{\"Pure\":[16,39,0,0,0,0,0,0]}]}},\"sender\":\"0xebe623e33b7307f1350f8934beb3fb16baef0fc1b3f1b92868eec39440938869\"}}");
  }

  #[test]
  fn test_parse_msg() {
    let msg = parse_msg(hex::decode("0a48656c6c6f2c20537569").unwrap());
    assert_eq!(json!(msg.unwrap()).to_string(), "{\"message\":[72,101,108,108,111,44,32,83,117,105]}");
  }

}
