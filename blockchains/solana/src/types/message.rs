use hex::{encode, ToHex};

use crate::error::{Result, SolanaError};
use crate::types::compact::Compact;
use crate::types::instruction::Instruction;
use crate::types::read::Read;
use bs58;
use serde_json::{json, Value};

struct Signature {
    value: Vec<u8>,
}

impl Read<Signature> for Signature {
    fn read(raw: &mut Vec<u8>) -> Result<Signature> {
        if raw.len() < 64 {
            return Err(SolanaError::InvalidData(format!("signature")));
        }
        Ok(Signature {
            value: raw.splice(0..64, []).collect(),
        })
    }
}

struct Account {
    value: Vec<u8>,
}

impl Read<Account> for Account {
    fn read(raw: &mut Vec<u8>) -> Result<Account> {
        if raw.len() < 32 {
            return Err(SolanaError::InvalidData(format!("account")));
        }
        Ok(Account {
            value: raw.splice(0..32, []).collect(),
        })
    }
}

struct BlockHash {
    value: Vec<u8>,
}

impl Read<BlockHash> for BlockHash {
    fn read(raw: &mut Vec<u8>) -> Result<BlockHash> {
        if raw.len() < 32 {
            return Err(SolanaError::InvalidData(format!("blockhash")));
        }
        Ok(BlockHash {
            value: raw.splice(0..32, []).collect(),
        })
    }
}

pub struct Message {
    header: MessageHeader,
    accounts: Vec<Account>,
    block_hash: BlockHash,
    instructions: Vec<Instruction>,
}

impl Read<Message> for Message {
    fn read(raw: &mut Vec<u8>) -> Result<Message> {
        let header = MessageHeader::read(raw)?;
        let accounts = Compact::read(raw)?.data;
        let block_hash = BlockHash::read(raw)?;
        let instructions = Compact::read(raw)?.data;
        Ok(Message {
            header,
            accounts,
            block_hash,
            instructions,
        })
    }
}

enum SupportedPrograms {
    System,
    Vote,
    Stake,
    Config,
}

impl Message {
    pub fn to_json_str(&self) -> Result<String> {
        let instructions = self
            .instructions
            .iter()
            .map(|instruction| {
                let accounts = instruction
                    .account_indexes
                    .iter()
                    .map(|account_index| {
                        bs58::encode(&self.accounts[usize::from(*account_index)].value)
                            .into_string()
                    })
                    .collect::<Vec<String>>();
                let program_account =
                    bs58::encode(&self.accounts[usize::from(instruction.program_index)].value)
                        .into_string();
                let accounts_string = accounts.clone().join(",").to_string();
                match instruction.parse(&program_account, accounts) {
                    Ok(value) => Ok(json!({
                        "raw": {
                            "program_index": instruction.program_index,
                            "program_account": program_account,
                            "account_indexes": instruction.account_indexes,
                            "accounts": accounts_string,
                            "data": bs58::encode(&instruction.data).into_string(),
                        },
                        "readable": value,
                    })),
                    Err(e) => {
                        let readable =
                            format!("Unable to parse instruction, reason: {}", e.to_string());
                        Ok(json!({
                            "raw": {
                                "program_index": instruction.program_index,
                                "program_account": program_account,
                                "account_indexes": instruction.account_indexes,
                                "accounts": accounts_string,
                                "data": bs58::encode(&instruction.data).into_string(),
                            },
                            "readable": readable,
                        }))
                    }
                }
            })
            .collect::<Result<Vec<Value>>>()?;
        let json = json!({
            "header": {
                "num_required_signatures": self.header.num_required_signatures,
                "num_readonly_signed_accounts": self.header.num_readonly_signed_accounts,
                "num_readonly_unsigned_accounts": self.header.num_readonly_unsigned_accounts,
            },
            "accounts": self.accounts.iter().map(|account| {bs58::encode(&account.value).into_string()}).collect::<Vec<String>>(),
            "block_hash": bs58::encode(&self.block_hash.value).into_string(),
            "instructions": instructions,
        });
        Ok(json.to_string())
    }

    pub fn validate(raw: &mut Vec<u8>) -> bool {
        match Self::read(raw) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

struct MessageHeader {
    num_required_signatures: u8,
    num_readonly_signed_accounts: u8,
    num_readonly_unsigned_accounts: u8,
}

impl Read<MessageHeader> for MessageHeader {
    fn read(raw: &mut Vec<u8>) -> Result<MessageHeader> {
        if raw.len() < 3 {
            return Err(SolanaError::InvalidData(format!("message header")));
        }
        let n1 = raw.remove(0);
        let n2 = raw.remove(0);
        let n3 = raw.remove(0);
        Ok(MessageHeader {
            num_required_signatures: n1,
            num_readonly_signed_accounts: n2,
            num_readonly_unsigned_accounts: n3,
        })
    }
}

impl Read<u8> for u8 {
    fn read(raw: &mut Vec<u8>) -> Result<u8> {
        if raw.len() < 1 {
            return Err(SolanaError::InvalidData(format!("u8")));
        }
        Ok(raw.remove(0))
    }
}

#[cfg(test)]
mod tests {
    use crate::types::message::{Instruction, Message, MessageHeader};
    use crate::types::read::Read;
    use hex::{self, encode, FromHex};
    use serde_json::json;

    #[test]
    fn test_parse_message() {
        let mut raw = Vec::from_hex("01000103c8d842a2f17fd7aab608ce2ea535a6e958dffa20caf669b347b911c4171965530f957620b228bae2b94c82ddd4c093983a67365555b737ec7ddc1117e61c72e0000000000000000000000000000000000000000000000000000000000000000010295cc2f1f39f3604718496ea00676d6a72ec66ad09d926e3ece34f565f18d201020200010c0200000000e1f50500000000").unwrap();
        let message = Message::read(&mut raw).unwrap();

        let header = &message.header;
        assert_eq!(header.num_required_signatures, 1);
        assert_eq!(header.num_readonly_signed_accounts, 0);
        assert_eq!(header.num_readonly_unsigned_accounts, 1);

        let accounts = &message.accounts;
        assert_eq!(
            accounts[0].value,
            Vec::from_hex("c8d842a2f17fd7aab608ce2ea535a6e958dffa20caf669b347b911c417196553")
                .unwrap()
        );
        assert_eq!(
            accounts[1].value,
            Vec::from_hex("0f957620b228bae2b94c82ddd4c093983a67365555b737ec7ddc1117e61c72e0")
                .unwrap()
        );
        assert_eq!(
            accounts[2].value,
            Vec::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );

        let block_hash = &message.block_hash;
        assert_eq!(
            block_hash.value,
            Vec::from_hex("10295cc2f1f39f3604718496ea00676d6a72ec66ad09d926e3ece34f565f18d2")
                .unwrap()
        );

        let instructions = &message.instructions;
        assert_eq!(instructions[0].program_index, 2);
        assert_eq!(instructions[0].account_indexes, [0, 1]);
        assert_eq!(
            instructions[0].data,
            Vec::from_hex("0200000000e1f50500000000").unwrap()
        );
        assert_eq!(message.to_json_str().unwrap(), json!({
            "accounts": [
                "EX1oURpiPWWYUjVSK9KQR2qyqTBaR1EGfRNxkTsNk57Y",
                "23qJPvgvCBGJFhPmemqcksVCtrLDKyXJh5ZstjfCuu9q",
                "11111111111111111111111111111111"
            ],
            "block_hash": "26673efpV4o6Cv5ZnEfYp3M18nkqhg6tyXF2A2JzeoCd",
            "header": {
                "num_readonly_signed_accounts": 0,
                "num_readonly_unsigned_accounts": 1,
                "num_required_signatures": 1
            },
            "instructions": [
                {
                  "raw": {
                    "account_indexes": [0, 1],
                    "accounts": "EX1oURpiPWWYUjVSK9KQR2qyqTBaR1EGfRNxkTsNk57Y,23qJPvgvCBGJFhPmemqcksVCtrLDKyXJh5ZstjfCuu9q",
                    "data": "3Bxs411Dtc7pkFQj",
                    "program_account": "11111111111111111111111111111111",
                    "program_index": 2
                  },
                  "readable": {
                    "arguments": {
                      "amount": "100000000",
                      "from": "EX1oURpiPWWYUjVSK9KQR2qyqTBaR1EGfRNxkTsNk57Y",
                      "to": "23qJPvgvCBGJFhPmemqcksVCtrLDKyXJh5ZstjfCuu9q"
                    },
                    "method_name": "Transfer",
                    "program_name": "System"
                  }
                }
            ]
        }).to_string())
    }

    #[test]
    fn test_validate_message() {
        let message_invalid = "4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f726520657420646f6c6f7265206d61676e6120616c697175612e";
        let mut raw_invalid = Vec::from_hex(message_invalid).unwrap();
        let result_invalid = Message::validate(&mut raw_invalid);
        assert_eq!(result_invalid, false);

        let message_valid = "01000103c8d842a2f17fd7aab608ce2ea535a6e958dffa20caf669b347b911c4171965530f957620b228bae2b94c82ddd4c093983a67365555b737ec7ddc1117e61c72e0000000000000000000000000000000000000000000000000000000000000000010295cc2f1f39f3604718496ea00676d6a72ec66ad09d926e3ece34f565f18d201020200010c0200000000e1f50500000000";
        let mut raw_valid = Vec::from_hex(message_valid).unwrap();
        let result_valid = Message::validate(&mut raw_valid);
        assert_eq!(result_valid, true);
    }

    #[test]
    fn test_system_transfer() {
        let mut transaction = Vec::from_hex("01000103876c762c4c83532f82966935ba1810659a96237028a2af6688dadecb0155ae071c7d0930a08193e702b0f24ebba96f179e9c186ef1208f98652ee775001744490000000000000000000000000000000000000000000000000000000000000000a7516fe1d3af3457fdc54e60856c0c3c87f4e5be3d10ffbc7a5cce8bf96792a101020200010c020000008813000000000000").unwrap();
        let message = Message::read(&mut transaction).unwrap();
        let json = message.to_json_str().unwrap();
        assert_eq!(json, json!({
          "accounts": [
            "A7dxsCbMy5ktZwQUgsQhVxsoJpx6wPAZYEcccQVjWnkE",
            "2vCzt15qsXSCsf5k6t6QF9DiQSpE7kPTg3PdvFZtm2Tr",
            "11111111111111111111111111111111"
          ],
          "block_hash": "CG97KCGLGgPS1E754VjLgy724zNwGjE9sjrzqYa6CU2t",
          "header": {
            "num_readonly_signed_accounts": 0,
            "num_readonly_unsigned_accounts": 1,
            "num_required_signatures": 1
          },
          "instructions": [
            {
              "raw": {
                "account_indexes": [0, 1],
                "accounts": "A7dxsCbMy5ktZwQUgsQhVxsoJpx6wPAZYEcccQVjWnkE,2vCzt15qsXSCsf5k6t6QF9DiQSpE7kPTg3PdvFZtm2Tr",
                "data": "3Bxs4PckVVt51W8w",
                "program_account": "11111111111111111111111111111111",
                "program_index": 2
              },
              "readable": {
                "arguments": {
                  "amount": "5000",
                  "from": "A7dxsCbMy5ktZwQUgsQhVxsoJpx6wPAZYEcccQVjWnkE",
                  "to": "2vCzt15qsXSCsf5k6t6QF9DiQSpE7kPTg3PdvFZtm2Tr"
                },
                "method_name": "Transfer",
                "program_name": "System"
              }
            }
          ]
        }).to_string())
    }

    #[test]
    fn test_vote_vote() {
        let mut transaction = Vec::from_hex("01000305b446cb8fd7c225bf416df87c286710d75711af95222e41216da2177289cbbfa6b68edcd94d93de68614892bd165a94a6647aa040d87b9a042b41a009bdb469cf06a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b210000000006a7d517192f0aafc6f265e3fb77cc7ada82c529d0be3b136e2d0055200000000761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da35380000000009254bd5e695fabf43f0ead6da730e88cf39bec6991c2c4374bcade97d0a73be7010404010302003d02000000010000000000000060f2790800000000856a887d33af1cd1723388576a7be8fa6d9c9c80c548495a24bf680c908812cf01da7dd66200000000").unwrap();
        let message = Message::read(&mut transaction).unwrap();
        let json = message.to_json_str().unwrap();
        assert_eq!(json, json!({
          "accounts": [
            "D8izqaR979Fc2amDoGHmYqEugjckEi1RQL1Y1JKyHUwX",
            "DHdYsTEsd1wGrmthR1ognfRXPkWBmxAWAv2pKdAix3HY",
            "SysvarC1ock11111111111111111111111111111111",
            "SysvarS1otHashes111111111111111111111111111",
            "Vote111111111111111111111111111111111111111"
          ],
          "block_hash": "ArDU9jQqkrYg12SBihpjx7JSw2FjWtJ8K91uKTCyLEFG",
          "header": {
            "num_readonly_signed_accounts": 0,
            "num_readonly_unsigned_accounts": 3,
            "num_required_signatures": 1
          },
          "instructions": [
            {
              "raw": {
                "account_indexes": [1, 3, 2, 0],
                "accounts": "DHdYsTEsd1wGrmthR1ognfRXPkWBmxAWAv2pKdAix3HY,SysvarS1otHashes111111111111111111111111111,SysvarC1ock11111111111111111111111111111111,D8izqaR979Fc2amDoGHmYqEugjckEi1RQL1Y1JKyHUwX",
                "data": "2ZjTR1vUs2pHXyTM654NvMLxNNEnyzg3FA11yGaXSzmQfbB1dvqqKtnN2zJZUdhjpAoqBb3M3gye9Dghi7q",
                "program_account": "Vote111111111111111111111111111111111111111",
                "program_index": 4
              },
              "readable": {
                "arguments": {
                  "clock_sysvar": "SysvarC1ock11111111111111111111111111111111",
                  "slot_hashes_sysvar": "D8izqaR979Fc2amDoGHmYqEugjckEi1RQL1Y1JKyHUwX",
                  "timestamp": "1658224090",
                  "vote_account": "SysvarS1otHashes111111111111111111111111111",
                  "vote_authority": "DHdYsTEsd1wGrmthR1ognfRXPkWBmxAWAv2pKdAix3HY",
                  "vote_hash": "9yoSeo4kEjumeyYFfohaCUYyjsu134xhXbrAxumCmysC",
                  "vote_slots": "142209632"
                },
                "method_name": "Vote",
                "program_name": "Vote"
              }
            }
          ]
        }).to_string())
    }
}
