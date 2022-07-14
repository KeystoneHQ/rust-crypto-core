use hex::{encode, ToHex};

use crate::types::compact::Compact;
use crate::types::read::Read;
use bs58;
use serde_json::json;

struct Signature {
    value: Vec<u8>,
}

impl Read<Signature> for Signature {
    fn read(raw: &mut Vec<u8>) -> Result<Signature, String> {
        if raw.len() < 64 {
            return Err(format!("meet invalid data when reading signature"));
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
    fn read(raw: &mut Vec<u8>) -> Result<Account, String> {
        if raw.len() < 32 {
            return Err(format!("meet invalid data when reading account"));
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
    fn read(raw: &mut Vec<u8>) -> Result<BlockHash, String> {
        if raw.len() < 32 {
            return Err(format!("meet invalid data when reading blockhash"));
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
    fn read(raw: &mut Vec<u8>) -> Result<Message, String> {
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
    pub fn to_json_str(&self) -> String {
        let json = json!({
            "header": {
                "num_required_signatures": self.header.num_required_signatures,
                "num_readonly_signed_accounts": self.header.num_readonly_signed_accounts,
                "num_readonly_unsigned_accounts": self.header.num_readonly_unsigned_accounts,
            },
            "accounts": self.accounts.iter().map(|account| {bs58::encode(&account.value).into_string()}).collect::<Vec<String>>(),
            "block_hash": bs58::encode(&self.block_hash.value).into_string(),
            "instructions": self.instructions.iter().map(|instruction| {
                json!({
                    "program_index": instruction.program_index,
                    "program_account": bs58::encode(&self.accounts[usize::from(instruction.program_index)].value).into_string(),
                    "account_indexes": instruction.account_indexes,
                    "accounts": instruction.account_indexes.iter().map(|account_index| bs58::encode(&self.accounts[usize::from(*account_index)].value).into_string()).collect::<String>(),
                    "data": bs58::encode(&instruction.data).into_string(),
                })
            }).collect::<serde_json::Value>()
        });
        json.to_string()
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
    fn read(raw: &mut Vec<u8>) -> Result<MessageHeader, String> {
        if raw.len() < 3 {
            return Err(format!("meet invalid data when reading message header"));
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
    fn read(raw: &mut Vec<u8>) -> Result<u8, String> {
        if raw.len() < 1 {
            return Err(format!("invalid data when reading u8"));
        }
        Ok(raw.remove(0))
    }
}

struct Instruction {
    program_index: u8,
    account_indexes: Vec<u8>,
    data: Vec<u8>,
}

impl Read<Instruction> for Instruction {
    fn read(raw: &mut Vec<u8>) -> Result<Instruction, String> {
        if raw.len() < 1 {
            return Err(format!("meet invalid data when reading instruction"));
        }
        let program_index = raw.remove(0);
        let account_indexes = Compact::read(raw)?.data;
        let data = Compact::read(raw)?.data;
        Ok(Instruction {
            program_index,
            account_indexes,
            data,
        })
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

        assert_eq!(message.to_json_str(), json!({
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
              "account_indexes": [0, 1],
              "accounts": "EX1oURpiPWWYUjVSK9KQR2qyqTBaR1EGfRNxkTsNk57Y23qJPvgvCBGJFhPmemqcksVCtrLDKyXJh5ZstjfCuu9q",
              "data": "3Bxs411Dtc7pkFQj",
              "program_account": "11111111111111111111111111111111",
              "program_index": 2
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
}
