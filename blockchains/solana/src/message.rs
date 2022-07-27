use crate::error::{Result, SolanaError};
use crate::compact::Compact;
use crate::instruction::Instruction;
use crate::read::Read;
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
    use crate::message::Message;
    use crate::read::Read;
    use hex::{self, FromHex};
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

    fn read_message(tx: &str) -> String {
        let mut transaction = Vec::from_hex(tx).unwrap();
        let message = Message::read(&mut transaction).unwrap();
        message.to_json_str().unwrap()
    }

    #[test]
    fn test_transaction_1() {
        // System.Transfer
        let json = read_message("01000103876c762c4c83532f82966935ba1810659a96237028a2af6688dadecb0155ae071c7d0930a08193e702b0f24ebba96f179e9c186ef1208f98652ee775001744490000000000000000000000000000000000000000000000000000000000000000a7516fe1d3af3457fdc54e60856c0c3c87f4e5be3d10ffbc7a5cce8bf96792a101020200010c020000008813000000000000");
        assert_eq!(json, json!({"accounts":["A7dxsCbMy5ktZwQUgsQhVxsoJpx6wPAZYEcccQVjWnkE","2vCzt15qsXSCsf5k6t6QF9DiQSpE7kPTg3PdvFZtm2Tr","11111111111111111111111111111111"],"block_hash":"CG97KCGLGgPS1E754VjLgy724zNwGjE9sjrzqYa6CU2t","header":{"num_readonly_signed_accounts":0,"num_readonly_unsigned_accounts":1,"num_required_signatures":1},"instructions":[{"raw":{"account_indexes":[0,1],"accounts":"A7dxsCbMy5ktZwQUgsQhVxsoJpx6wPAZYEcccQVjWnkE,2vCzt15qsXSCsf5k6t6QF9DiQSpE7kPTg3PdvFZtm2Tr","data":"3Bxs4PckVVt51W8w","program_account":"11111111111111111111111111111111","program_index":2},"readable":{"arguments":{"amount":"5000","from":"A7dxsCbMy5ktZwQUgsQhVxsoJpx6wPAZYEcccQVjWnkE","to":"2vCzt15qsXSCsf5k6t6QF9DiQSpE7kPTg3PdvFZtm2Tr"},"method_name":"Transfer","program_name":"System"}}]}).to_string())
    }

    #[test]
    fn test_transaction_2() {
        // Vote.Vote
        let json = read_message("01000305b446cb8fd7c225bf416df87c286710d75711af95222e41216da2177289cbbfa6b68edcd94d93de68614892bd165a94a6647aa040d87b9a042b41a009bdb469cf06a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b210000000006a7d517192f0aafc6f265e3fb77cc7ada82c529d0be3b136e2d0055200000000761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da35380000000009254bd5e695fabf43f0ead6da730e88cf39bec6991c2c4374bcade97d0a73be7010404010302003d02000000010000000000000060f2790800000000856a887d33af1cd1723388576a7be8fa6d9c9c80c548495a24bf680c908812cf01da7dd66200000000");
        assert_eq!(json, json!({"accounts":["D8izqaR979Fc2amDoGHmYqEugjckEi1RQL1Y1JKyHUwX","DHdYsTEsd1wGrmthR1ognfRXPkWBmxAWAv2pKdAix3HY","SysvarC1ock11111111111111111111111111111111","SysvarS1otHashes111111111111111111111111111","Vote111111111111111111111111111111111111111"],"block_hash":"ArDU9jQqkrYg12SBihpjx7JSw2FjWtJ8K91uKTCyLEFG","header":{"num_readonly_signed_accounts":0,"num_readonly_unsigned_accounts":3,"num_required_signatures":1},"instructions":[{"raw":{"account_indexes":[1,3,2,0],"accounts":"DHdYsTEsd1wGrmthR1ognfRXPkWBmxAWAv2pKdAix3HY,SysvarS1otHashes111111111111111111111111111,SysvarC1ock11111111111111111111111111111111,D8izqaR979Fc2amDoGHmYqEugjckEi1RQL1Y1JKyHUwX","data":"2ZjTR1vUs2pHXyTM654NvMLxNNEnyzg3FA11yGaXSzmQfbB1dvqqKtnN2zJZUdhjpAoqBb3M3gye9Dghi7q","program_account":"Vote111111111111111111111111111111111111111","program_index":4},"readable":{"arguments":{"clock_sysvar":"SysvarC1ock11111111111111111111111111111111","slot_hashes_sysvar":"SysvarS1otHashes111111111111111111111111111","vote":{"hash":"9yoSeo4kEjumeyYFfohaCUYyjsu134xhXbrAxumCmysC","slots":"142209632","timestamp":"1658224090"},"vote_account":"DHdYsTEsd1wGrmthR1ognfRXPkWBmxAWAv2pKdAix3HY","vote_authority":"D8izqaR979Fc2amDoGHmYqEugjckEi1RQL1Y1JKyHUwX"},"method_name":"Vote","program_name":"Vote"}}]}).to_string())
    }

    #[test]
    fn test_transaction_3() {
        // System.CreateAccount + Token.InitializeMint + AToken.CreateAssociatedAccount + Custom Program
        // TODO: test InitialMint, CreateAssociatedAccount in this transaction
        // https://solscan.io/tx/34YhTdSXdcXF5DQ29rhLrvt7GtCYGHYJMtchpHotfsRx3TGdDm8scoNKhGY77s6r9hxQPoXQ7f2d1k1nA8aKdmKk
        let json = read_message("0200050a06852df21778a462ea79aae81500eae98a935dcca05f8b899ca8b41021a79980acc933a10d87058ad3131361cd345fe95eb7598ad52d972ee559f1ea3f8deb452bb2df65fdf1ad0514f549457e4338bb71e6885354aa5ed87969ef14f5fc736772295dfa0330919867f6f90f2e334d1a56a2203ec3d4086151aab0171ca13c74b626da01ca1cb62be1bbbf9927dd0de251964d351736fd36100bb0e06f728b4100000000000000000000000000000000000000000000000000000000000000008c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f8590b7065b1e3d17c45389d527f6b04c3cd58b86c731aa0fdb549b6d1bc03f8294606a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a0000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a92865a919afcfd4d57cf8f69e11990c98a55e4cc4389ba43c7d32184ca652adb406050200013400000000604d160000000000520000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90902010843000006852df21778a462ea79aae81500eae98a935dcca05f8b899ca8b41021a799800106852df21778a462ea79aae81500eae98a935dcca05f8b899ca8b41021a799800707030100000005087b0012000000536e65616b65722023313830333539303435000000003200000068747470733a2f2f6170692e737465706e2e636f6d2f72756e2f6e66746a736f6e2f3130332f3130363036313531353732319001010100000006852df21778a462ea79aae81500eae98a935dcca05f8b899ca8b41021a799800164010607000400010509080009030104000907010000000000000007090201000000030905080a0a010000000000000000");
        assert_eq!(json, json!({"accounts":["STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK","CdV4w55UDTvcza5d6V2Y6m7TF9Xmq9MHPUBYMe9WtptL","3wajAESNoYKGMuEqgXsdhEzp2mdpkc1BTVf9dNW1Pb4a","8ge4eJpudaataASooEDNuVk4W75M5CMv5suZS6Lw25to","DG3Za1KX8Tj1TeZJy2U9nDa8qX3tyZCBYNehNy4fFsnQ","11111111111111111111111111111111","ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL","metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s","SysvarRent111111111111111111111111111111111","TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],"block_hash":"3ihDb3AE8CY1vL4tUgN2Kj4KZybrGHvyVhnv5vfxdJ27","header":{"num_readonly_signed_accounts":0,"num_readonly_unsigned_accounts":5,"num_required_signatures":2},"instructions":[{"raw":{"account_indexes":[0,1],"accounts":"STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK,CdV4w55UDTvcza5d6V2Y6m7TF9Xmq9MHPUBYMe9WtptL","data":"11114XtYk9gGfZoo968fyjNUYQJKf9gdmkGoaoBpzFv4vyaSMBn3VKxZdv7mZLzoyX5YNC","program_account":"11111111111111111111111111111111","program_index":5},"readable":{"arguments":{"account":"CdV4w55UDTvcza5d6V2Y6m7TF9Xmq9MHPUBYMe9WtptL","amount":"1461600","funder":"STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK","owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","space":"82"},"method_name":"CreateAccount","program_name":"System"}},{"raw":{"account_indexes":[1,8],"accounts":"CdV4w55UDTvcza5d6V2Y6m7TF9Xmq9MHPUBYMe9WtptL,SysvarRent111111111111111111111111111111111","data":"11aNbEGym5ZbhL9jG3H2GJLxvX5FrZdNE6dYA1WvE94LzewqKD6uvACgcF4ebDPca9AT4oix8XzgBPJyMf7HtpUBTm","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":9},"readable":{"arguments":{"decimals":0,"freeze_authority":"STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK","mint":"CdV4w55UDTvcza5d6V2Y6m7TF9Xmq9MHPUBYMe9WtptL","mint_authority":"STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK","rent_sysvar":"SysvarRent111111111111111111111111111111111"},"method_name":"InitializeMint","program_name":"Token"}},{"raw":{"account_indexes":[3,1,0,0,0,5,8],"accounts":"8ge4eJpudaataASooEDNuVk4W75M5CMv5suZS6Lw25to,CdV4w55UDTvcza5d6V2Y6m7TF9Xmq9MHPUBYMe9WtptL,STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK,STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK,STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK,11111111111111111111111111111111,SysvarRent111111111111111111111111111111111","data":"1qc9PgwVveMHiKRmHs9DiE9zqA86thPyaoFr5WTuiGT72BNznAsUGa92jw27ZKojtPXtBH7C9jvSf6AE8JQ3aVfowUV6ZtZMkTxM6v6FKZRuRN4cMvETyxcCvAAUJhWRnp4iEmD5VcxNfiLx9E8UbCKeiEJHMNVD6riSoF6","program_account":"metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s","program_index":7},"readable":"Unable to parse instruction, reason: Program `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s` is not supported yet"},{"raw":{"account_indexes":[0,4,0,1,5,9,8],"accounts":"STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK,DG3Za1KX8Tj1TeZJy2U9nDa8qX3tyZCBYNehNy4fFsnQ,STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK,CdV4w55UDTvcza5d6V2Y6m7TF9Xmq9MHPUBYMe9WtptL,11111111111111111111111111111111,TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA,SysvarRent111111111111111111111111111111111","data":"","program_account":"ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL","program_index":6},"readable":"Unable to parse instruction, reason: Program `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` is not supported yet"},{"raw":{"account_indexes":[1,4,0],"accounts":"CdV4w55UDTvcza5d6V2Y6m7TF9Xmq9MHPUBYMe9WtptL,DG3Za1KX8Tj1TeZJy2U9nDa8qX3tyZCBYNehNy4fFsnQ,STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK","data":"6AuM4xMCPFhR","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":9},"readable":{"arguments":{"amount":"1","authority":"STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK","mint":"CdV4w55UDTvcza5d6V2Y6m7TF9Xmq9MHPUBYMe9WtptL","mint_to_account":"DG3Za1KX8Tj1TeZJy2U9nDa8qX3tyZCBYNehNy4fFsnQ"},"method_name":"MintTo","program_name":"Token"}},{"raw":{"account_indexes":[2,1,0,0,0,3,9,5,8],"accounts":"3wajAESNoYKGMuEqgXsdhEzp2mdpkc1BTVf9dNW1Pb4a,CdV4w55UDTvcza5d6V2Y6m7TF9Xmq9MHPUBYMe9WtptL,STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK,STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK,STEPNq2UGeGSzCyGVr2nMQAzf8xuejwqebd84wcksCK,8ge4eJpudaataASooEDNuVk4W75M5CMv5suZS6Lw25to,TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA,11111111111111111111111111111111,SysvarRent111111111111111111111111111111111","data":"ZbhHTZcMWdXcj","program_account":"metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s","program_index":7},"readable":"Unable to parse instruction, reason: Program `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s` is not supported yet"}]}).to_string())
    }

    #[test]
    fn test_transaction_4() {
        // System.CreateAccount + Token.InitializeAccount + Token.TokenTransfer + Token.CloseAccount
        // https://solscan.io/tx/5mSjiAapKzn7TEDWH3pkmNUYXSvmVyAAyF3zTEbmX9AosdfiC1dEbsQnNgDhUDBpNoYmSnPS99HPaBsKsakGR1hf
        let json = read_message("02000407e9940f6435ae992ddbb4ac739ada475fde93bd54c6a9f36a8b60b37fe23ec3fdd8ffff8ad461ca3138f356758b148f2dffa7d055a79356b52727298026189ae82e6df8bd210e5f167971908e8746aa6790aa3bc74ee48a4bbf23236f9effaa65069b8857feab8184fb687f634618c035dac439dc1aeb3b5598a0f0000000000106a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000000000000000000000000000000000000000000000000000000000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9bff514b7cba346fe333553de5579d50a7da74cf950dd7bdd27327ce9a17c876f04050200013400000000f01d1f0000000000a50000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9060401030004010106030201000903242d84be0000000006030100000109");
        assert_eq!(json, json!({"accounts":["GinwSnwbsjkWXkancBr5E6EPrQtKdwnE5vPdriv1tK3i","Fc5UC9wa32FVzeFB2ijduV4R5nnGQu4dXH8ZrRUCSHMh","48F1neXh5bGgKr8G6CM6tFZkaC51UgtVb5pqGLC27Doi","So11111111111111111111111111111111111111112","SysvarRent111111111111111111111111111111111","11111111111111111111111111111111","TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],"block_hash":"DvKd2LtXHva6tkZSp4EQUFGk23t7tjUEDK6XHXzfzF1G","header":{"num_readonly_signed_accounts":0,"num_readonly_unsigned_accounts":4,"num_required_signatures":2},"instructions":[{"raw":{"account_indexes":[0,1],"accounts":"GinwSnwbsjkWXkancBr5E6EPrQtKdwnE5vPdriv1tK3i,Fc5UC9wa32FVzeFB2ijduV4R5nnGQu4dXH8ZrRUCSHMh","data":"11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL","program_account":"11111111111111111111111111111111","program_index":5},"readable":{"arguments":{"account":"Fc5UC9wa32FVzeFB2ijduV4R5nnGQu4dXH8ZrRUCSHMh","amount":"2039280","funder":"GinwSnwbsjkWXkancBr5E6EPrQtKdwnE5vPdriv1tK3i","owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","space":"165"},"method_name":"CreateAccount","program_name":"System"}},{"raw":{"account_indexes":[1,3,0,4],"accounts":"Fc5UC9wa32FVzeFB2ijduV4R5nnGQu4dXH8ZrRUCSHMh,So11111111111111111111111111111111111111112,GinwSnwbsjkWXkancBr5E6EPrQtKdwnE5vPdriv1tK3i,SysvarRent111111111111111111111111111111111","data":"2","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":6},"readable":{"arguments":{"account":"Fc5UC9wa32FVzeFB2ijduV4R5nnGQu4dXH8ZrRUCSHMh","mint":"So11111111111111111111111111111111111111112","owner":"GinwSnwbsjkWXkancBr5E6EPrQtKdwnE5vPdriv1tK3i","rent_sysvar":"SysvarRent111111111111111111111111111111111"},"method_name":"InitializeAccount","program_name":"Token"}},{"raw":{"account_indexes":[2,1,0],"accounts":"48F1neXh5bGgKr8G6CM6tFZkaC51UgtVb5pqGLC27Doi,Fc5UC9wa32FVzeFB2ijduV4R5nnGQu4dXH8ZrRUCSHMh,GinwSnwbsjkWXkancBr5E6EPrQtKdwnE5vPdriv1tK3i","data":"3KWXrv5AxkoZ","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":6},"readable":{"arguments":{"amount":"3196333348","destination_account":"Fc5UC9wa32FVzeFB2ijduV4R5nnGQu4dXH8ZrRUCSHMh","owner":"GinwSnwbsjkWXkancBr5E6EPrQtKdwnE5vPdriv1tK3i","source_account":"48F1neXh5bGgKr8G6CM6tFZkaC51UgtVb5pqGLC27Doi"},"method_name":"Transfer","program_name":"Token"}},{"raw":{"account_indexes":[1,0,0],"accounts":"Fc5UC9wa32FVzeFB2ijduV4R5nnGQu4dXH8ZrRUCSHMh,GinwSnwbsjkWXkancBr5E6EPrQtKdwnE5vPdriv1tK3i,GinwSnwbsjkWXkancBr5E6EPrQtKdwnE5vPdriv1tK3i","data":"A","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":6},"readable":{"arguments":{"account":"Fc5UC9wa32FVzeFB2ijduV4R5nnGQu4dXH8ZrRUCSHMh","destination_account":"GinwSnwbsjkWXkancBr5E6EPrQtKdwnE5vPdriv1tK3i","owner":"GinwSnwbsjkWXkancBr5E6EPrQtKdwnE5vPdriv1tK3i"},"method_name":"Burn","program_name":"Token"}}]}).to_string());
    }

    #[test]
    fn test_transaction_5() {
        // Memo + AToken.CreateAssociatedAccount + Token.SetAuthority
        // https://solscan.io/tx/55gHV4rWvLbyz7V5rhn3NeMPMKKiuhHJbLRSwLqzCc2482jeowmc93UJuCD7h3GpB1E3pVdDETZQu3CBFZSnAXJS
        let json = read_message("0201060908a13fb5c9e7bc18aef6d4ec2e5bca9fb0b8c329c32bdf2baae9125aa3191cd36eeb5c79927943eef87a2828925665d2b3612a070fe5eee74680d8ac0b779ca136a3ae0cda1d97779bcd08c24409fe1c76f84f218aeed3296d8efe2dade261a606a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a0000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90b3338a0ab2cc841d5b014bc6a3cf756291874b319c9517d9bbfa9e4e9661ef90000000000000000000000000000000000000000000000000000000000000000054a5350f85dc882d614a55672788a296ddf1eababd0a60678884932f4eef6a08c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f859704b00127cf4d5d2ca44446993ee3bab439ce957bde518d1767b108b87a4a7d00307002c416141414141414141414141414141414141414141414141414141414141414141414141414141414141413d08070002010506040300040202012306030108a13fb5c9e7bc18aef6d4ec2e5bca9fb0b8c329c32bdf2baae9125aa3191cd3");
        assert_eq!(json, json!({"accounts":["agsWhfJ5PPGjmzMieWY8BR5o1XRVszUBQ5uFz4CtDiJ","8Tz15moyu4eL48o4Pq5XLyxX5XkkKEsNcgx27ycaPLaU","4gHmx6Puk1J9YntAUvnyrXP68SmjCvQocuArQCt5o4p5","SysvarRent111111111111111111111111111111111","TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","kinXdEcpDQeHPEuQnqmUgtYykqKGVFq6CeVX5iAHJq6","11111111111111111111111111111111","Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo","ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"],"block_hash":"8ZLzai689nErJVd5CW74QnPqT3HDs9Uwc4SC2CRgwaPH","header":{"num_readonly_signed_accounts":1,"num_readonly_unsigned_accounts":6,"num_required_signatures":2},"instructions":[{"raw":{"account_indexes":[],"accounts":"","data":"NFw4Tg8NvoG7NVDGdoferkiJmQTGJ6esGoTc6W89Z9HRabSLuLYYjs6qwPmW","program_account":"Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo","program_index":7},"readable":"Unable to parse instruction, reason: Program `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo` is not supported yet"},{"raw":{"account_indexes":[0,2,1,5,6,4,3],"accounts":"agsWhfJ5PPGjmzMieWY8BR5o1XRVszUBQ5uFz4CtDiJ,4gHmx6Puk1J9YntAUvnyrXP68SmjCvQocuArQCt5o4p5,8Tz15moyu4eL48o4Pq5XLyxX5XkkKEsNcgx27ycaPLaU,kinXdEcpDQeHPEuQnqmUgtYykqKGVFq6CeVX5iAHJq6,11111111111111111111111111111111,TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA,SysvarRent111111111111111111111111111111111","data":"","program_account":"ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL","program_index":8},"readable":"Unable to parse instruction, reason: Program `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` is not supported yet"},{"raw":{"account_indexes":[2,1],"accounts":"4gHmx6Puk1J9YntAUvnyrXP68SmjCvQocuArQCt5o4p5,8Tz15moyu4eL48o4Pq5XLyxX5XkkKEsNcgx27ycaPLaU","data":"bnu16WJX3yyY2rzoPSifzd3mq5vHtA5WZbxnfUmvV1MheRp","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":4},"readable":{"arguments":{"account":"4gHmx6Puk1J9YntAUvnyrXP68SmjCvQocuArQCt5o4p5","authority":"8Tz15moyu4eL48o4Pq5XLyxX5XkkKEsNcgx27ycaPLaU","authority_type":"close account","new_authority":"agsWhfJ5PPGjmzMieWY8BR5o1XRVszUBQ5uFz4CtDiJ"},"method_name":"SetAuthority","program_name":"Token"}}]}).to_string());
    }

    #[test]
    fn test_transaction_6() {
        // Token.Approve
        // https://solscan.io/tx/zf2KZX8S9BavoYxuxYrX47BmDY9YEdeMSzeCxakDoMGBCr7qYHjHAuEj5Qt2k6hV12XJKBGNAfsqLPPyPjthy5B
        let json = read_message("0301070faa30697d8ea2d14ce506c401ad5f1bd33476ebcb8a8b5cea89fa0aafb7c04f3925070f12913aa23553bfaf08f0a6f293aadb24dd66711db239c9b0ccca751b05dcc3a6c16cb67f59d67085e174cd7469f3e00b99a63d6c8d95337096f9e8437d8c17a1e64eba64bb7238d33b21461db8824508c879f91199d9eff9309ff63952baf04e4356057aaea057a6d744e1a0dbb99091448d6c2807114f0a016c9f2c39df8b1e991b87277d51b2ee23b63496ff1a54ab30e61eb4c4572e52fb99af9421e636e5095d76cede0e72ff2a024a07652d423fb7f3978a4663a278d13e1c1ba10deb821d34b39060c73598d3dd86ecf853df3b2f38b02991ad2ccfa51306e01600000000000000000000000000000000000000000000000000000000000000003f5877e18f96dea58c638a21d2be860ba96f0e21d1d84c6a94dba44e2be81f0e494500f4fdcbc9ad22814e250c0d6763266f6ca9169e12662f477601991e1a36be49a1eeb81bf889c158fd8b7496ff9141d4aa433eae3948d0d8488f78951b78069b8857feab8184fb687f634618c035dac439dc1aeb3b5598a0f0000000000106a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a0000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a954c495b382bac905bb70f97bc252b2ee3b796b2836a3287ed5787c70eb2484120608020001340000000030266d0500000000a50000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90e04010c000d01010e03010200090440084e05000000000b0a090a020106030504070e110140084e05000000005d4d3700000000000e02010001050e030100000109");
        assert_eq!(json, json!({"accounts":["CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC","3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i","FrmjFyCUdgrZfps1cJ7B3BTLnj9jjEJ34MwZncJBCxaG","ARryk4nSoS6bu7nyv6BgQah8oU23svFm7Rek7kR4fy3X","DajMqwbJXA7JbqgU97zycA1zReQhmTqf1YjNNQjo6gCQ","G3cxNKQvwnLDFEtRugKABmhUnf9BkhcV3n3pz1QgHLtQ","GVfKYBNMdaER21wwuqa4CSQV8ajVpuPbNZVV3wcuKWhE","wLavAJvGZa6Try8jxPRLc9AXBN4yCLF2qpFKbRNB4wF","11111111111111111111111111111111","5GGvkcqQ1554ibdc18JXiPqR8aJz6WV3JSNShoj32ufT","5w1nmqvpus3UfpP67EpYuHhE63aSFdF5AT8VHZTkvnp5","Dooar9JkhdZ7J3LHN3A7YCuoGRUggXhQaG4kijfLGU2j","So11111111111111111111111111111111111111112","SysvarRent111111111111111111111111111111111","TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],"block_hash":"6hu7DYzTwbg82Yw2c9yUGiuf5fFLccdvWLUyjYbafqdj","header":{"num_readonly_signed_accounts":1,"num_readonly_unsigned_accounts":7,"num_required_signatures":3},"instructions":[{"raw":{"account_indexes":[0,1],"accounts":"CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC,3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i","data":"11112mSibg2jPYkce37WqtWKZAsCdVzCYHNwDsAvX3a328yq65cStepo3P2qyd9wGCvoLC","program_account":"11111111111111111111111111111111","program_index":8},"readable":{"arguments":{"account":"3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i","amount":"91039280","funder":"CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC","owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","space":"165"},"method_name":"CreateAccount","program_name":"System"}},{"raw":{"account_indexes":[1,12,0,13],"accounts":"3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i,So11111111111111111111111111111111111111112,CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC,SysvarRent111111111111111111111111111111111","data":"2","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":14},"readable":{"arguments":{"account":"3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i","mint":"So11111111111111111111111111111111111111112","owner":"CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC","rent_sysvar":"SysvarRent111111111111111111111111111111111"},"method_name":"InitializeAccount","program_name":"Token"}},{"raw":{"account_indexes":[1,2,0],"accounts":"3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i,FrmjFyCUdgrZfps1cJ7B3BTLnj9jjEJ34MwZncJBCxaG,CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC","data":"48zH6qc1xRCj","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":14},"readable":{"arguments":{"amount":"89000000","delegate_account":"FrmjFyCUdgrZfps1cJ7B3BTLnj9jjEJ34MwZncJBCxaG","owner":"CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC","source_account":"3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i"},"method_name":"Approve","program_name":"Token"}},{"raw":{"account_indexes":[9,10,2,1,6,3,5,4,7,14],"accounts":"5GGvkcqQ1554ibdc18JXiPqR8aJz6WV3JSNShoj32ufT,5w1nmqvpus3UfpP67EpYuHhE63aSFdF5AT8VHZTkvnp5,FrmjFyCUdgrZfps1cJ7B3BTLnj9jjEJ34MwZncJBCxaG,3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i,GVfKYBNMdaER21wwuqa4CSQV8ajVpuPbNZVV3wcuKWhE,ARryk4nSoS6bu7nyv6BgQah8oU23svFm7Rek7kR4fy3X,G3cxNKQvwnLDFEtRugKABmhUnf9BkhcV3n3pz1QgHLtQ,DajMqwbJXA7JbqgU97zycA1zReQhmTqf1YjNNQjo6gCQ,wLavAJvGZa6Try8jxPRLc9AXBN4yCLF2qpFKbRNB4wF,TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","data":"gX6pJKFn9nTGZYN6UfFFps","program_account":"Dooar9JkhdZ7J3LHN3A7YCuoGRUggXhQaG4kijfLGU2j","program_index":11},"readable":"Unable to parse instruction, reason: Program `Dooar9JkhdZ7J3LHN3A7YCuoGRUggXhQaG4kijfLGU2j` is not supported yet"},{"raw":{"account_indexes":[1,0],"accounts":"3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i,CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC","data":"6","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":14},"readable":{"arguments":{"owner":"CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC","source_account":"3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i"},"method_name":"Revoke","program_name":"Token"}},{"raw":{"account_indexes":[1,0,0],"accounts":"3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i,CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC,CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC","data":"A","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":14},"readable":{"arguments":{"account":"3VYL1TrNMJFQaLy3SC9jAe9gNgymPgQgcZQNUzcc6M3i","destination_account":"CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC","owner":"CTM8DpiZXt1R85fxY4NM85P5t3QqR4Wjm1V85Z8EjVCC"},"method_name":"Burn","program_name":"Token"}}]}).to_string());
    }

    #[test]
    fn test_transaction_7() {
        // System.CreateAccountWithSeed + Stake: Initialize + Stake: Delegate
        // https://solscan.io/tx/UxNDLmLJb1nR9sx3Q4xnELJZuneM4W9WBfb2pwBYDjWfCHxpWqCGgjpUsrwqMAFzfkCCNDj4AUpzvguSQ8tDHEk
        let json = read_message("010007096aefb992fa0cd54aea185bf65a7da92aad6bd46da5a67c7675a04e6540d86f7a3d2ce2421048aa748a6cc22b5696032f902cfc0b3dd6bce0d379f76c383bceda0000000000000000000000000000000000000000000000000000000000000000e23a2b23b625e7513991be370a2c20d5c5e276491d36777ef2e5b1227ffe732906a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc00000000006a1d817a502050b680791e6ce6db88e1e5b7150f61fc6790a4eb4d10000000006a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b210000000006a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a0000000006a7d517193584d0feed9bb3431d13206be544281b57b8566cc5375ff4000000aada712c5d14f4e64d913b330ff3e519bc7f2aac580997f0c549620601866915030202000174030000006aefb992fa0cd54aea185bf65a7da92aad6bd46da5a67c7675a04e6540d86f7a18000000000000007374616b653a302e3231363239323431373439393638393500de2a9200000000c80000000000000006a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc0000000000402010774000000006aefb992fa0cd54aea185bf65a7da92aad6bd46da5a67c7675a04e6540d86f7a6aefb992fa0cd54aea185bf65a7da92aad6bd46da5a67c7675a04e6540d86f7a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004060103060805000402000000");
        assert_eq!(json, json!({"accounts":["8CSELK4udyP5M3XU3nNRc9N8zfqL3Z6zFybiz3Bm9beH","57oZmoSzqF5at3ioAV7h849mUa6FKdu98ig3FwmjS4Nd","11111111111111111111111111111111","GE6atKoWiQ2pt3zL7N13pjNHjdLVys8LinG8qeJLcAiL","Stake11111111111111111111111111111111111111","StakeConfig11111111111111111111111111111111","SysvarC1ock11111111111111111111111111111111","SysvarRent111111111111111111111111111111111","SysvarStakeHistory1111111111111111111111111"],"block_hash":"CVwVzgVbSKbSeybxUsvKTDgCt5tkVuEsWVkZaEy3sk6x","header":{"num_readonly_signed_accounts":0,"num_readonly_unsigned_accounts":7,"num_required_signatures":1},"instructions":[{"raw":{"account_indexes":[0,1],"accounts":"8CSELK4udyP5M3XU3nNRc9N8zfqL3Z6zFybiz3Bm9beH,57oZmoSzqF5at3ioAV7h849mUa6FKdu98ig3FwmjS4Nd","data":"4gmm6vheLREbsXu6JNWuTBnSdJf4LHBSetvxrTTRap8ujutQ9hzKFHxcLnkLeVCS1twH9qY8fwgu9Dbks4DSHVkbf4pjHvo4yr2m6LEFfZzqvJjnPM8t3rMbBWHhHGTWKchiPFKXReTuEyQvpssg4hFW6xKyLs","program_account":"11111111111111111111111111111111","program_index":2},"readable":{"arguments":{"account":"57oZmoSzqF5at3ioAV7h849mUa6FKdu98ig3FwmjS4Nd","amount":"2452282880","base":"8CSELK4udyP5M3XU3nNRc9N8zfqL3Z6zFybiz3Bm9beH","funder":"8CSELK4udyP5M3XU3nNRc9N8zfqL3Z6zFybiz3Bm9beH","owner":"Stake11111111111111111111111111111111111111","seed":"stake:0.2162924174996895","signer":null,"space":"200"},"method_name":"CreateAccountWithSeed","program_name":"System"}},{"raw":{"account_indexes":[1,7],"accounts":"57oZmoSzqF5at3ioAV7h849mUa6FKdu98ig3FwmjS4Nd,SysvarRent111111111111111111111111111111111","data":"1111M5VGXdRTNyvFXopVKSaUzFxt4rov9gyD1qojEpE8xyqR66tSfH2vXdTbjmEUPZNgMZ6Leet3FDuwrHMN15jbNukNoxyxkaCnMaZAz8VJmEKK8wuJ7RnV8i5UWFA21ADh5xRknDDcAzyyaKBNLEiU1uLes","program_account":"Stake11111111111111111111111111111111111111","program_index":4},"readable":{"arguments":{"authorized":{"staker":"8CSELK4udyP5M3XU3nNRc9N8zfqL3Z6zFybiz3Bm9beH","withdrawer":"8CSELK4udyP5M3XU3nNRc9N8zfqL3Z6zFybiz3Bm9beH"},"lockup":{"custodian":"11111111111111111111111111111111","epoch":0,"timestamp":0},"rent_sysvar":"SysvarRent111111111111111111111111111111111","stake_account":"57oZmoSzqF5at3ioAV7h849mUa6FKdu98ig3FwmjS4Nd"},"method_name":"Initialize","program_name":"Stake"}},{"raw":{"account_indexes":[1,3,6,8,5,0],"accounts":"57oZmoSzqF5at3ioAV7h849mUa6FKdu98ig3FwmjS4Nd,GE6atKoWiQ2pt3zL7N13pjNHjdLVys8LinG8qeJLcAiL,SysvarC1ock11111111111111111111111111111111,SysvarStakeHistory1111111111111111111111111,StakeConfig11111111111111111111111111111111,8CSELK4udyP5M3XU3nNRc9N8zfqL3Z6zFybiz3Bm9beH","data":"3xyZh","program_account":"Stake11111111111111111111111111111111111111","program_index":4},"readable":{"arguments":{"authority":"8CSELK4udyP5M3XU3nNRc9N8zfqL3Z6zFybiz3Bm9beH","clock_sysvar":"SysvarC1ock11111111111111111111111111111111","config_account":"StakeConfig11111111111111111111111111111111","stake_account":"57oZmoSzqF5at3ioAV7h849mUa6FKdu98ig3FwmjS4Nd","stake_history_sysvar":"SysvarStakeHistory1111111111111111111111111","vote_account":"GE6atKoWiQ2pt3zL7N13pjNHjdLVys8LinG8qeJLcAiL"},"method_name":"DelegateStake","program_name":"Stake"}}]}).to_string());
    }

    #[test]
    fn test_transaction_8() {
        // Stake: Withdraw
        // https://solscan.io/tx/4UDXRHMzzfFFnayfbR5pmRvdn3YqPwvYb7s5TkoL92osGGagENpfYXLFnK5guZ7187Dd3eNjDFDMkBd7jixpDfnG
        let json = read_message("01000305575949043cea1e1713d06b6b2eba6bb22d303884908e683fcaaa7b0ba6209be859d521dc428449106dabb34dadd3b44cc7795f58be0d4a81aaeaada967b21bd206a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc00000000006a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b210000000006a7d517193584d0feed9bb3431d13206be544281b57b8566cc5375ff400000067415e51677a2d98e9f86da5c65fe4c72bdee5cb2755af7a27d13dda710aa26001020501000304000c04000000ed77410300000000");
        assert_eq!(json, json!({"accounts":["6sySB1243EqqtMsExjNwmbouFVksZAF6w6bGe99V2CgX","73fnG8GC1ZanZSVv86re4kQsbrsiLP7xPCvXizCs9XW9","Stake11111111111111111111111111111111111111","SysvarC1ock11111111111111111111111111111111","SysvarStakeHistory1111111111111111111111111"],"block_hash":"7x4oh9xNyHE4HEozqDe3GXSjqX3cawjr7q1cDTAhXqnX","header":{"num_readonly_signed_accounts":0,"num_readonly_unsigned_accounts":3,"num_required_signatures":1},"instructions":[{"raw":{"account_indexes":[1,0,3,4,0],"accounts":"73fnG8GC1ZanZSVv86re4kQsbrsiLP7xPCvXizCs9XW9,6sySB1243EqqtMsExjNwmbouFVksZAF6w6bGe99V2CgX,SysvarC1ock11111111111111111111111111111111,SysvarStakeHistory1111111111111111111111111,6sySB1243EqqtMsExjNwmbouFVksZAF6w6bGe99V2CgX","data":"5Nvj7gS32ohGJR5Z","program_account":"Stake11111111111111111111111111111111111111","program_index":2},"readable":{"arguments":{"amount":"54622189","clock_sysvar":"SysvarC1ock11111111111111111111111111111111","recipient_account":"6sySB1243EqqtMsExjNwmbouFVksZAF6w6bGe99V2CgX","stake_account":"73fnG8GC1ZanZSVv86re4kQsbrsiLP7xPCvXizCs9XW9","stake_authority":null,"stake_history_sysvar":"SysvarStakeHistory1111111111111111111111111","withdraw_authority":"6sySB1243EqqtMsExjNwmbouFVksZAF6w6bGe99V2CgX"},"method_name":"Withdraw","program_name":"Stake"}}]}).to_string());
    }

    #[test]
    fn test_transaction_9() {
        // Stake: Deactivate
        // https://solscan.io/tx/23nCgTp9zNo7e56bcFiyYgM4t4A9HGGX4z3JNPMzBxGbGExAVSMBfpkE3digYRcYbKUQfwnq3rGtEND7fD5HiT2x
        let json = read_message("010002044dd6a13d7b9ca64c690638eb9679f4a264a5a93022212ec608b24964dbc5701aff979426efda42a314f5b5477ea3264fddfb5ee1b9f939bff1e90cbea09cde3306a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc00000000006a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b2100000000a4eb4d5967097a0ec98783003eba3fde67341ba6d6d55f7d6987494a952466520102030103000405000000");
        assert_eq!(json, json!({"accounts":["6ErDKgZ7M1jdHp9fMWQ7mB3vmxBAWKH7YJ9FGk1qaYBK","JCj29zzZjPjZnDKVP7EyR6gordbAAYacKGkG811NepcJ","Stake11111111111111111111111111111111111111","SysvarC1ock11111111111111111111111111111111"],"block_hash":"C6mxxjU1QuPoDAJQwheeXwv6CnFt8toc11zPM7rvy4Wd","header":{"num_readonly_signed_accounts":0,"num_readonly_unsigned_accounts":2,"num_required_signatures":1},"instructions":[{"raw":{"account_indexes":[1,3,0],"accounts":"JCj29zzZjPjZnDKVP7EyR6gordbAAYacKGkG811NepcJ,SysvarC1ock11111111111111111111111111111111,6ErDKgZ7M1jdHp9fMWQ7mB3vmxBAWKH7YJ9FGk1qaYBK","data":"8QwQj","program_account":"Stake11111111111111111111111111111111111111","program_index":2},"readable":{"arguments":{"clock_sysvar":"SysvarC1ock11111111111111111111111111111111","delegated_stake_account":"JCj29zzZjPjZnDKVP7EyR6gordbAAYacKGkG811NepcJ","stake_authority":"6ErDKgZ7M1jdHp9fMWQ7mB3vmxBAWKH7YJ9FGk1qaYBK"},"method_name":"Deactivate","program_name":"Stake"}}]}).to_string());
    }

    #[test]
    fn test_transaction_10() {
        // https://solscan.io/tx/3KCJ2aWgKc6cyEagFdk74WfM9eDw7VumB7rPw96fQkD1CmjG3w29gTazDEvNsc2bNbkQaZAvL2att11Siy8qF89k
        let json = read_message("0301080fae0e9965d80b3bb521ed714366a4d461fd58d7b7c97caa15564ba34c3ec5c04d940d487f489c470872533e2d8b55a5ec1ae1fd130cefae0f1bd1527a9b6955c1ab9daad5867d8a4dba28bb9b9bc4146bc81a83e877c01d693d9860e2863df6f5aaf29edc6d0d3544fccda1232277d6032783264c5cfc335600c85f30754adaa9f604b96c15a6018a88598d0c5a310fe2b6333aa48ba916e502be02578ca50384cc51e45da7f68a2906979e692c1e8bc87e51deca9ddfe7e673895a01ef80facf5f4019373457f129bf4cae6a4255518b885bf718157dd4357233dc79268c4cbf069b8857feab8184fb687f634618c035dac439dc1aeb3b5598a0f0000000000106a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a0000000006a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b210000000023166cdfc331b06925f390147d4270172c25a5b218580326b09081a9f3bbe90c051e8a28c6a067b32fbb33323ed92334b6adbdc4639b871c8a2e44f47058ef8506ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a900000000000000000000000000000000000000000000000000000000000000000508c2ceb1b5d05c874980ac52cf659740e7e9b9356aaf2a0362673263526c15e83b5d0c7735cf4f76914b1488bc665d32dce3140950851428922cc65fbb565b070c03030200090424eb0700000000000d0200013400000000f01d1f0000000000a50000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90c040107000801010e02090401080e0a03010405060a0b02090c090424eb0700000000000c02030001050c03010000010901");
        assert_eq!(json, json!({"accounts":["CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC","Axw63e2KwrSmqWsZcNUQNXHH4cSfv2xEJBZG7Ua5Rrit","CYvAAqCR6LjctqdWvPe1CfBW9p5uSc85Da45gENrVSr8","CWJtEyYYHy3ydjHn5Beh48mHiW9BBHSYjcGDJkB8awNx","HZMUNJQDwT8rdEiY2r15UR6h8yYg7QkxiekjyJGFFwnB","EkabaFX962r7gbdjQ6i2kfbrjFA6XppgKZ4APeUhA7gS","7QpRNyLenfoUA8SrpDTaaurtx4JxAJ2j4zdkNUMsTa6A","So11111111111111111111111111111111111111112","SysvarRent111111111111111111111111111111111","SysvarC1ock11111111111111111111111111111111","3My6wgR1fHmDFqBvv1hys7PigtH1megLncRCh2PkBMTR","Lz3nGpTr7SfSf7eJqcoQEkXK2fSK3dfCoSdQSKxbXxQ","TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","11111111111111111111111111111111","LendZqTs7gn5CTSJU1jWKhKuVpjJGom45nnwPb2AMTi"],"block_hash":"GdY64TjWowmh4pojKVu6ZW1mVyMXikdY3AYCoor25r8J","header":{"num_readonly_signed_accounts":1,"num_readonly_unsigned_accounts":8,"num_required_signatures":3},"instructions":[{"raw":{"account_indexes":[3,2,0],"accounts":"CWJtEyYYHy3ydjHn5Beh48mHiW9BBHSYjcGDJkB8awNx,CYvAAqCR6LjctqdWvPe1CfBW9p5uSc85Da45gENrVSr8,CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC","data":"44TEbAMwXMLK","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":12},"readable":{"arguments":{"amount":"518948","delegate_account":"CYvAAqCR6LjctqdWvPe1CfBW9p5uSc85Da45gENrVSr8","owner":"CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC","source_account":"CWJtEyYYHy3ydjHn5Beh48mHiW9BBHSYjcGDJkB8awNx"},"method_name":"Approve","program_name":"Token"}},{"raw":{"account_indexes":[0,1],"accounts":"CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC,Axw63e2KwrSmqWsZcNUQNXHH4cSfv2xEJBZG7Ua5Rrit","data":"11119os1e9qSs2u7TsThXqkBSRVFxhmYaFKFZ1waB2X7armDmvK3p5GmLdUxYdg3h7QSrL","program_account":"11111111111111111111111111111111","program_index":13},"readable":{"arguments":{"account":"Axw63e2KwrSmqWsZcNUQNXHH4cSfv2xEJBZG7Ua5Rrit","amount":"2039280","funder":"CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC","owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","space":"165"},"method_name":"CreateAccount","program_name":"System"}},{"raw":{"account_indexes":[1,7,0,8],"accounts":"Axw63e2KwrSmqWsZcNUQNXHH4cSfv2xEJBZG7Ua5Rrit,So11111111111111111111111111111111111111112,CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC,SysvarRent111111111111111111111111111111111","data":"2","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":12},"readable":{"arguments":{"account":"Axw63e2KwrSmqWsZcNUQNXHH4cSfv2xEJBZG7Ua5Rrit","mint":"So11111111111111111111111111111111111111112","owner":"CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC","rent_sysvar":"SysvarRent111111111111111111111111111111111"},"method_name":"InitializeAccount","program_name":"Token"}},{"raw":{"account_indexes":[9,4],"accounts":"SysvarC1ock11111111111111111111111111111111,HZMUNJQDwT8rdEiY2r15UR6h8yYg7QkxiekjyJGFFwnB","data":"9","program_account":"LendZqTs7gn5CTSJU1jWKhKuVpjJGom45nnwPb2AMTi","program_index":14},"readable":"Unable to parse instruction, reason: Error occurred when parsing program instruction, reason: `Custom program error: 0x0`"},{"raw":{"account_indexes":[3,1,4,5,6,10,11,2,9,12],"accounts":"CWJtEyYYHy3ydjHn5Beh48mHiW9BBHSYjcGDJkB8awNx,Axw63e2KwrSmqWsZcNUQNXHH4cSfv2xEJBZG7Ua5Rrit,HZMUNJQDwT8rdEiY2r15UR6h8yYg7QkxiekjyJGFFwnB,EkabaFX962r7gbdjQ6i2kfbrjFA6XppgKZ4APeUhA7gS,7QpRNyLenfoUA8SrpDTaaurtx4JxAJ2j4zdkNUMsTa6A,3My6wgR1fHmDFqBvv1hys7PigtH1megLncRCh2PkBMTR,Lz3nGpTr7SfSf7eJqcoQEkXK2fSK3dfCoSdQSKxbXxQ,CYvAAqCR6LjctqdWvPe1CfBW9p5uSc85Da45gENrVSr8,SysvarC1ock11111111111111111111111111111111,TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","data":"44TEbAMwXMLK","program_account":"LendZqTs7gn5CTSJU1jWKhKuVpjJGom45nnwPb2AMTi","program_index":14},"readable":{"arguments":{"destination_collateral_pubkey":"Axw63e2KwrSmqWsZcNUQNXHH4cSfv2xEJBZG7Ua5Rrit","lending_market_authority_pubkey":"Lz3nGpTr7SfSf7eJqcoQEkXK2fSK3dfCoSdQSKxbXxQ","lending_market_pubkey":"3My6wgR1fHmDFqBvv1hys7PigtH1megLncRCh2PkBMTR","liquidity_amount":"518948","reserve_collateral_mint_pubkey":"7QpRNyLenfoUA8SrpDTaaurtx4JxAJ2j4zdkNUMsTa6A","reserve_liquidity_supply_pubkey":"EkabaFX962r7gbdjQ6i2kfbrjFA6XppgKZ4APeUhA7gS","reserve_pubkey":"HZMUNJQDwT8rdEiY2r15UR6h8yYg7QkxiekjyJGFFwnB","source_liquidity_pubkey":"CWJtEyYYHy3ydjHn5Beh48mHiW9BBHSYjcGDJkB8awNx","sysvar_clock":"SysvarC1ock11111111111111111111111111111111","token_program_id":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","user_transfer_authority_pubkey":"CYvAAqCR6LjctqdWvPe1CfBW9p5uSc85Da45gENrVSr8"},"method_name":"DepositReserveLiquidity","program_name":"TokenLending"}},{"raw":{"account_indexes":[3,0],"accounts":"CWJtEyYYHy3ydjHn5Beh48mHiW9BBHSYjcGDJkB8awNx,CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC","data":"6","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":12},"readable":{"arguments":{"owner":"CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC","source_account":"CWJtEyYYHy3ydjHn5Beh48mHiW9BBHSYjcGDJkB8awNx"},"method_name":"Revoke","program_name":"Token"}},{"raw":{"account_indexes":[1,0,0],"accounts":"Axw63e2KwrSmqWsZcNUQNXHH4cSfv2xEJBZG7Ua5Rrit,CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC,CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC","data":"A","program_account":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","program_index":12},"readable":{"arguments":{"account":"Axw63e2KwrSmqWsZcNUQNXHH4cSfv2xEJBZG7Ua5Rrit","destination_account":"CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC","owner":"CiSrMrPbsnr2pXFHEKXSvHqw1r29qbpRnK1qV9n7zYCC"},"method_name":"Burn","program_name":"Token"}}]}).to_string());
    }
}
