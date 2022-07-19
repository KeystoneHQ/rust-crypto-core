use std::fmt::format;
use serde_json::{json, Value};
use crate::Read;
use crate::types::compact::Compact;
use solana_sdk;
use solana_program;
use solana_program::bpf_loader_upgradeable::UpgradeableLoaderState::Program;
use solana_program::system_instruction::SystemInstruction;
use crate::error::{SolanaError, Result};
use crate::error::SolanaError::ProgramError;

pub struct Instruction {
    pub(crate) program_index: u8,
    pub(crate) account_indexes: Vec<u8>,
    pub(crate) data: Vec<u8>,
}

impl Read<Instruction> for Instruction {
    fn read(raw: &mut Vec<u8>) -> Result<Instruction> {
        if raw.len() < 1 {
            return Err(SolanaError::InvalidData(format!("instruction")));
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

enum SupportedProgram {
    SystemProgram,
    TokenProgram,
}

impl SupportedProgram {
    pub fn from_program_id(program_id: String) -> Result<Self> {
        match program_id.as_str() {
            "11111111111111111111111111111111" => Ok(SupportedProgram::SystemProgram),
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" => Ok(SupportedProgram::TokenProgram),
            x => {
                Err(SolanaError::UnsupportedProgram(x.to_string()))
            }
        }
    }
}


impl Instruction {
    pub fn parse(&self, program_id: &String, accounts: Vec<String>) -> Result<Value> {
        let program = SupportedProgram::from_program_id(program_id.clone())?;
        let _accounts: Result<Vec<String>> = self.account_indexes.iter()
            .map(|v|
                accounts.get(usize::from(v.clone())).map(|v| v.clone())
                    .ok_or(SolanaError::InvalidData(format!("instruction data")))
            ).collect();
        match program {
            SupportedProgram::SystemProgram => {
                let instruction = Self::parse_native_program_instruction::<solana_program::system_instruction::SystemInstruction>
                    (self.data.clone())?;
                Self::resolve_system_program_instruction(instruction, _accounts?)
            }
            SupportedProgram::TokenProgram => {
                unimplemented!()
                // Self::parse_on_chain_program_instruction(_accounts, self.data.clone())
            }
        }
    }

    fn parse_native_program_instruction<T: for<'de> serde::de::Deserialize<'de>>(instruction_data: Vec<u8>) -> Result<T> {
        solana_sdk::program_utils::limited_deserialize::<T>(instruction_data.as_slice())
            .map_err(|e| ProgramError(e.to_string()))
    }

    fn resolve_system_program_instruction(instruction: SystemInstruction, accounts: Vec<String>) -> Result<Value> {
        let program_name = "System";
        match instruction {
            SystemInstruction::Transfer {
                lamports
            } => {
                let method_name = "Transfer";
                let from = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("Transfer.from")))?;
                let to = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!("Transfer.to")))?;
                let amount = lamports.to_string();
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "from": from,
                        "to": to,
                        "amount": amount
                    },
                }))
            }
            SystemInstruction::Allocate {
                space
            } => {
                let method_name = "Allocate";
                let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("Allocate.account")))?;
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "account": account,
                        "space": space.to_string(),
                    },
                }))
            }
            SystemInstruction::Assign {
                owner
            } => {
                let method_name = "Assign";
                let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("Allocate.account")))?;
                let new_owner = owner.to_string();
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "account": account,
                        "new_owner": new_owner,
                    },
                }))
            }
            SystemInstruction::CreateAccount {
                lamports, space, owner,
            } => {
                let method_name = "CreateAccount";
                let funder = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("CreateAccount.funder")))?;
                let account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!("CreateAccount.account")))?;
                let amount = lamports.to_string();
                let space = space.to_string();
                let owner = owner.to_string();
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "funder": funder,
                        "account": account,
                        "amount": amount,
                        "space": space,
                        "owner": owner,
                    },
                }))
            }
            SystemInstruction::AssignWithSeed {
                owner, seed, base
            } => {
                let method_name = "AssignWithSeed";
                let assigned_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("AssignWithSeed.assigned_account")))?;
                let base_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!("AssignWithSeed.base_account")))?;
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "assigned_account": assigned_account,
                        "base_account": base_account,
                        "seed": seed,
                        "base": base.to_string(),
                        "owner": owner.to_string(),
                    },
                }))
            }
            SystemInstruction::AdvanceNonceAccount {} => {
                let method_name = "AdvanceNonceAccount";
                let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("AdvanceNonceAccount.nonce_account")))?;
                let recent_blockhashes_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!("AdvanceNonceAccount.recent_blockhashes_account")))?;
                let authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!("AdvanceNonceAccount.authority")))?;
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "nonce_account": nonce_account,
                        "recent_blockhashes_account": recent_blockhashes_account,
                        "authority": authority,
                    },
                }))
            }
            SystemInstruction::AllocateWithSeed {
                owner, base, seed, space
            } => {
                let method_name = "AllocateWithSeed";
                let allocated_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("AllocateWithSeed.allocated_account")))?;
                let base_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!("AllocateWithSeed.base_account")))?;
                let owner = owner.to_string();
                let base = base.to_string();
                let space = space.to_string();
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "allocated_account": allocated_account,
                        "base_account": base_account,
                        "owner": owner,
                        "base": base,
                        "space": space
                    },
                }))
            }
            SystemInstruction::AuthorizeNonceAccount(
                pubkey
            ) => {
                let method_name = "AuthorizeNonceAccount";
                let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("AuthorizeNonceAccount.nonce_account")))?;
                let nonce_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!("AuthorizeNonceAccount.nonce_authority")))?;
                let new_authority = pubkey.to_string();
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "nonce_account": nonce_account,
                        "nonce_authority": nonce_authority,
                        "new_authority": new_authority,
                    },
                }))
            }
            SystemInstruction::InitializeNonceAccount(
                pubkey,
            ) => {
                let method_name = "InitializeNonceAccount";
                let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("InitializeNonceAccount.nonce_account")))?;
                let recent_blockhashes_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!("InitializeNonceAccount.recent_blockhashes_account")))?;
                let rent_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!("InitializeNonceAccount.rent_account")))?;
                let authority = pubkey.to_string();
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "nonce_account": nonce_account,
                        "recent_blockhashes_account": recent_blockhashes_account,
                        "rent_account": rent_account,
                        "authority": authority,
                    },
                }))
            }
            SystemInstruction::WithdrawNonceAccount(
                lamports
            ) => {
                let method_name = "WithdrawNonceAccount";
                let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("WithdrawNonceAccount.nonce_account")))?;
                let recipient_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!("WithdrawNonceAccount.recipient_account")))?;
                let recent_blockhashes_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!("WithdrawNonceAccount.recent_blockhashes_account")))?;
                let rent_account = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!("WithdrawNonceAccount.rent_account")))?;
                let nonce_authority = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!("WithdrawNonceAccount.nonce_authority")))?;
                let amount = lamports.to_string();
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "nonce_account": nonce_account,
                        "recipient_account": recipient_account,
                        "recent_blockhashes_account": recent_blockhashes_account,
                        "rent_account": rent_account,
                        "nonce_authority": nonce_authority,
                        "amount": amount,
                    },
                }))
            }
            SystemInstruction::TransferWithSeed {
                lamports, from_seed, from_owner
            } => {
                let method_name = "TransferWithSeed";
                let fund_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("TransferWithSeed.fund_account")))?;
                let from_base = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!("TransferWithSeed.from_base")))?;
                let recipient_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!("TransferWithSeed.recipient_account")))?;
                let amount = lamports.to_string();
                let from_owner = from_owner.to_string();
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "fund_account": fund_account,
                        "recipient_account": recipient_account,
                        "amount": amount,
                        "from_base": from_base,
                        "from_owner": from_owner,
                        "from_seed": from_seed,
                    },
                }))
            }
            SystemInstruction::UpgradeNonceAccount => {
                let method_name = "UpgradeNonceAccount";
                let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("UpgradeNonceAccount.nonce_account")))?;
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "nonce_account": nonce_account,
                    },
                }))
            }
            _ => {
                Err(SolanaError::UnknownInstruction)
            }
        }
    }

    fn parse_on_chain_program_instruction(accounts: Vec<String>, instruction_data: Vec<u8>) -> Result<String> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;

    #[test]
    fn test_system_transfer() {
        let transaction = Vec::from_hex("01000103876c762c4c83532f82966935ba1810659a96237028a2af6688dadecb0155ae071c7d0930a08193e702b0f24ebba96f179e9c186ef1208f98652ee775001744490000000000000000000000000000000000000000000000000000000000000000a7516fe1d3af3457fdc54e60856c0c3c87f4e5be3d10ffbc7a5cce8bf96792a101020200010c020000008813000000000000");
    }
}