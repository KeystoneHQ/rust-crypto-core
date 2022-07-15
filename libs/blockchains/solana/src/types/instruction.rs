use std::fmt::format;
use serde_json::json;
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
    pub fn parse(&self, accounts: Vec<String>) -> Result<String> {
        let program_id = accounts.get(usize::from(self.program_index))
            .ok_or(SolanaError::InvalidData(format!("program id")))?;
        let program = SupportedProgram::from_program_id(program_id.clone())?;
        let _accounts: Result<Vec<String>> = self.account_indexes.iter()
            .map(|v|
                accounts.get(usize::from(v.clone())).map(|v| v.clone())
                    .ok_or(SolanaError::InvalidData(format!("instruction data")))
            ).collect();
        match program {
            SupportedProgram::SystemProgram => {
                let _accounts: Vec<String> = Vec::new();
                let instruction = Self::parse_native_program_instruction::<solana_program::system_instruction::SystemInstruction>
                    (self.data.clone())?;
                Self::resolve_system_program_instruction(instruction, _accounts)
            }
            SupportedProgram::TokenProgram => {
                let _accounts: Vec<String> = Vec::new();
                Self::parse_on_chain_program_instruction(_accounts, self.data.clone())
            }
        }
    }

    fn parse_native_program_instruction<T: for<'de> serde::de::Deserialize<'de>>(instruction_data: Vec<u8>) -> Result<T> {
        solana_sdk::program_utils::limited_deserialize::<T>(instruction_data.as_slice())
            .map_err(|e| ProgramError(e.to_string()))
    }

    fn resolve_system_program_instruction(instruction: SystemInstruction, accounts: Vec<String>) -> Result<String> {
        match instruction {
            SystemInstruction::Transfer {
                lamports
            } => {
                let program_name = "System";
                let method_name = "Transfer";
                let from = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!("transfer.from")))?;
                let to = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!("transfer.to")))?;
                let amount = lamports.to_string();
                Ok(json!({
                    "program_name": program_name,
                    "method_name": method_name,
                    "arguments": {
                        "from": from,
                        "to": to,
                        "amount": amount
                    },
                }).to_string())
            }
            _ => {
                unimplemented!()
            }
        }
    }

    fn parse_on_chain_program_instruction(accounts: Vec<String>, instruction_data: Vec<u8>) -> Result<String> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test() {}
}