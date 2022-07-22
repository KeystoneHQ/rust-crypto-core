use crate::error::SolanaError::ProgramError;
use crate::error::{Result, SolanaError};
use crate::types::compact::Compact;
use crate::Read;
use serde_json::{json, Value};
use solana_program;
use solana_program::stake::instruction::StakeInstruction;
use solana_sdk;
use solana_vote_program::vote_instruction::VoteInstruction;
use std::fmt::format;
use solana_program::system_instruction::SystemInstruction;
use solana_vote_program::vote_state::VoteAuthorize;
use crate::types::resolvers;

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
    VoteProgram,
    StakeProgram,
    TokenProgram,
}

impl SupportedProgram {
    pub fn from_program_id(program_id: String) -> Result<Self> {
        match program_id.as_str() {
            "11111111111111111111111111111111" => Ok(SupportedProgram::SystemProgram),
            "Vote111111111111111111111111111111111111111" => Ok(SupportedProgram::VoteProgram),
            "Stake11111111111111111111111111111111111111" => Ok(SupportedProgram::StakeProgram),
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" => Ok(SupportedProgram::TokenProgram),
            x => Err(SolanaError::UnsupportedProgram(x.to_string())),
        }
    }
}

impl Instruction {
    pub fn parse(&self, program_id: &String, accounts: Vec<String>) -> Result<Value> {
        let program = SupportedProgram::from_program_id(program_id.clone())?;
        match program {
            SupportedProgram::SystemProgram => {
                let instruction = Self::parse_native_program_instruction::<
                    SystemInstruction,
                >(self.data.clone())?;
                resolvers::system::resolve(instruction, accounts)
            }
            SupportedProgram::VoteProgram => {
                let instruction = Self::parse_native_program_instruction::<
                    VoteInstruction,
                >(self.data.clone())?;
                resolvers::vote::resolve(instruction, accounts)
            }
            SupportedProgram::StakeProgram => {
                let instruction = Self::parse_native_program_instruction::<
                    StakeInstruction,
                >(self.data.clone())?;
                resolvers::stake::resolve(instruction, accounts)
            }
            SupportedProgram::TokenProgram => {
                unimplemented!()
                // Self::parse_on_chain_program_instruction(_accounts, self.data.clone())
            }
        }
    }

    fn parse_native_program_instruction<T: for<'de> serde::de::Deserialize<'de>>(
        instruction_data: Vec<u8>,
    ) -> Result<T> {
        solana_sdk::program_utils::limited_deserialize::<T>(instruction_data.as_slice())
            .map_err(|e| ProgramError(e.to_string()))
    }

    fn parse_on_chain_program_instruction(
        accounts: Vec<String>,
        instruction_data: Vec<u8>,
    ) -> Result<String> {
        unimplemented!()
    }
}
