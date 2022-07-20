use crate::error::SolanaError::ProgramError;
use crate::error::{Result, SolanaError};
use crate::types::compact::Compact;
use crate::Read;
use serde_json::{json, Value};
use solana_program;
use solana_program::bpf_loader_upgradeable::UpgradeableLoaderState::Program;
use solana_program::system_instruction::SystemInstruction;
use solana_sdk;
use solana_vote_program::vote_instruction::VoteInstruction;
use std::fmt::format;
use solana_vote_program::vote_state::VoteAuthorize;

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
    TokenProgram,
}

fn template_instruction(program_name: &str, method_name: &str, arguments: Value) -> Value {
    json!({
        "program_name": program_name,
        "method_name": method_name,
        "arguments": arguments
    })
}

impl SupportedProgram {
    pub fn from_program_id(program_id: String) -> Result<Self> {
        match program_id.as_str() {
            "11111111111111111111111111111111" => Ok(SupportedProgram::SystemProgram),
            "Vote111111111111111111111111111111111111111" => Ok(SupportedProgram::VoteProgram),
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" => Ok(SupportedProgram::TokenProgram),
            x => Err(SolanaError::UnsupportedProgram(x.to_string())),
        }
    }
}

impl Instruction {
    pub fn parse(&self, program_id: &String, accounts: Vec<String>) -> Result<Value> {
        let program = SupportedProgram::from_program_id(program_id.clone())?;
        let _accounts: Result<Vec<String>> = self
            .account_indexes
            .iter()
            .map(|v| {
                accounts
                    .get(usize::from(v.clone()))
                    .map(|v| v.clone())
                    .ok_or(SolanaError::InvalidData(format!("instruction data")))
            })
            .collect();
        match program {
            SupportedProgram::SystemProgram => {
                let instruction = Self::parse_native_program_instruction::<
                    solana_program::system_instruction::SystemInstruction,
                >(self.data.clone())?;
                Self::resolve_system_program_instruction(instruction, _accounts?)
            }
            SupportedProgram::VoteProgram => {
                let instruction = Self::parse_native_program_instruction::<
                    solana_vote_program::vote_instruction::VoteInstruction,
                >(self.data.clone())?;
                Self::resolve_vote_program_instruction(instruction, _accounts?)
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

    fn resolve_system_program_instruction(
        instruction: SystemInstruction,
        accounts: Vec<String>,
    ) -> Result<Value> {
        let program_name = "System";
        match instruction {
            SystemInstruction::CreateAccount {
                lamports,
                space,
                owner,
            } => {
                let method_name = "CreateAccount";
                let funder = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                    "CreateAccount.funder"
                )))?;
                let account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "CreateAccount.account"
                )))?;
                let amount = lamports.to_string();
                let space = space.to_string();
                let owner = owner.to_string();
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "funder": funder,
                        "account": account,
                        "amount": amount,
                        "space": space,
                        "owner": owner,
                    }),
                ))
            }
            SystemInstruction::Assign { owner } => {
                let method_name = "Assign";
                let account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("Allocate.account")))?;
                let new_owner = owner.to_string();
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "new_owner": new_owner,
                    }),
                ))
            }

            SystemInstruction::Transfer { lamports } => {
                let method_name = "Transfer";
                let from = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("Transfer.from")))?;
                let to = accounts
                    .get(1)
                    .ok_or(SolanaError::AccountNotFound(format!("Transfer.to")))?;
                let amount = lamports.to_string();
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "from": from,
                        "to": to,
                        "amount": amount
                    }),
                ))
            }
            SystemInstruction::CreateAccountWithSeed {
                base,
                seed,
                lamports,
                space,
                owner,
            } => {
                let method_name = "CreateAccountWithSeed";
                let funder = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                    "CreateAccountWithSeed.funder"
                )))?;
                let account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "CreateAccountWithSeed.account"
                )))?;
                let signer = accounts.get(2);
                let amount = lamports.to_string();
                let space = space.to_string();
                let owner = owner.to_string();
                let base = base.to_string();
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "funder": funder,
                        "account": account,
                        "signer": signer,
                        "base": signer,
                        "seed": seed,
                        "amount": amount,
                        "space": space,
                        "owner": owner,
                    }),
                ))
            }
            SystemInstruction::AdvanceNonceAccount {} => {
                let method_name = "AdvanceNonceAccount";
                let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                    format!("AdvanceNonceAccount.nonce_account"),
                ))?;
                let recent_blockhashes_sysvar =
                    accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                        "AdvanceNonceAccount.recent_blockhashes_sysvar"
                    )))?;
                let authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                    "AdvanceNonceAccount.authority"
                )))?;
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "nonce_account": nonce_account,
                        "recent_blockhashes_sysvar": recent_blockhashes_sysvar,
                        "authority": authority,
                    }),
                ))
            }
            SystemInstruction::WithdrawNonceAccount(lamports) => {
                let method_name = "WithdrawNonceAccount";
                let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                    format!("WithdrawNonceAccount.nonce_account"),
                ))?;
                let recipient_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                    format!("WithdrawNonceAccount.recipient_account"),
                ))?;
                let recent_blockhashes_sysvar =
                    accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                        "WithdrawNonceAccount.recent_blockhashes_sysvar"
                    )))?;
                let rent_sysvar = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                    "WithdrawNonceAccount.rent_sysvar"
                )))?;
                let nonce_authority = accounts.get(4).ok_or(SolanaError::AccountNotFound(
                    format!("WithdrawNonceAccount.nonce_authority"),
                ))?;
                let amount = lamports.to_string();
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "nonce_account": nonce_account,
                        "recipient_account": recipient_account,
                        "recent_blockhashes_sysvar": recent_blockhashes_sysvar,
                        "rent_sysvar": rent_sysvar,
                        "nonce_authority": nonce_authority,
                        "amount": amount,
                    }),
                ))
            }
            SystemInstruction::InitializeNonceAccount(pubkey) => {
                let method_name = "InitializeNonceAccount";
                let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                    format!("InitializeNonceAccount.nonce_account"),
                ))?;
                let recent_blockhashes_sysvar =
                    accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                        "InitializeNonceAccount.recent_blockhashes_sysvar"
                    )))?;
                let rent_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                    "InitializeNonceAccount.rent_sysvar"
                )))?;
                let authority = pubkey.to_string();
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "nonce_account": nonce_account,
                        "recent_blockhashes_sysvar": recent_blockhashes_sysvar,
                        "rent_sysvar": rent_sysvar,
                        "authority": authority,
                    }),
                ))
            }
            SystemInstruction::AuthorizeNonceAccount(pubkey) => {
                let method_name = "AuthorizeNonceAccount";
                let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                    format!("AuthorizeNonceAccount.nonce_account"),
                ))?;
                let nonce_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                    format!("AuthorizeNonceAccount.nonce_authority"),
                ))?;
                let new_authority = pubkey.to_string();
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "nonce_account": nonce_account,
                        "nonce_authority": nonce_authority,
                        "new_authority": new_authority,
                    }),
                ))
            }
            SystemInstruction::Allocate { space } => {
                let method_name = "Allocate";
                let account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("Allocate.account")))?;
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "space": space.to_string(),
                    }),
                ))
            }
            SystemInstruction::AllocateWithSeed {
                owner,
                base,
                seed,
                space,
            } => {
                let method_name = "AllocateWithSeed";
                let allocated_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                    format!("AllocateWithSeed.allocated_account"),
                ))?;
                let base_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "AllocateWithSeed.base_account"
                )))?;
                let owner = owner.to_string();
                let base = base.to_string();
                let space = space.to_string();
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "allocated_account": allocated_account,
                        "base_account": base_account,
                        "owner": owner,
                        "base": base,
                        "space": space
                    }),
                ))
            }
            SystemInstruction::AssignWithSeed { owner, seed, base } => {
                let method_name = "AssignWithSeed";
                let assigned_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                    format!("AssignWithSeed.assigned_account"),
                ))?;
                let base_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "AssignWithSeed.base_account"
                )))?;
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "assigned_account": assigned_account,
                        "base_account": base_account,
                        "seed": seed,
                        "base": base.to_string(),
                        "owner": owner.to_string(),
                    }),
                ))
            }
            SystemInstruction::TransferWithSeed {
                lamports,
                from_seed,
                from_owner,
            } => {
                let method_name = "TransferWithSeed";
                let fund_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                    "TransferWithSeed.fund_account"
                )))?;
                let from_base = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "TransferWithSeed.from_base"
                )))?;
                let recipient_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                    format!("TransferWithSeed.recipient_account"),
                ))?;
                let amount = lamports.to_string();
                let from_owner = from_owner.to_string();
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "fund_account": fund_account,
                        "recipient_account": recipient_account,
                        "amount": amount,
                        "from_base": from_base,
                        "from_owner": from_owner,
                        "from_seed": from_seed,
                    }),
                ))
            }
            SystemInstruction::UpgradeNonceAccount => {
                let method_name = "UpgradeNonceAccount";
                let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                    format!("UpgradeNonceAccount.nonce_account"),
                ))?;
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "nonce_account": nonce_account,
                    }),
                ))
            }
        }
    }

    fn resolve_vote_program_instruction(
        instruction: VoteInstruction,
        accounts: Vec<String>,
    ) -> Result<Value> {
        let program_name = "Vote";
        match instruction {
            VoteInstruction::InitializeAccount(vote_init) => {
                let account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("InitializeAccount.account")))?;
                let rent_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                    format!("InitializeAccount.rent_sysvar"),
                ))?;
                let clock_sysvar = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("InitializeAccount.clock_sysvar")))?;
                let new_validator_identity = accounts
                    .get(3)
                    .ok_or(SolanaError::AccountNotFound(format!("InitializeAccount.new_validator_identity")))?;
                let node_pubkey = vote_init.node_pubkey.to_string();
                let authorized_voter = vote_init.authorized_voter.to_string();
                let authorized_withdrawer = vote_init.authorized_withdrawer.to_string();
                let commission = vote_init.commission;
                Ok(template_instruction(
                    program_name,
                    "InitializeAccount",
                    json!({
                        "vote_account": vote_account,
                        "rent_sysvar": rent_sysvar,
                        "clock_sysvar": clock_sysvar,
                        "new_validator_identity": new_validator_identity,
                        "vote_init": {
                            "node_pubkey": node_pubkey,
                            "authorized_voter": authorized_voter,
                            "authorized_withdrawer": authorized_withdrawer,
                            "commission": commission,
                        }
                    }),
                ))
            }
            VoteInstruction::Authorize(pubkey, vote_authority) => {
                let vote_account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("Authorize.vote_account")))?;
                let clock_sysvar = accounts
                    .get(1)
                    .ok_or(SolanaError::AccountNotFound(format!("Authorize.clock_sysvar")))?;
                let authority = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("Authorize.vote_authority")))?;
                let authority_type = match vote_authority {
                    VoteAuthorize::Voter => "voter",
                    VoteAuthorize::Withdrawer => "withdrawer",
                };
                Ok(template_instruction(
                    program_name,
                    "Authorize",
                    json!({
                        "vote_account": vote_account,
                        "clock_sysvar": clock_sysvar,
                        "vote_authority": vote_authority,
                        "new_authorized_pubkey": pubkey.to_string(),
                        "authority_type": authority_type,
                    }),
                ))
            }
            VoteInstruction::Vote(vote) => {
                let vote_account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("Vote.vote_account")))?;
                let slot_hashes_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                    format!("Vote.slot_hashes_sysvar"),
                ))?;
                let clock_sysvar = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("Vote.clock_sysvar")))?;
                let vote_authority = accounts
                    .get(3)
                    .ok_or(SolanaError::AccountNotFound(format!("Vote.vote_authority")))?;
                let vote_slots = vote
                    .slots
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                let vote_hash = vote.hash.to_string();
                let timestamp = vote.timestamp.map(|v| v.to_string());
                Ok(template_instruction(
                    program_name,
                    "Vote",
                    json!({
                        "vote_account": vote_account,
                        "slot_hashes_sysvar": slot_hashes_sysvar,
                        "clock_sysvar": clock_sysvar,
                        "vote_authority": vote_authority,
                        "vote": {
                            "slots": vote_slots,
                            "hash": vote_hash,
                            "timestamp": timestamp,
                        }
                    }),
                ))
            }
            VoteInstruction::Withdraw(lamports) => {
                let vote_account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("Withdraw.vote_account")))?;
                let recipient_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                    format!("Withdraw.recipient_account"),
                ))?;
                let withdraw_authority = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("Withdraw.withdraw_authority")))?;
                let amount = lamports.to_string();
                Ok(template_instruction(
                    program_name,
                    "Withdraw",
                    json!({
                        "vote_account": vote_account,
                        "recipient_account": recipient_account,
                        "withdraw_authority": withdraw_authority,
                        "amount": amount,
                    }),
                ))
            }
            VoteInstruction::UpdateValidatorIdentity => {
                let vote_account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("UpdateValidatorIdentity.vote_account")))?;
                let new_validator_identity = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                    format!("UpdateValidatorIdentity.new_validator_identity"),
                ))?;
                let withdraw_authority = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("UpdateValidatorIdentity.withdraw_authority")))?;
                let amount = lamports.to_string();
                Ok(template_instruction(
                    program_name,
                    "UpdateValidatorIdentity",
                    json!({
                        "vote_account": vote_account,
                        "new_validator_identity": new_validator_identity,
                        "withdraw_authority": withdraw_authority,
                    }),
                ))
            }
            VoteInstruction::UpdateCommission(new_commission) => {
                let vote_account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("UpdateCommission.vote_account")))?;
                let withdraw_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                    format!("UpdateCommission.withdraw_authority"),
                ))?;
                Ok(template_instruction(
                    program_name,
                    "UpdateCommission",
                    json!({
                        "vote_account": vote_account,
                        "withdraw_authority": withdraw_authority,
                        "new_commission": new_commission,
                    }),
                ))
            }
            VoteInstruction::VoteSwitch(vote, proof_hash) => {
                let vote_account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("VoteSwitch.vote_account")))?;
                let slot_hashes_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                    format!("VoteSwitch.slot_hashes_sysvar"),
                ))?;
                let clock_sysvar = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("VoteSwitch.clock_sysvar")))?;
                let vote_authority = accounts
                    .get(3)
                    .ok_or(SolanaError::AccountNotFound(format!("VoteSwitch.vote_authority")))?;
                let vote_slots = vote
                    .slots
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                let vote_hash = vote.hash.to_string();
                let proof_hash = proof_hash.to_string();
                let timestamp = vote.timestamp.map(|v| v.to_string());
                Ok(template_instruction(
                    program_name,
                    "VoteSwitch",
                    json!({
                        "vote_account": vote_account,
                        "slot_hashes_sysvar": slot_hashes_sysvar,
                        "clock_sysvar": clock_sysvar,
                        "vote_authority": vote_authority,
                        "vote": {
                            "slots": vote_slots,
                            "hash": vote_hash,
                            "timestamp": timestamp,
                        }
                        "proof_hash": proof_hash,
                    }),
                ))
            }
            VoteInstruction::AuthorizeChecked(vote_authority) => {
                let vote_account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("AuthorizeChecked.vote_account")))?;
                let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                    format!("AuthorizeChecked.clock_sysvar"),
                ))?;
                let authority = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("AuthorizeChecked.authority")))?;
                let new_authority = accounts
                    .get(3)
                    .ok_or(SolanaError::AccountNotFound(format!("AuthorizeChecked.new_authority")))?;
                let authority_type = match vote_authority {
                    VoteAuthorize::Voter => "voter",
                    VoteAuthorize::Withdrawer => "withdrawer"
                };
                Ok(template_instruction(
                    program_name,
                    "AuthorizeChecked",
                    json!({
                        "vote_account": vote_account,
                        "clock_sysvar": clock_sysvar,
                        "authority": vote_authority,
                        "new_authority": new_authority,
                        "authority_type": authority_type,
                    }),
                ))
            }
            VoteInstruction::UpdateVoteState(state) => {
                let vote_account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("UpdateVoteState.vote_account")))?;
                let vote_authority = accounts
                    .get(1)
                    .ok_or(SolanaError::AccountNotFound(format!("UpdateVoteState.vote_authority")))?;
                let lockouts = state.lockouts.iter().map(|v| json!({
                    "confirmation_count": v.confirmation_count,
                    "slot": v.slot,
                })).collect::<Vec<Value>>();
                let root = state.root.map(|v| v.to_string());
                let hash = state.hash.to_string();
                let timestamp = state.timestamp.map(|v| v.to_string());
                Ok(template_instruction(
                    program_name,
                    "UpdateVoteState",
                    json!({
                        "vote_account": vote_account,
                        "vote_authority": vote_authority,
                        "new_authorized_pubkey": pubkey.to_string(),
                        "authority_type": authority_type,
                        "new_vote_state": {
                            "lockouts": lockouts,
                            "root": root,
                            "hash": hash,
                            "timestamp": timestamp,
                        }
                    }),
                ))
            }
            VoteInstruction::UpdateVoteStateSwitch(state, proof_hash) => {
                let vote_account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("UpdateVoteStateSwitch.vote_account")))?;
                let vote_authority = accounts
                    .get(1)
                    .ok_or(SolanaError::AccountNotFound(format!("UpdateVoteStateSwitch.vote_authority")))?;
                let lockouts = state.lockouts.iter().map(|v| json!({
                    "confirmation_count": v.confirmation_count,
                    "slot": v.slot,
                })).collect::<Vec<Value>>();
                let root = state.root.map(|v| v.to_string());
                let hash = state.hash.to_string();
                let timestamp = state.timestamp.map(|v| v.to_string());
                let proof_hash = proof_hash.to_string();
                Ok(template_instruction(
                    program_name,
                    "UpdateVoteStateSwitch",
                    json!({
                        "vote_account": vote_account,
                        "vote_authority": vote_authority,
                        "new_authorized_pubkey": pubkey.to_string(),
                        "authority_type": authority_type,
                        "new_vote_state": {
                            "lockouts": lockouts,
                            "root": root,
                            "hash": hash,
                            "timestamp": timestamp,
                        },
                        "proof_hash": proof_hash
                    }),
                ))
            }
            VoteInstruction::AuthorizeWithSeed(args) => {
                let vote_account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("AuthorizeWithSeed.vote_account")))?;
                let clock_sysvar = accounts
                    .get(1)
                    .ok_or(SolanaError::AccountNotFound(format!("AuthorizeWithSeed.clock_sysvar")))?;
                let base_key = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("AuthorizeWithSeed.base_key")))?;

                let authorization_type = match args.authorization_type {
                    VoteAuthorize::Voter => "voter",
                    VoteAuthorize::Withdrawer => "withdrawer"
                };
                let current_authority_derived_key_owner = args.current_authority_derived_key_owner.to_string();
                let current_authority_derived_key_seed = args.current_authority_derived_key_seed;
                let new_authority = args.new_authority.to_string();

                Ok(template_instruction(
                    program_name,
                    "AuthorizeWithSeed",
                    json!({
                        "vote_account": vote_account,
                        "clock_sysvar": clock_sysvar,
                        "base_key": base_key,
                        "authorize_arguments": {
                            "authorization_type": authorization_type,
                            "current_authority_derived_key_owner": current_authority_derived_key_owner,
                            "current_authority_derived_key_seed": current_authority_derived_key_seed,
                            "new_authority": new_authority,
                        },
                    }),
                ))
            }
            VoteInstruction::AuthorizeCheckedWithSeed(args) => {
                let vote_account = accounts
                    .get(0)
                    .ok_or(SolanaError::AccountNotFound(format!("AuthorizeCheckedWithSeed.vote_account")))?;
                let clock_sysvar = accounts
                    .get(1)
                    .ok_or(SolanaError::AccountNotFound(format!("AuthorizeCheckedWithSeed.clock_sysvar")))?;
                let base_key = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("AuthorizeCheckedWithSeed.base_key")))?;
                let new_authority = accounts
                    .get(3)
                    .ok_or(SolanaError::AccountNotFound(format!("AuthorizeCheckedWithSeed.new_authority")))?;

                let authorization_type = match args.authorization_type {
                    VoteAuthorize::Voter => "voter",
                    VoteAuthorize::Withdrawer => "withdrawer"
                };
                let current_authority_derived_key_owner = args.current_authority_derived_key_owner.to_string();
                let current_authority_derived_key_seed = args.current_authority_derived_key_seed;

                Ok(template_instruction(
                    program_name,
                    "AuthorizeCheckedWithSeed",
                    json!({
                        "vote_account": vote_account,
                        "clock_sysvar": clock_sysvar,
                        "base_key": base_key,
                        "new_authority": new_authority,
                        "authorize_arguments": {
                            "authorization_type": authorization_type,
                            "current_authority_derived_key_owner": current_authority_derived_key_owner,
                            "current_authority_derived_key_seed": current_authority_derived_key_seed,
                        },
                    }),
                ))
            }
        }
    }

    fn parse_on_chain_program_instruction(
        accounts: Vec<String>,
        instruction_data: Vec<u8>,
    ) -> Result<String> {
        unimplemented!()
    }
}
