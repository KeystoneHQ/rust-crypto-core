use solana_program::stake::instruction::StakeInstruction;
use crate::error::{Result, SolanaError};
use serde_json::{json, Value};
use solana_program::stake::state::StakeAuthorize;
use crate::types::resolvers::template_instruction;

pub fn resolve(instruction: StakeInstruction,
               accounts: Vec<String>, ) -> Result<Value> {
    let program_name = "Stake";
    match instruction {
        StakeInstruction::Initialize(authorized, lookup) => {
            let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "Initialize.stake_account"
            )))?;
            let rent_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "Initialize.rent_sysvar"
            )))?;
            let staker = authorized.staker.to_string();
            let withdrawer = authorized.withdrawer.to_string();
            let unix_timestamp = lookup.unix_timestamp;
            let epoch = lookup.epoch;
            let custodian = lookup.custodian.to_string();
            Ok(template_instruction(
                program_name,
                "Initialize",
                json!({
                    "stake_account": funder,
                    "rent_sysvar": account,
                    "authorized": {
                        "staker": staker,
                        "withdrawer": withdrawer,
                    },
                    "lookup": {
                        "timestamp": unix_timestamp,
                        "epoch": epoch,
                        "custodian": custodian
                    }
                }),
            ))
        }
        StakeInstruction::Authorize(pubkey, stake_authorize) => {
            let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "Authorize.stake_account"
            )))?;
            let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "Authorize.clock_sysvar"
            )))?;
            let authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "Authorize.authority"
            )))?;
            let new_authorized_pubkey = pubkey.to_string();
            let authorize_type = match stake_authorize {
                StakeAuthorize::Staker => "staker",
                StakeAuthorize::Withdrawer => "withdrawer"
            };
            Ok(template_instruction(
                program_name,
                "Authorize",
                json!({
                    "stake_account": stake_account,
                    "clock_sysvar": clock_sysvar,
                    "authority": authority,
                    "new_authorized_pubkey": new_authorized_pubkey,
                    "authorize_type": authorize_type,
                }),
            ))
        }
        StakeInstruction::DelegateStake => {
            let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "DelegateStake.stake_account"
            )))?;
            let vote_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "DelegateStake.vote_account"
            )))?;
            let clock_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "DelegateStake.clock_sysvar"
            )))?;
            let stake_history_sysvar = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "DelegateStake.stake_history_sysvar"
            )))?;
            let config_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "DelegateStake.config_account"
            )))?;
            let authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "DelegateStake.authority"
            )))?;
            Ok(template_instruction(
                program_name,
                "DelegateStake",
                json!({
                    "stake_account": stake_account,
                    "vote_account": vote_account,
                    "clock_sysvar": clock_sysvar,
                    "stake_history_sysvar": stake_history_sysvar,
                    "config_account": config_account,
                    "authority": authority,
                }),
            ))
        }
        _ => Err(SolanaError::UnknownInstruction)
    }
}
