use crate::error::{Result, SolanaError};
use crate::resolvers::template_instruction;
use serde_json::{json, Value};
use solana_program::stake::instruction::StakeInstruction;
use solana_program::stake::state::StakeAuthorize;

pub fn resolve(instruction: StakeInstruction, accounts: Vec<String>) -> Result<Value> {
    let program_name = "Stake";
    match instruction {
        StakeInstruction::Initialize(authorized, lockup) => {
            let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "Initialize.stake_account"
            )))?;
            let rent_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "Initialize.rent_sysvar"
            )))?;
            let staker = authorized.staker.to_string();
            let withdrawer = authorized.withdrawer.to_string();
            let unix_timestamp = lockup.unix_timestamp;
            let epoch = lockup.epoch;
            let custodian = lockup.custodian.to_string();
            Ok(template_instruction(
                program_name,
                "Initialize",
                json!({
                    "stake_account": stake_account,
                    "rent_sysvar": rent_sysvar,
                    "authorized": {
                        "staker": staker,
                        "withdrawer": withdrawer,
                    },
                    "lockup": {
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
            let authority = accounts
                .get(2)
                .ok_or(SolanaError::AccountNotFound(format!("Authorize.authority")))?;
            let new_authorized_pubkey = pubkey.to_string();
            let authorize_type = match stake_authorize {
                StakeAuthorize::Staker => "staker",
                StakeAuthorize::Withdrawer => "withdrawer",
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
            let stake_history_sysvar = accounts.get(3).ok_or(SolanaError::AccountNotFound(
                format!("DelegateStake.stake_history_sysvar"),
            ))?;
            let config_account = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
                "DelegateStake.config_account"
            )))?;
            let authority = accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
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
        StakeInstruction::Split(lamports) => {
            let stake_account = accounts
                .get(0)
                .ok_or(SolanaError::AccountNotFound(format!("Split.stake_account")))?;
            let target_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "Split.target_account"
            )))?;
            let stake_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "Split.stake_authority"
            )))?;
            let amount = lamports.to_string();
            Ok(template_instruction(
                program_name,
                "Split",
                json!({
                    "stake_account": stake_account,
                    "target_account": target_account,
                    "stake_authority": stake_authority,
                    "amount": amount,
                }),
            ))
        }
        StakeInstruction::Withdraw(lamports) => {
            let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "Withdraw.stake_account"
            )))?;
            let recipient_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                format!("Withdraw.target_account"),
            ))?;
            let clock_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "Withdraw.stake_authority"
            )))?;
            let stake_history_sysvar = accounts.get(3).ok_or(SolanaError::AccountNotFound(
                format!("Withdraw.stake_account"),
            ))?;
            let withdraw_authority = accounts.get(4).ok_or(SolanaError::AccountNotFound(
                format!("Withdraw.target_account"),
            ))?;
            let stake_authority = accounts.get(5);
            let amount = lamports.to_string();
            Ok(template_instruction(
                program_name,
                "Withdraw",
                json!({
                    "stake_account": stake_account,
                    "recipient_account": recipient_account,
                    "clock_sysvar": clock_sysvar,
                    "stake_history_sysvar": stake_history_sysvar,
                    "withdraw_authority": withdraw_authority,
                    "stake_authority": stake_authority,
                    "amount": amount,
                }),
            ))
        }
        StakeInstruction::Deactivate => {
            let delegated_stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("Deactivate.delegated_stake_account"),
            ))?;
            let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "Deactivate.clock_sysvar"
            )))?;
            let stake_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "Deactivate.stake_authority"
            )))?;
            Ok(template_instruction(
                program_name,
                "Deactivate",
                json!({
                    "delegated_stake_account": delegated_stake_account,
                    "clock_sysvar": clock_sysvar,
                    "stake_authority": stake_authority,
                }),
            ))
        }
        StakeInstruction::SetLockup(lockup) => {
            let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "SetLockup.stake_account"
            )))?;
            let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "SetLockup.clock_sysvar"
            )))?;
            let unix_timestamp = lockup.unix_timestamp;
            let epoch = lockup.epoch;
            let custodian = lockup.custodian.map(|v| v.to_string());
            Ok(template_instruction(
                program_name,
                "SetLockup",
                json!({
                    "stake_account": stake_account,
                    "clock_sysvar": clock_sysvar,
                    "lockup": {
                        "unix_timestamp": unix_timestamp,
                        "epoch": epoch,
                        "custodian": custodian,
                    }
                }),
            ))
        }
        StakeInstruction::Merge => {
            let destination_stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("Merge.destination_stake_account"),
            ))?;
            let source_stake_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                format!("Merge.source_stake_account"),
            ))?;
            let clock_sysvar = accounts
                .get(2)
                .ok_or(SolanaError::AccountNotFound(format!("Merge.clock_sysvar")))?;
            let stake_history_sysvar = accounts.get(3).ok_or(SolanaError::AccountNotFound(
                format!("Merge.stake_history_sysvar"),
            ))?;
            let stake_authority = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
                "Merge.stake_authority"
            )))?;
            Ok(template_instruction(
                program_name,
                "Merge",
                json!({
                    "destination_stake_account": destination_stake_account,
                    "source_stake_account": source_stake_account,
                    "clock_sysvar": clock_sysvar,
                    "stake_history_sysvar": stake_history_sysvar,
                    "stake_authority": stake_authority,
                }),
            ))
        }
        StakeInstruction::AuthorizeWithSeed(args) => {
            let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeWithSeed.destination_stake_account"
            )))?;
            let base_key = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeWithSeed.destination_stake_account"
            )))?;
            let clock_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeWithSeed.destination_stake_account"
            )))?;
            let lockup_authority = accounts.get(3);

            let new_authorized_pubkey = args.new_authorized_pubkey.to_string();
            let stake_authorize = match args.stake_authorize {
                StakeAuthorize::Staker => "staker",
                StakeAuthorize::Withdrawer => "withdrawer",
            };
            let authority_owner = args.authority_owner.to_string();
            Ok(template_instruction(
                program_name,
                "AuthorizeWithSeed",
                json!({
                    "stake_account": stake_account,
                    "base_key": base_key,
                    "clock_sysvar": clock_sysvar,
                    "lockup_authority": lockup_authority,
                    "authorize_args": {
                        "new_authorized_pubkey": new_authorized_pubkey,
                        "authorize_type": stake_authorize,
                        "authority_seed": args.authority_seed,
                        "authority_owner": authority_owner,
                    }
                }),
            ))
        }
        StakeInstruction::InitializeChecked => {
            let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let rent_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let stake_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let withdraw_authority = accounts.get(3).ok_or(SolanaError::AccountNotFound(
                format!("InitializeChecked.destination_stake_account"),
            ))?;
            Ok(template_instruction(
                program_name,
                "InitializeChecked",
                json!({
                    "stake_account": stake_account,
                    "rent_sysvar": rent_sysvar,
                    "stake_authority": stake_authority,
                    "withdraw_authority": withdraw_authority,
                }),
            ))
        }
        StakeInstruction::AuthorizeChecked(stake_authorize) => {
            let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let old_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let new_authority = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let lock_authority = accounts.get(4);
            let authority_type = match stake_authorize {
                StakeAuthorize::Staker => "staker",
                StakeAuthorize::Withdrawer => "withdrawer",
            };
            Ok(template_instruction(
                program_name,
                "InitializeChecked",
                json!({
                    "stake_account": stake_account,
                    "clock_sysvar": clock_sysvar,
                    "old_authority": old_authority,
                    "new_authority": new_authority,
                    "lock_authority": lock_authority,
                    "authority_type": authority_type
                }),
            ))
        }
        StakeInstruction::AuthorizeCheckedWithSeed(args) => {
            let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let old_base_key = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let clock_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let new_authority = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let lock_authority = accounts.get(4);
            let authority_type = match args.stake_authorize {
                StakeAuthorize::Staker => "staker",
                StakeAuthorize::Withdrawer => "withdrawer",
            };
            let authority_seed = args.authority_seed;
            let authority_owner = args.authority_owner.to_string();
            Ok(template_instruction(
                program_name,
                "InitializeChecked",
                json!({
                    "stake_account": stake_account,
                    "clock_sysvar": clock_sysvar,
                    "old_base_key": old_base_key,
                    "new_authority": new_authority,
                    "lock_authority": lock_authority,
                    "arguments": {
                        "authority_type": authority_type,
                        "authority_seed": authority_seed,
                        "authority_owner": authority_owner,
                    }
                }),
            ))
        }
        StakeInstruction::SetLockupChecked(args) => {
            let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeChecked.destination_stake_account"
            )))?;
            let new_lockup_authority = accounts.get(2);

            let unix_timestamp = args.unix_timestamp;
            let epoch = args.epoch;
            Ok(template_instruction(
                program_name,
                "InitializeChecked",
                json!({
                    "stake_account": stake_account,
                    "authority": authority,
                    "new_lockup_authority": new_lockup_authority,
                    "arguments": {
                        "unix_timestamp": unix_timestamp,
                        "epoch": epoch,
                    },
                }),
            ))
        }
        StakeInstruction::GetMinimumDelegation => Ok(template_instruction(
            program_name,
            "GetMinimumDelegation",
            json!({}),
        )),
        StakeInstruction::DeactivateDelinquent => Ok(template_instruction(
            program_name,
            "DeactivateDelinquent",
            json!({}),
        )),
    }
}
