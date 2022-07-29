use crate::error::{Result, SolanaError};
use crate::resolvers::template_instruction;
use serde_json::{json, Value};
use solana_program::pubkey::Pubkey;
use solana_program::stake::instruction::{
    AuthorizeCheckedWithSeedArgs, AuthorizeWithSeedArgs, LockupArgs, LockupCheckedArgs,
    StakeInstruction,
};
use solana_program::stake::state::{Authorized, Lockup, StakeAuthorize};

static PROGRAM_NAME: &str = "Stake";

pub fn resolve(instruction: StakeInstruction, accounts: Vec<String>) -> Result<Value> {
    match instruction {
        StakeInstruction::Initialize(authorized, lockup) => {
            resolve_initialize(accounts, authorized, lockup)
        }
        StakeInstruction::Authorize(pubkey, stake_authorize) => {
            resolve_authorize(accounts, pubkey, stake_authorize)
        }
        StakeInstruction::DelegateStake => resolve_delegate_stake(accounts),
        StakeInstruction::Split(lamports) => resolve_split(accounts, lamports),
        StakeInstruction::Withdraw(lamports) => resolve_withdraw(accounts, lamports),
        StakeInstruction::Deactivate => resolve_deactivate(accounts),
        StakeInstruction::SetLockup(lockup) => resolve_set_lockup(accounts, lockup),
        StakeInstruction::Merge => resolve_merge(accounts),
        StakeInstruction::AuthorizeWithSeed(args) => resolve_authorize_with_seed(accounts, args),
        StakeInstruction::InitializeChecked => resolve_initialize_checked(accounts),
        StakeInstruction::AuthorizeChecked(stake_authorize) => {
            resolve_authorize_checked(accounts, stake_authorize)
        }
        StakeInstruction::AuthorizeCheckedWithSeed(args) => {
            resolve_authorize_checked_with_seed(accounts, args)
        }
        StakeInstruction::SetLockupChecked(args) => resolve_set_lockup_checked(accounts, args),
        StakeInstruction::GetMinimumDelegation => Ok(template_instruction(
            PROGRAM_NAME,
            "GetMinimumDelegation",
            json!({}),
        )),
        StakeInstruction::DeactivateDelinquent => Ok(template_instruction(
            PROGRAM_NAME,
            "DeactivateDelinquent",
            json!({}),
        )),
    }
}

fn resolve_initialize(
    accounts: Vec<String>,
    authorized: Authorized,
    lockup: Lockup,
) -> Result<Value> {
    let method_name = "Initialize";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_account",
        method_name
    )))?;
    let rent_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.rent_sysvar",
        method_name
    )))?;
    let staker = authorized.staker.to_string();
    let withdrawer = authorized.withdrawer.to_string();
    let unix_timestamp = lockup.unix_timestamp;
    let epoch = lockup.epoch;
    let custodian = lockup.custodian.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
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
fn resolve_authorize(
    accounts: Vec<String>,
    pubkey: Pubkey,
    stake_authorize: StakeAuthorize,
) -> Result<Value> {
    let method_name = "Authorize";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_account",
        method_name
    )))?;
    let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.clock_sysvar",
        method_name
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
        PROGRAM_NAME,
        method_name,
        json!({
            "stake_account": stake_account,
            "clock_sysvar": clock_sysvar,
            "authority": authority,
            "new_authorized_pubkey": new_authorized_pubkey,
            "authorize_type": authorize_type,
        }),
    ))
}
fn resolve_delegate_stake(accounts: Vec<String>) -> Result<Value> {
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "DelegateStake.stake_account"
    )))?;
    let vote_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "DelegateStake.vote_account"
    )))?;
    let clock_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "DelegateStake.clock_sysvar"
    )))?;
    let stake_history_sysvar = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "DelegateStake.stake_history_sysvar"
    )))?;
    let config_account = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
        "DelegateStake.config_account"
    )))?;
    let authority = accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
        "DelegateStake.authority"
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
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
fn resolve_split(accounts: Vec<String>, lamports: u64) -> Result<Value> {
    let method_name = "Split";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_account",
        method_name
    )))?;
    let target_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.target_account",
        method_name
    )))?;
    let stake_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_authority",
        method_name
    )))?;
    let amount = lamports.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "stake_account": stake_account,
            "target_account": target_account,
            "stake_authority": stake_authority,
            "amount": amount,
        }),
    ))
}
fn resolve_withdraw(accounts: Vec<String>, lamports: u64) -> Result<Value> {
    let method_name = "Withdraw";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_account",
        method_name
    )))?;
    let recipient_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.recipient_account",
        method_name
    )))?;
    let clock_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.clock_sysvar",
        method_name
    )))?;
    let stake_history_sysvar = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_history_sysvar",
        method_name
    )))?;
    let withdraw_authority = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
        "{}.withdraw_authority",
        method_name
    )))?;
    let stake_authority = accounts.get(5);
    let amount = lamports.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
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
fn resolve_deactivate(accounts: Vec<String>) -> Result<Value> {
    let method_name = "Deactivate";
    let delegated_stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.delegated_stake_account",
        method_name
    )))?;
    let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.clock_sysvar",
        method_name
    )))?;
    let stake_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_authority",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "delegated_stake_account": delegated_stake_account,
            "clock_sysvar": clock_sysvar,
            "stake_authority": stake_authority,
        }),
    ))
}
fn resolve_set_lockup(accounts: Vec<String>, lockup: LockupArgs) -> Result<Value> {
    let method_name = "SetLockup";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_account",
        method_name
    )))?;
    let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.clock_sysvar",
        method_name
    )))?;
    let unix_timestamp = lockup.unix_timestamp;
    let epoch = lockup.epoch;
    let custodian = lockup.custodian.map(|v| v.to_string());
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
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
fn resolve_merge(accounts: Vec<String>) -> Result<Value> {
    let method_name = "Merge";
    let destination_stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
        format!("{}.destination_stake_account", method_name),
    ))?;
    let source_stake_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.source_stake_account",
        method_name
    )))?;
    let clock_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.clock_sysvar",
        method_name
    )))?;
    let stake_history_sysvar = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_history_sysvar",
        method_name
    )))?;
    let stake_authority = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_authority",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "destination_stake_account": destination_stake_account,
            "source_stake_account": source_stake_account,
            "clock_sysvar": clock_sysvar,
            "stake_history_sysvar": stake_history_sysvar,
            "stake_authority": stake_authority,
        }),
    ))
}
fn resolve_authorize_with_seed(
    accounts: Vec<String>,
    args: AuthorizeWithSeedArgs,
) -> Result<Value> {
    let method_name = "AuthorizeWithSeed";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let base_key = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let clock_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let lockup_authority = accounts.get(3);

    let new_authorized_pubkey = args.new_authorized_pubkey.to_string();
    let stake_authorize = match args.stake_authorize {
        StakeAuthorize::Staker => "staker",
        StakeAuthorize::Withdrawer => "withdrawer",
    };
    let authority_owner = args.authority_owner.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
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
fn resolve_initialize_checked(accounts: Vec<String>) -> Result<Value> {
    let method_name = "InitializeChecked";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let rent_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let stake_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let withdraw_authority = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "stake_account": stake_account,
            "rent_sysvar": rent_sysvar,
            "stake_authority": stake_authority,
            "withdraw_authority": withdraw_authority,
        }),
    ))
}
fn resolve_authorize_checked(
    accounts: Vec<String>,
    stake_authorize: StakeAuthorize,
) -> Result<Value> {
    let method_name = "AuthorizeChecked";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let old_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let new_authority = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let lock_authority = accounts.get(4);
    let authority_type = match stake_authorize {
        StakeAuthorize::Staker => "staker",
        StakeAuthorize::Withdrawer => "withdrawer",
    };
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
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
fn resolve_authorize_checked_with_seed(
    accounts: Vec<String>,
    args: AuthorizeCheckedWithSeedArgs,
) -> Result<Value> {
    let method_name = "AuthorizeCheckedWithSeed";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let old_base_key = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let clock_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let new_authority = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let lock_authority = accounts.get(4);
    let authority_type = match args.stake_authorize {
        StakeAuthorize::Staker => "staker",
        StakeAuthorize::Withdrawer => "withdrawer",
    };
    let authority_seed = args.authority_seed;
    let authority_owner = args.authority_owner.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
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
fn resolve_set_lockup_checked(accounts: Vec<String>, args: LockupCheckedArgs) -> Result<Value> {
    let method_name = "SetLockupChecked";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_stake_account",
        method_name
    )))?;
    let new_lockup_authority = accounts.get(2);

    let unix_timestamp = args.unix_timestamp;
    let epoch = args.epoch;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
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
