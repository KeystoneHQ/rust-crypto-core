use crate::error::{Result, SolanaError};
use crate::resolvers::template_instruction;
use crate::solana_lib::solana_program::pubkey::Pubkey;
use crate::solana_lib::solana_program::stake::instruction::{
    AuthorizeCheckedWithSeedArgs, AuthorizeWithSeedArgs, LockupArgs, LockupCheckedArgs,
    StakeInstruction,
};
use crate::solana_lib::solana_program::stake::state::{Authorized, Lockup, StakeAuthorize};
use serde_json::{json, Value};

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
            json!({}),
        )),
        StakeInstruction::DeactivateDelinquent => Ok(template_instruction(
            PROGRAM_NAME,
            "DeactivateDelinquent",
            json!({}),
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
    let sysvar_rent = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_rent",
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
            "sysvar_rent": sysvar_rent,
            "staker": staker,
            "withdrawer": withdrawer,
            "timestamp": unix_timestamp,
            "epoch": epoch,
            "custodian": custodian
        }),
        json!({
            "stake_account": stake_account,
            "staker": staker,
            "withdrawer": withdrawer,
            "timestamp": unix_timestamp,
            "epoch": epoch,
            "custodian": custodian
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
    let sysvar_clock = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let old_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "Authorize.old_authority_pubkey"
    )))?;
    let lockup_authority_pubkey = accounts.get(3);
    let new_authority_pubkey = pubkey.to_string();
    let authorize_type = match stake_authorize {
        StakeAuthorize::Staker => "staker",
        StakeAuthorize::Withdrawer => "withdrawer",
    };
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "stake_account": stake_account,
            "sysvar_clock": sysvar_clock,
            "old_authority_pubkey": old_authority_pubkey,
            "lockup_authority_pubkey": lockup_authority_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
            "authorize_type": authorize_type,
        }),
        json!({
            "stake_account": stake_account,
            "old_authority_pubkey": old_authority_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
            "authorize_type": authorize_type,
        }),
    ))
}

fn resolve_delegate_stake(accounts: Vec<String>) -> Result<Value> {
    let method_name = "DelegateStake";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_account",
        method_name
    )))?;
    let vote_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
        method_name
    )))?;
    let sysvar_clock = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let sysvar_stake_history = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_stake_history",
        method_name
    )))?;
    let config_account = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
        "{}.config_account",
        method_name
    )))?;
    let stake_authority_pubkey = accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_authority_pubkey",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "stake_account": stake_account,
            "vote_account": vote_account,
            "sysvar_clock": sysvar_clock,
            "sysvar_stake_history": sysvar_stake_history,
            "config_account": config_account,
            "stake_authority_pubkey": stake_authority_pubkey,
        }),
        json!({
            "stake_account": stake_account,
            "vote_account": vote_account,
            "config_account": config_account,
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
    let stake_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_authority_pubkey",
        method_name
    )))?;
    let amount = lamports.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "stake_account": stake_account,
            "target_account": target_account,
            "stake_authority_pubkey": stake_authority_pubkey,
            "amount": amount,
        }),
        json!({
            "stake_account": stake_account,
            "target_account": target_account,
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
    let recipient = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.recipient",
        method_name
    )))?;
    let sysvar_clock = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let sysvar_stake_history = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_stake_history",
        method_name
    )))?;
    let withdraw_authority_pubkey = accounts.get(4).ok_or(SolanaError::AccountNotFound(
        format!("{}.withdraw_authority_pubkey", method_name),
    ))?;
    let stake_authority_pubkey = accounts.get(5);
    let amount = lamports.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "stake_account": stake_account,
            "recipient": recipient,
            "sysvar_clock": sysvar_clock,
            "sysvar_stake_history": sysvar_stake_history,
            "withdraw_authority_pubkey": withdraw_authority_pubkey,
            "stake_authority_pubkey": stake_authority_pubkey,
            "amount": amount,
        }),
        json!({
            "stake_account": stake_account,
            "recipient": recipient,
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
    let sysvar_clock = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let stake_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_authority_pubkey",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "delegated_stake_account": delegated_stake_account,
            "sysvar_clock": sysvar_clock,
            "stake_authority_pubkey": stake_authority_pubkey,
        }),
        json!({
            "delegated_stake_account": delegated_stake_account,
        }),
    ))
}

fn resolve_set_lockup(accounts: Vec<String>, lockup: LockupArgs) -> Result<Value> {
    let method_name = "SetLockup";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_account",
        method_name
    )))?;
    let lockup_authority_pubkey = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.lockup_authority_pubkey",
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
            "lockup_authority_pubkey": lockup_authority_pubkey,
            "unix_timestamp": unix_timestamp,
            "epoch": epoch,
            "custodian": custodian,
        }),
        json!({
            "stake_account": stake_account,
            "unix_timestamp": unix_timestamp,
            "epoch": epoch,
            "custodian": custodian,
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
    let sysvar_clock = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let sysvar_stake_history = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_stake_history",
        method_name
    )))?;
    let stake_authority_pubkey = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_authority_pubkey",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "destination_stake_account": destination_stake_account,
            "source_stake_account": source_stake_account,
            "sysvar_clock": sysvar_clock,
            "sysvar_stake_history": sysvar_stake_history,
            "stake_authority_pubkey": stake_authority_pubkey,
        }),
        json!({
            "destination_stake_account": destination_stake_account,
            "source_stake_account": source_stake_account,
        }),
    ))
}

fn resolve_authorize_with_seed(
    accounts: Vec<String>,
    args: AuthorizeWithSeedArgs,
) -> Result<Value> {
    let method_name = "AuthorizeWithSeed";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_account",
        method_name
    )))?;
    let old_base_pubkey = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.old_base_pubkey",
        method_name
    )))?;
    let sysvar_clock = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let lockup_authority_pubkey = accounts.get(3);

    let new_authority_pubkey = args.new_authorized_pubkey.to_string();
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
            "old_base_pubkey": old_base_pubkey,
            "sysvar_clock": sysvar_clock,
            "lockup_authority_pubkey": lockup_authority_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
            "authorize_type": stake_authorize,
            "authority_seed": args.authority_seed,
            "authority_owner": authority_owner,
        }),
        json!({
            "stake_account": stake_account,
            "old_base_pubkey": old_base_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
            "authorize_type": stake_authorize,
            "authority_seed": args.authority_seed,
        }),
    ))
}

fn resolve_initialize_checked(accounts: Vec<String>) -> Result<Value> {
    let method_name = "InitializeChecked";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_account",
        method_name
    )))?;
    let sysvar_rent = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_rent",
        method_name
    )))?;
    let stake_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_authority_pubkey",
        method_name
    )))?;
    let withdraw_authority_pubkey = accounts.get(3).ok_or(SolanaError::AccountNotFound(
        format!("{}.withdraw_authority_pubkey", method_name),
    ))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "stake_account": stake_account,
            "sysvar_rent": sysvar_rent,
            "stake_authority_pubkey": stake_authority_pubkey,
            "withdraw_authority_pubkey": withdraw_authority_pubkey,
        }),
        json!({
            "stake_account": stake_account,
            "stake_authority_pubkey": stake_authority_pubkey,
            "withdraw_authority_pubkey": withdraw_authority_pubkey,
        }),
    ))
}

fn resolve_authorize_checked(
    accounts: Vec<String>,
    stake_authorize: StakeAuthorize,
) -> Result<Value> {
    let method_name = "AuthorizeChecked";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_account",
        method_name
    )))?;
    let sysvar_clock = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let old_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.old_authority_pubkey",
        method_name
    )))?;
    let new_authority_pubkey = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.new_authority_pubkey",
        method_name
    )))?;
    let lockup_authority_pubkey = accounts.get(4);
    let authority_type = match stake_authorize {
        StakeAuthorize::Staker => "staker",
        StakeAuthorize::Withdrawer => "withdrawer",
    };
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "stake_account": stake_account,
            "sysvar_clock": sysvar_clock,
            "old_authority_pubkey": old_authority_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
            "lockup_authority_pubkey": lockup_authority_pubkey,
            "authority_type": authority_type
        }),
        json!({
            "stake_account": stake_account,
            "old_authority_pubkey": old_authority_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
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
        "{}.stake_account",
        method_name
    )))?;
    let old_base_pubkey = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.old_base_pubkey",
        method_name
    )))?;
    let sysvar_clock = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let new_authority_pubkey = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.new_authority_pubkey",
        method_name
    )))?;
    let lockup_authority = accounts.get(4);
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
            "sysvar_clock": sysvar_clock,
            "old_base_pubkey": old_base_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
            "lockup_authority": lockup_authority,
            "authority_type": authority_type,
            "authority_seed": authority_seed,
            "authority_owner": authority_owner,
        }),
        json!({
            "stake_account": stake_account,
            "old_base_pubkey": old_base_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
            "authority_type": authority_type,
            "authority_seed": authority_seed,
        }),
    ))
}

fn resolve_set_lockup_checked(accounts: Vec<String>, args: LockupCheckedArgs) -> Result<Value> {
    let method_name = "SetLockupChecked";
    let stake_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.stake_account",
        method_name
    )))?;
    let lockup_authority_pubkey = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.authority_pubkey",
        method_name
    )))?;
    let new_lockup_authority_pubkey = accounts.get(2);

    let unix_timestamp = args.unix_timestamp;
    let epoch = args.epoch;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "stake_account": stake_account,
            "lockup_authority_pubkey": lockup_authority_pubkey,
            "new_lockup_authority_pubkey": new_lockup_authority_pubkey,
            "timestamp": unix_timestamp,
            "epoch": epoch,
        }),
        json!({
            "stake_account": stake_account,
            "lockup_authority_pubkey": lockup_authority_pubkey,
            "new_lockup_authority_pubkey": new_lockup_authority_pubkey,
            "timestamp": unix_timestamp,
            "epoch": epoch,
        }),
    ))
}
