use crate::error::{Result, SolanaError};
use crate::resolvers::template_instruction;
use serde_json::{json, Value};
use crate::solana_lib::solana_program::hash::Hash;
use crate::solana_lib::solana_program::pubkey::Pubkey;
use crate::solana_lib::solana_program::vote::instruction::VoteInstruction;
use crate::solana_lib::solana_program::vote::state::{Vote, VoteAuthorize, VoteAuthorizeCheckedWithSeedArgs, VoteAuthorizeWithSeedArgs, VoteInit, VoteStateUpdate};

static PROGRAM_NAME: &str = "Vote";

pub fn resolve(instruction: VoteInstruction, accounts: Vec<String>) -> Result<Value> {
    match instruction {
        VoteInstruction::InitializeAccount(vote_init) => {
            resolve_initialize_account(accounts, vote_init)
        }
        VoteInstruction::Authorize(pubkey, vote_authority) => {
            resolve_authorize(accounts, pubkey, vote_authority)
        }
        VoteInstruction::Vote(vote) => resolve_vote(accounts, vote),
        VoteInstruction::Withdraw(lamports) => resolve_withdraw(accounts, lamports),
        VoteInstruction::UpdateValidatorIdentity => resolve_update_validator_identity(accounts),
        VoteInstruction::UpdateCommission(new_commission) => {
            resolve_update_commission(accounts, new_commission)
        }
        VoteInstruction::VoteSwitch(vote, proof_hash) => {
            resolve_vote_switch(accounts, vote, proof_hash)
        }
        VoteInstruction::AuthorizeChecked(vote_authority) => {
            resolve_authorize_checked(accounts, vote_authority)
        }
        VoteInstruction::UpdateVoteState(state) => resolve_update_vote_state(accounts, state),
        VoteInstruction::UpdateVoteStateSwitch(state, proof_hash) => {
            resolve_update_vote_state_switch(accounts, state, proof_hash)
        }
        VoteInstruction::AuthorizeWithSeed(args) => resolve_authorize_with_seed(accounts, args),
        VoteInstruction::AuthorizeCheckedWithSeed(args) => {
            resolve_authorize_checked_with_seed(accounts, args)
        }
    }
}

fn resolve_initialize_account(accounts: Vec<String>, vote_init: VoteInit) -> Result<Value> {
    let method_name = "InitializeAccount";
    let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account",
        method_name
    )))?;
    let sysvar_rent = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_rent",
        method_name
    )))?;
    let sysvar_clock = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let new_validator_identity = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.new_validator_identity",
        method_name
    )))?;
    let node_pubkey = vote_init.node_pubkey.to_string();
    let authorized_voter = vote_init.authorized_voter.to_string();
    let authorized_withdrawer = vote_init.authorized_withdrawer.to_string();
    let commission = vote_init.commission;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": account,
            "sysvar_rent": sysvar_rent,
            "sysvar_clock": sysvar_clock,
            "new_validator_identity": new_validator_identity,
            "config": {
                "node_pubkey": node_pubkey,
                "authorized_voter": authorized_voter,
                "authorized_withdrawer": authorized_withdrawer,
                "commission": commission,
            }
        }),
        json!({
            "vote_account": account,
            "new_validator_identity": new_validator_identity,
            "config": {
                "node_pubkey": node_pubkey,
                "authorized_voter": authorized_voter,
                "authorized_withdrawer": authorized_withdrawer,
                "commission": commission,
            }
        })
    ))
}

fn resolve_authorize(
    accounts: Vec<String>,
    pubkey: Pubkey,
    vote_authority: VoteAuthorize,
) -> Result<Value> {
    let method_name = "Authorize";
    let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
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
    let authority_type = match vote_authority {
        VoteAuthorize::Voter => "voter",
        VoteAuthorize::Withdrawer => "withdrawer",
    };
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": vote_account,
            "sysvar_clock": sysvar_clock,
            "old_authority_pubkey": old_authority_pubkey,
            "new_authority_pubkey": pubkey.to_string(),
            "authority_type": authority_type,
        }),
        json!({
            "vote_account": vote_account,
            "old_authority_pubkey": old_authority_pubkey,
            "new_authority_pubkey": pubkey.to_string(),
            "authority_type": authority_type,
        })
    ))
}

fn resolve_vote(accounts: Vec<String>, vote: Vote) -> Result<Value> {
    let method_name = "Vote";

    let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
        method_name
    )))?;
    let sysvar_slot_hashes = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_slot_hashes",
        method_name
    )))?;
    let sysvar_clock = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let vote_authority_pubkey = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_authority_pubkey",
        method_name
    )))?;
    let vote_slots = vote
        .slots
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>()
        .join(",");
    let vote_hash = vote.hash.to_string();
    let timestamp = vote.timestamp.map(|v| v.to_string());
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": vote_account,
            "sysvar_slot_hashes": sysvar_slot_hashes,
            "sysvar_clock": sysvar_clock,
            "vote_authority_pubkey": vote_authority_pubkey,
            "vote": {
                "slots": vote_slots,
                "hash": vote_hash,
                "timestamp": timestamp,
            }
        }),
        json!({
            "vote_account": vote_account,
            "vote": {
                "slots": vote_slots,
                "hash": vote_hash,
                "timestamp": timestamp,
            }
        })
    ))
}

fn resolve_withdraw(accounts: Vec<String>, lamports: u64) -> Result<Value> {
    let method_name = "Withdraw";

    let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
        method_name
    )))?;
    let recipient = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.recipient",
        method_name
    )))?;
    let withdraw_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.withdraw_authority_pubkey",
        method_name
    )))?;
    let amount = lamports.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": vote_account,
            "recipient": recipient,
            "withdraw_authority_pubkey": withdraw_authority_pubkey,
            "amount": amount,
        }),
        json!({
            "vote_account": vote_account,
            "recipient": recipient,
            "amount": amount,
        })
    ))
}

fn resolve_update_validator_identity(accounts: Vec<String>) -> Result<Value> {
    let method_name = "UpdateValidatorIdentity";

    let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
        method_name
    )))?;
    let new_validator_identity = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.new_validator_identity",
        method_name
    )))?;
    let withdraw_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.withdraw_authority_pubkey",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": vote_account,
            "new_validator_identity": new_validator_identity,
            "withdraw_authority": withdraw_authority_pubkey,
        }),
        json!({
            "vote_account": vote_account,
            "new_validator_identity": new_validator_identity,
        })
    ))
}

fn resolve_update_commission(accounts: Vec<String>, new_commission: u8) -> Result<Value> {
    let method_name = "UpdateCommission";

    let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
        method_name
    )))?;
    let withdraw_authority_pubkey = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.withdraw_authority_pubkey",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": vote_account,
            "withdraw_authority_pubkey": withdraw_authority_pubkey,
            "new_commission": new_commission,
        }),
        json!({
            "vote_account": vote_account,
            "new_commission": new_commission,
        })
    ))
}

fn resolve_vote_switch(accounts: Vec<String>, vote: Vote, proof_hash: Hash) -> Result<Value> {
    let method_name = "VoteSwitch";

    let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
        method_name
    )))?;
    let sysvar_slot_hashes = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_slot_hashes",
        method_name
    )))?;
    let sysvar_clock = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let vote_authority_pubkey = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_authority_pubkey",
        method_name
    )))?;
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
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": vote_account,
            "sysvar_slot_hashes": sysvar_slot_hashes,
            "sysvar_clock": sysvar_clock,
            "vote_authority_pubkey": vote_authority_pubkey,
            "vote": {
                "slots": vote_slots,
                "hash": vote_hash,
                "timestamp": timestamp,
            },
            "proof_hash": proof_hash,
        }),
        json!({
            "vote_account": vote_account,
            "vote": {
                "slots": vote_slots,
                "hash": vote_hash,
                "timestamp": timestamp,
            },
            "proof_hash": proof_hash,
        })
    ))
}

fn resolve_authorize_checked(
    accounts: Vec<String>,
    vote_authority: VoteAuthorize,
) -> Result<Value> {
    let method_name = "AuthorizeChecked";

    let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
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
    let authority_type = match vote_authority {
        VoteAuthorize::Voter => "voter",
        VoteAuthorize::Withdrawer => "withdrawer",
    };
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": vote_account,
            "sysvar_clock": sysvar_clock,
            "old_authority_pubkey": old_authority_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
            "authority_type": authority_type,
        }),
        json!({
            "vote_account": vote_account,
            "old_authority_pubkey": old_authority_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
            "authority_type": authority_type,
        })
    ))
}

fn resolve_update_vote_state(accounts: Vec<String>, state: VoteStateUpdate) -> Result<Value> {
    let method_name = "UpdateVoteState";

    let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
        method_name
    )))?;
    let vote_authority_pubkey = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_authority_pubkey",
        method_name
    )))?;

    let lockouts = state
        .lockouts
        .iter()
        .map(|v| {
            json!({
                "confirmation_count": v.confirmation_count,
                "slot": v.slot,
            })
        })
        .collect::<Vec<Value>>();
    let root = state.root.map(|v| v.to_string());
    let hash = state.hash.to_string();
    let timestamp = state.timestamp.map(|v| v.to_string());
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": vote_account,
            "vote_authority_pubkey": vote_authority_pubkey,
            "new_state": {
                "lockouts": lockouts,
                "root": root,
                "hash": hash,
                "timestamp": timestamp,
            }
        }),
        json!({
            "vote_account": vote_account,
            "new_state": {
                "lockouts": lockouts,
                "root": root,
                "hash": hash,
                "timestamp": timestamp,
            }
        })
    ))
}

fn resolve_update_vote_state_switch(
    accounts: Vec<String>,
    state: VoteStateUpdate,
    proof_hash: Hash,
) -> Result<Value> {
    let method_name = "UpdateVoteStateSwitch";

    let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
        method_name
    )))?;
    let vote_authority_pubkey = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_authority_pubkey",
        method_name
    )))?;
    let lockouts = state
        .lockouts
        .iter()
        .map(|v| {
            json!({
                "confirmation_count": v.confirmation_count,
                "slot": v.slot,
            })
        })
        .collect::<Vec<Value>>();
    let root = state.root.map(|v| v.to_string());
    let hash = state.hash.to_string();
    let timestamp = state.timestamp.map(|v| v.to_string());
    let proof_hash = proof_hash.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": vote_account,
            "vote_authority_pubkey": vote_authority_pubkey,
            "new_state": {
                "lockouts": lockouts,
                "root": root,
                "hash": hash,
                "timestamp": timestamp,
            },
            "proof_hash": proof_hash
        }),
        json!({
            "vote_account": vote_account,
            "new_state": {
                "lockouts": lockouts,
                "root": root,
                "hash": hash,
                "timestamp": timestamp,
            },
            "proof_hash": proof_hash
        })
    ))
}

fn resolve_authorize_with_seed(
    accounts: Vec<String>,
    args: VoteAuthorizeWithSeedArgs,
) -> Result<Value> {
    let method_name = "AuthorizeWithSeed";

    let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
        method_name
    )))?;
    let sysvar_clock = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let old_base_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.old_base_pubkey",
        method_name
    )))?;

    let authorization_type = match args.authorization_type {
        VoteAuthorize::Voter => "voter",
        VoteAuthorize::Withdrawer => "withdrawer",
    };
    let current_authority_derived_key_owner = args.current_authority_derived_key_owner.to_string();
    let current_authority_derived_key_seed = args.current_authority_derived_key_seed;
    let new_authority_pubkey = args.new_authority.to_string();

    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": vote_account,
            "sysvar_clock": sysvar_clock,
            "old_base_pubkey": old_base_pubkey,
            "arguments": {
                "authorization_type": authorization_type,
                "current_authority_derived_key_owner": current_authority_derived_key_owner,
                "current_authority_derived_key_seed": current_authority_derived_key_seed,
                "new_authority_pubkey": new_authority_pubkey,
            },
        }),
        json!({
            "vote_account": vote_account,
            "old_base_pubkey": old_base_pubkey,
            "arguments": {
                "authorization_type": authorization_type,
                "current_authority_derived_key_seed": current_authority_derived_key_seed,
                "new_authority_pubkey": new_authority_pubkey,
            },
        })
    ))
}

fn resolve_authorize_checked_with_seed(
    accounts: Vec<String>,
    args: VoteAuthorizeCheckedWithSeedArgs,
) -> Result<Value> {
    let method_name = "AuthorizeCheckedWithSeed";

    let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.vote_account",
        method_name
    )))?;
    let sysvar_clock = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_clock",
        method_name
    )))?;
    let old_base_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.old_base_pubkey",
        method_name
    )))?;
    let new_authority_pubkey = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.new_authority_pubkey",
        method_name
    )))?;

    let authorization_type = match args.authorization_type {
        VoteAuthorize::Voter => "voter",
        VoteAuthorize::Withdrawer => "withdrawer",
    };
    let current_authority_derived_key_owner = args.current_authority_derived_key_owner.to_string();
    let current_authority_derived_key_seed = args.current_authority_derived_key_seed;

    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "vote_account": vote_account,
            "sysvar_clock": sysvar_clock,
            "old_base_pubkey": old_base_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
            "authorize_arguments": {
                "authorization_type": authorization_type,
                "current_authority_derived_key_owner": current_authority_derived_key_owner,
                "current_authority_derived_key_seed": current_authority_derived_key_seed,
            },
        }),
        json!({
            "vote_account": vote_account,
            "old_base_pubkey": old_base_pubkey,
            "new_authority_pubkey": new_authority_pubkey,
            "authorize_arguments": {
                "authorization_type": authorization_type,
                "current_authority_derived_key_seed": current_authority_derived_key_seed,
            },
        })
    ))
}
