use crate::error::{Result, SolanaError};
use crate::types::resolvers::template_instruction;
use serde_json::{json, Value};
use solana_vote_program::vote_instruction::VoteInstruction;
use solana_vote_program::vote_state::VoteAuthorize;

pub fn resolve(instruction: VoteInstruction, accounts: Vec<String>) -> Result<Value> {
    let program_name = "Vote";
    match instruction {
        VoteInstruction::InitializeAccount(vote_init) => {
            let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeAccount.account"
            )))?;
            let rent_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeAccount.rent_sysvar"
            )))?;
            let clock_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeAccount.clock_sysvar"
            )))?;
            let new_validator_identity = accounts.get(3).ok_or(SolanaError::AccountNotFound(
                format!("InitializeAccount.new_validator_identity"),
            ))?;
            let node_pubkey = vote_init.node_pubkey.to_string();
            let authorized_voter = vote_init.authorized_voter.to_string();
            let authorized_withdrawer = vote_init.authorized_withdrawer.to_string();
            let commission = vote_init.commission;
            Ok(template_instruction(
                program_name,
                "InitializeAccount",
                json!({
                    "vote_account": account,
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
            let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "Authorize.vote_account"
            )))?;
            let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "Authorize.clock_sysvar"
            )))?;
            let authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "Authorize.vote_authority"
            )))?;
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
            let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "Withdraw.vote_account"
            )))?;
            let recipient_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                format!("Withdraw.recipient_account"),
            ))?;
            let withdraw_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                format!("Withdraw.withdraw_authority"),
            ))?;
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
            let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "UpdateValidatorIdentity.vote_account"
            )))?;
            let new_validator_identity = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                format!("UpdateValidatorIdentity.new_validator_identity"),
            ))?;
            let withdraw_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                format!("UpdateValidatorIdentity.withdraw_authority"),
            ))?;
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
            let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "UpdateCommission.vote_account"
            )))?;
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
            let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "VoteSwitch.vote_account"
            )))?;
            let slot_hashes_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                format!("VoteSwitch.slot_hashes_sysvar"),
            ))?;
            let clock_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "VoteSwitch.clock_sysvar"
            )))?;
            let vote_authority = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "VoteSwitch.vote_authority"
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
                    },
                    "proof_hash": proof_hash,
                }),
            ))
        }
        VoteInstruction::AuthorizeChecked(vote_authority) => {
            let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeChecked.vote_account"
            )))?;
            let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeChecked.clock_sysvar"
            )))?;
            let authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeChecked.authority"
            )))?;
            let new_authority = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeChecked.new_authority"
            )))?;
            let authority_type = match vote_authority {
                VoteAuthorize::Voter => "voter",
                VoteAuthorize::Withdrawer => "withdrawer",
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
            let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "UpdateVoteState.vote_account"
            )))?;
            let vote_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "UpdateVoteState.vote_authority"
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
                program_name,
                "UpdateVoteState",
                json!({
                    "vote_account": vote_account,
                    "vote_authority": vote_authority,
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
            let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "UpdateVoteStateSwitch.vote_account"
            )))?;
            let vote_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "UpdateVoteStateSwitch.vote_authority"
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
                program_name,
                "UpdateVoteStateSwitch",
                json!({
                    "vote_account": vote_account,
                    "vote_authority": vote_authority,
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
            let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeWithSeed.vote_account"
            )))?;
            let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeWithSeed.clock_sysvar"
            )))?;
            let base_key = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeWithSeed.base_key"
            )))?;

            let authorization_type = match args.authorization_type {
                VoteAuthorize::Voter => "voter",
                VoteAuthorize::Withdrawer => "withdrawer",
            };
            let current_authority_derived_key_owner =
                args.current_authority_derived_key_owner.to_string();
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
            let vote_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeCheckedWithSeed.vote_account"
            )))?;
            let clock_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeCheckedWithSeed.clock_sysvar"
            )))?;
            let base_key = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeCheckedWithSeed.base_key"
            )))?;
            let new_authority = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "AuthorizeCheckedWithSeed.new_authority"
            )))?;

            let authorization_type = match args.authorization_type {
                VoteAuthorize::Voter => "voter",
                VoteAuthorize::Withdrawer => "withdrawer",
            };
            let current_authority_derived_key_owner =
                args.current_authority_derived_key_owner.to_string();
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
