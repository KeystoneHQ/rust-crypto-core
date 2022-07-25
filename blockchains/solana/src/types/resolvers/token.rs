use crate::error::{Result, SolanaError};
use crate::types::resolvers::template_instruction;
use serde_json::{json, Value};
use solana_program::program_option::COption;
use spl_token::instruction::{AuthorityType, TokenInstruction};

fn map_coption_to_option<T>(value: COption<T>) -> Option<T> {
    match value {
        COption::Some(t) => Some(t),
        COption::None => None,
    }
}

fn is_multisig(accounts: &Vec<String>, point: u8) -> bool {
    (accounts.len() as u8) > point
}

pub fn resolve(instruction: TokenInstruction, accounts: Vec<String>) -> Result<Value> {
    let program_name = "Token";
    match instruction {
        TokenInstruction::InitializeMint {
            mint_authority,
            decimals,
            freeze_authority,
        } => {
            let mint = accounts
                .get(0)
                .ok_or(SolanaError::AccountNotFound(format!("InitializeMint.mint")))?;
            let rent_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeMint.rent_sysvar"
            )))?;
            let mint_authority = mint_authority.to_string();
            let freeze_authority = map_coption_to_option(freeze_authority.map(|v| v.to_string()));
            Ok(template_instruction(
                program_name,
                "InitializeMint",
                json!({
                    "mint": mint,
                    "rent_sysvar": rent_sysvar,
                    "mint_authority": mint_authority,
                    "freeze_authority": freeze_authority,
                    "decimals": decimals,
                }),
            ))
        }
        TokenInstruction::InitializeAccount => {
            let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeAccount.mint"
            )))?;
            let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeAccount.account"
            )))?;
            let owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeAccount.owner"
            )))?;
            let rent_sysvar = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeAccount.rent_sysvar"
            )))?;
            Ok(template_instruction(
                program_name,
                "InitializeAccount",
                json!({
                    "account": account,
                    "mint": mint,
                    "owner": owner,
                    "rent_sysvar": rent_sysvar,
                }),
            ))
        }
        TokenInstruction::InitializeMultisig { m } => {
            let multisig_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeMultisig.multisig_account"
            )))?;
            let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeMultisig.account"
            )))?;
            let attendees = &accounts[2..];
            let required_signatures = m;
            Ok(template_instruction(
                program_name,
                "InitializeMultisig",
                json!({
                    "multisig_account": multisig_account,
                    "mint": mint,
                    "attendees": attendees,
                    "required_signatures": required_signatures,
                }),
            ))
        }
        TokenInstruction::Transfer { amount } => {
            let source_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "Transfer.source_account"
            )))?;
            let destination_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                format!("Transfer.destination_account"),
            ))?;
            if is_multisig(&accounts, 3) {
                let multisig_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                    format!("Transfer.multisig_account"),
                ))?;
                let signers = &accounts[3..];
                return Ok(template_instruction(
                    program_name,
                    "Transfer",
                    json!({
                        "source_account": source_account,
                        "destination_account": destination_account,
                        "multisig_account": multisig_account,
                        "signers": signers,
                        "amount": amount,
                    }),
                ));
            }
            let owner = accounts
                .get(2)
                .ok_or(SolanaError::AccountNotFound(format!("Transfer.owner")))?;
            return Ok(template_instruction(
                program_name,
                "Transfer",
                json!({
                    "source_account": source_account,
                    "destination_account": destination_account,
                    "owner": owner,
                    "amount": amount,
                }),
            ));
        }
        TokenInstruction::Approve { amount } => {
            let source_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "Approve.source_account"
            )))?;
            let delegate_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "Approve.delegate_account"
            )))?;
            if is_multisig(&accounts, 3) {
                let multisig_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                    format!("Approve.multisig_account"),
                ))?;
                let signers = &accounts[3..];
                return Ok(template_instruction(
                    program_name,
                    "Approve",
                    json!({
                        "source_account": source_account,
                        "delegate_account": delegate_account,
                        "multisig_account": multisig_account,
                        "signers": signers,
                        "amount": amount,
                    }),
                ));
            }
            let owner = accounts
                .get(2)
                .ok_or(SolanaError::AccountNotFound(format!("Approve.owner")))?;
            Ok(template_instruction(
                program_name,
                "Approve",
                json!({
                    "source_account": source_account,
                    "delegate_account": delegate_account,
                    "owner": owner,
                    "amount": amount,
                }),
            ))
        }
        TokenInstruction::Revoke => {
            let source_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "Revoke.source_account"
            )))?;
            if is_multisig(&accounts, 2) {
                let multisig_owner = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                    format!("Revoke.multisig_owner"),
                ))?;
                let signers = &accounts[2..];
                return Ok(template_instruction(
                    program_name,
                    "Revoke",
                    json!({
                        "source_account": source_account,
                        "multisig_owner": multisig_owner,
                        "signers": signers,
                    }),
                ));
            }
            let owner = accounts
                .get(1)
                .ok_or(SolanaError::AccountNotFound(format!("Revoke.owner")))?;
            return Ok(template_instruction(
                program_name,
                "Revoke",
                json!({
                    "source_account": source_account,
                    "owner": owner,
                }),
            ));
        }
        TokenInstruction::SetAuthority {
            authority_type,
            new_authority,
        } => {
            let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "SetAuthority.account"
            )))?;
            let authority_type = match authority_type {
                AuthorityType::AccountOwner => "account owner",
                AuthorityType::CloseAccount => "close account",
                AuthorityType::MintTokens => "mint tokens",
                AuthorityType::FreezeAccount => "freeze account",
            };
            let new_authority = map_coption_to_option(new_authority.map(|v| v.to_string()));
            if is_multisig(&accounts, 2) {
                let multisig_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                    format!("SetAuthority.multisig_authority"),
                ))?;
                let signers = &accounts[2..];
                Ok(template_instruction(
                    program_name,
                    "SetAuthority",
                    json!({
                        "account": account,
                        "multisig_authority": multisig_authority,
                        "signers": signers,
                        "authority_type": authority_type,
                        "new_authority": new_authority,
                    }),
                ))
            } else {
                let authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "SetAuthority.authority"
                )))?;
                Ok(template_instruction(
                    program_name,
                    "SetAuthority",
                    json!({
                        "account": account,
                        "authority": authority,
                        "authority_type": authority_type,
                        "new_authority": new_authority,
                    }),
                ))
            }
        }
        TokenInstruction::MintTo { amount } => {
            let mint = accounts
                .get(0)
                .ok_or(SolanaError::AccountNotFound(format!("MintTo.mint")))?;
            let mint_to_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "MintTo.mint_to_account"
            )))?;
            if is_multisig(&accounts, 3) {
                let multisig_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                    format!("MintTo.multisig_authority"),
                ))?;
                let signers = &accounts[3..];
                Ok(template_instruction(
                    program_name,
                    "MintTo",
                    json!({
                        "mint": mint,
                        "mint_to_account": mint_to_account,
                        "multisig_authority": multisig_authority,
                        "signers": signers,
                        "amount": amount,
                    }),
                ))
            } else {
                let authority = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("MintTo.authority")))?;
                Ok(template_instruction(
                    program_name,
                    "MintTo",
                    json!({
                        "mint": mint,
                        "mint_to_account": mint_to_account,
                        "authority": authority,
                        "amount": amount,
                    }),
                ))
            }
        }
        TokenInstruction::Burn { amount } => {
            let account = accounts
                .get(0)
                .ok_or(SolanaError::AccountNotFound(format!("Burn.account")))?;
            let mint = accounts
                .get(1)
                .ok_or(SolanaError::AccountNotFound(format!("Burn.mint")))?;
            if is_multisig(&accounts, 3) {
                let multisig_owner = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("Burn.multisig_owner")))?;
                let signers = &accounts[3..];
                Ok(template_instruction(
                    program_name,
                    "Burn",
                    json!({
                        "account": account,
                        "mint": mint,
                        "multisig_owner": multisig_owner,
                        "signers": signers,
                        "amount": amount,
                    }),
                ))
            } else {
                let owner = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("Burn.owner")))?;
                Ok(template_instruction(
                    program_name,
                    "Burn",
                    json!({
                        "account": account,
                        "mint": mint,
                        "owner": owner,
                        "amount": amount,
                    }),
                ))
            }
        }
        TokenInstruction::CloseAccount => {
            let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "CloseAccount.account"
            )))?;
            let destination_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                format!("CloseAccount.destination_account"),
            ))?;
            if is_multisig(&accounts, 3) {
                let multisig_owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                    format!("CloseAccount.multisig_owner"),
                ))?;
                let signers = &accounts[3..];
                Ok(template_instruction(
                    program_name,
                    "Burn",
                    json!({
                        "account": account,
                        "destination_account": destination_account,
                        "multisig_owner": multisig_owner,
                        "signers": signers,
                    }),
                ))
            } else {
                let owner = accounts
                    .get(2)
                    .ok_or(SolanaError::AccountNotFound(format!("CloseAccount.owner")))?;
                Ok(template_instruction(
                    program_name,
                    "Burn",
                    json!({
                        "account": account,
                        "destination_account": destination_account,
                        "owner": owner,
                    }),
                ))
            }
        }
        TokenInstruction::FreezeAccount => {
            let method_name = "FreezeAccount";
            let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "{}.account",
                method_name
            )))?;
            let token_mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_mint",
                method_name
            )))?;
            if is_multisig(&accounts, 3) {
                let multisig_mint_freeze_authority =
                    accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                        "{}.multisig_mint_freeze_authority",
                        method_name
                    )))?;
                let signers = &accounts[3..];
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "token_mint": token_mint,
                        "multisig_mint_freeze_authority": multisig_mint_freeze_authority,
                        "signers": signers,
                    }),
                ))
            } else {
                let mint_freeze_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                    format!("{}.mint_freeze_authority", method_name),
                ))?;
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "token_mint": token_mint,
                        "mint_freeze_authority": mint_freeze_authority,
                    }),
                ))
            }
        }
        TokenInstruction::ThawAccount => {
            let method_name = "ThawAccount";
            let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "{}.account",
                method_name
            )))?;
            let token_mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_mint",
                method_name
            )))?;
            if is_multisig(&accounts, 3) {
                let multisig_mint_freeze_authority =
                    accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                        "{}.multisig_mint_freeze_authority",
                        method_name
                    )))?;
                let signers = &accounts[3..];
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "token_mint": token_mint,
                        "multisig_mint_freeze_authority": multisig_mint_freeze_authority,
                        "signers": signers,
                    }),
                ))
            } else {
                let mint_freeze_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                    format!("{}.mint_freeze_authority", method_name),
                ))?;
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "token_mint": token_mint,
                        "mint_freeze_authority": mint_freeze_authority,
                    }),
                ))
            }
        }
        TokenInstruction::TransferChecked { decimals, amount } => {
            let method_name = "TransferChecked";
            if is_multisig(&accounts, 4) {
                let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.account",
                    method_name
                )))?;
                let token_mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.token_mint",
                    method_name
                )))?;
                let destination_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                    format!("{}.destination_account", method_name),
                ))?;
                let multisig_owner = accounts.get(3).ok_or(SolanaError::AccountNotFound(
                    format!("{}.multisig_owner", method_name),
                ))?;
                let signers = &accounts[4..];
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "token_mint": token_mint,
                        "destination_account": destination_account,
                        "multisig_owner": multisig_owner,
                        "signers": signers,
                        "decimals": decimals,
                        "amount": amount,
                    }),
                ))
            } else {
                let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.account",
                    method_name
                )))?;
                let token_mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.token_mint",
                    method_name
                )))?;
                let destination_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                    format!("{}.destination_account", method_name),
                ))?;
                let owner = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.owner",
                    method_name
                )))?;
                let signers = &accounts[4..];
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "token_mint": token_mint,
                        "destination_account": destination_account,
                        "owner": owner,
                        "decimals": decimals,
                        "amount": amount,
                    }),
                ))
            }
        }
        TokenInstruction::ApproveChecked { decimals, amount } => {
            let method_name = "ApproveChecked";
            if is_multisig(&accounts, 4) {
                let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.account",
                    method_name
                )))?;
                let token_mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.token_mint",
                    method_name
                )))?;
                let delegate = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.delegate",
                    method_name
                )))?;
                let multisig_owner = accounts.get(3).ok_or(SolanaError::AccountNotFound(
                    format!("{}.multisig_owner", method_name),
                ))?;
                let signers = &accounts[4..];
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "token_mint": token_mint,
                        "delegate": delegate,
                        "multisig_owner": multisig_owner,
                        "signers": signers,
                        "decimals": decimals,
                        "amount": amount,
                    }),
                ))
            } else {
                let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.account",
                    method_name
                )))?;
                let token_mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.token_mint",
                    method_name
                )))?;
                let delegate = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.delegate",
                    method_name
                )))?;
                let owner = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.owner",
                    method_name
                )))?;
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "token_mint": token_mint,
                        "delegate": delegate,
                        "owner": owner,
                        "decimals": decimals,
                        "amount": amount,
                    }),
                ))
            }
        }
        TokenInstruction::MintToChecked { decimals, amount } => {
            let method_name = "MintToChecked";
            let mint = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "{}.mint",
                method_name
            )))?;
            let mint_to_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.mint_to_account",
                method_name
            )))?;
            if is_multisig(&accounts, 3) {
                let multisig_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                    format!("{}.multisig_authority", method_name),
                ))?;
                let signers = &accounts[3..];
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "mint": mint,
                        "mint_to_account": mint_to_account,
                        "multisig_authority": multisig_authority,
                        "signers": signers,
                        "decimals": decimals,
                        "amount": amount,
                    }),
                ))
            } else {
                let authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.authority",
                    method_name
                )))?;
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "mint": mint,
                        "mint_to_account": mint_to_account,
                        "authority": authority,
                        "decimals": decimals,
                        "amount": amount,
                    }),
                ))
            }
        }
        TokenInstruction::BurnChecked { decimals, amount } => {
            let method_name = "BurnChecked";
            let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "{}.account",
                method_name
            )))?;
            let token_mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_mint",
                method_name
            )))?;
            if is_multisig(&accounts, 3) {
                let multisig_owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                    format!("{}.multisig_owner", method_name),
                ))?;
                let signers = &accounts[3..];
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "token_mint": token_mint,
                        "multisig_owner": multisig_owner,
                        "signers": signers,
                        "decimals": decimals,
                        "amount": amount,
                    }),
                ))
            } else {
                let owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.owner",
                    method_name
                )))?;
                Ok(template_instruction(
                    program_name,
                    method_name,
                    json!({
                        "account": account,
                        "token_mint": token_mint,
                        "owner": owner,
                        "decimals": decimals,
                        "amount": amount,
                    }),
                ))
            }
        }
        TokenInstruction::InitializeAccount2 { owner } => {
            let method_name = "InitializeAccount2";
            let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "{}.account",
                method_name
            )))?;
            let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.mint",
                method_name
            )))?;
            let rent_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.rent_sysvar",
                method_name
            )))?;
            let owner = owner.to_string();
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "account": account,
                    "mint": mint,
                    "rent_sysvar": rent_sysvar,
                    "owner": owner,
                }),
            ))
        }
        TokenInstruction::SyncNative => {
            let method_name = "SyncNative";
            let account_to_sync = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "{}.account_to_sync",
                method_name
            )))?;
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "account_to_sync": account_to_sync,
                }),
            ))
        }
        TokenInstruction::InitializeAccount3 { owner } => {
            let method_name = "InitializeAccount2";
            let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "{}.account",
                method_name
            )))?;
            let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.mint",
                method_name
            )))?;
            let owner = owner.to_string();
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "account": account,
                    "mint": mint,
                    "owner": owner,
                }),
            ))
        }
        TokenInstruction::InitializeMultisig2 { m } => {
            let multisig_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "InitializeMultisig.multisig_account"
            )))?;
            let attendees = &accounts[1..];
            let required_signatures = m;
            Ok(template_instruction(
                program_name,
                "InitializeMultisig",
                json!({
                    "multisig_account": multisig_account,
                    "attendees": attendees,
                    "required_signatures": required_signatures,
                }),
            ))
        }
        TokenInstruction::InitializeMint2 {
            mint_authority,
            decimals,
            freeze_authority,
        } => {
            let mint = accounts
                .get(0)
                .ok_or(SolanaError::AccountNotFound(format!("InitializeMint.mint")))?;
            let mint_authority = mint_authority.to_string();
            let freeze_authority = map_coption_to_option(freeze_authority.map(|v| v.to_string()));
            Ok(template_instruction(
                program_name,
                "InitializeMint",
                json!({
                    "mint": mint,
                    "mint_authority": mint_authority,
                    "freeze_authority": freeze_authority,
                    "decimals": decimals,
                }),
            ))
        }
    }
}
