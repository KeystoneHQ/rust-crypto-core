use crate::error::{Result, SolanaError};
use crate::types::resolvers::template_instruction;
use serde_json::{json, Value};
use solana_program::program_option::COption;
use spl_token::instruction::TokenInstruction;

fn map_coption_to_option<T>(value: COption<T>) -> Option<T> {
    match value {
        COption::Some(t) => Some(t),
        COption::None => None,
    }
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
        _ => Err(SolanaError::UnknownInstruction),
    }
}
