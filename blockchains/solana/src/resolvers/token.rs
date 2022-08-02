use crate::error::{Result, SolanaError};
use crate::resolvers::template_instruction;
use serde_json::{json, Value};
use crate::solana_lib::solana_program::program_option::COption;
use crate::solana_lib::solana_program::pubkey::Pubkey;
use crate::solana_lib::spl::token::instruction::{AuthorityType, TokenInstruction};

fn map_coption_to_option<T>(value: COption<T>) -> Option<T> {
    match value {
        COption::Some(t) => Some(t),
        COption::None => None,
    }
}

fn is_multisig(accounts: &Vec<String>, point: u8) -> bool {
    (accounts.len() as u8) > point
}

static PROGRAM_NAME: &str = "Token";

pub fn resolve(instruction: TokenInstruction, accounts: Vec<String>) -> Result<Value> {
    match instruction {
        TokenInstruction::InitializeMint {
            mint_authority,
            decimals,
            freeze_authority,
        } => initialize_mint(accounts, mint_authority, decimals, freeze_authority),
        TokenInstruction::InitializeAccount => initialize_account(accounts),
        TokenInstruction::InitializeMultisig { m } => initialize_multisig(accounts, m),
        TokenInstruction::Transfer { amount } => transfer(accounts, amount),
        TokenInstruction::Approve { amount } => approve(accounts, amount),
        TokenInstruction::Revoke => revoke(accounts),
        TokenInstruction::SetAuthority {
            authority_type,
            new_authority,
        } => set_authority(accounts, authority_type, new_authority),
        TokenInstruction::MintTo { amount } => mint_to(accounts, amount),
        TokenInstruction::Burn { amount } => burn(accounts, amount),
        TokenInstruction::CloseAccount => close_account(accounts),
        TokenInstruction::FreezeAccount => freeze_account(accounts),
        TokenInstruction::ThawAccount => thaw_account(accounts),
        TokenInstruction::TransferChecked { decimals, amount } => {
            transfer_checked(accounts, decimals, amount)
        }
        TokenInstruction::ApproveChecked { decimals, amount } => {
            approve_checked(accounts, decimals, amount)
        }
        TokenInstruction::MintToChecked { decimals, amount } => {
            mint_to_checked(accounts, decimals, amount)
        }
        TokenInstruction::BurnChecked { decimals, amount } => {
            burn_checked(accounts, decimals, amount)
        }
        TokenInstruction::InitializeAccount2 { owner } => initialize_account_2(accounts, owner),
        TokenInstruction::SyncNative => sync_native(accounts),
        TokenInstruction::InitializeAccount3 { owner } => initialize_account_3(accounts, owner),
        TokenInstruction::InitializeMultisig2 { m } => initialize_multisig_2(accounts, m),
        TokenInstruction::InitializeMint2 {
            mint_authority,
            decimals,
            freeze_authority,
        } => initialize_mint_2(accounts, mint_authority, decimals, freeze_authority),
    }
}

fn initialize_mint(
    accounts: Vec<String>,
    mint_authority: Pubkey,
    decimals: u8,
    freeze_authority: COption<Pubkey>,
) -> Result<Value> {
    let method_name = "InitializeMint";
    let mint = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint",
        method_name
    )))?;
    let rent_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.rent_sysvar",
        method_name
    )))?;
    let mint_authority = mint_authority.to_string();
    let freeze_authority = map_coption_to_option(freeze_authority.map(|v| v.to_string()));
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "mint": mint,
            "rent_sysvar": rent_sysvar,
            "mint_authority": mint_authority,
            "freeze_authority": freeze_authority,
            "decimals": decimals,
        }),
    ))
}

fn initialize_account(accounts: Vec<String>) -> Result<Value> {
    let method_name = "InitializeAccount";

    let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint",
        method_name
    )))?;
    let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account",
        method_name
    )))?;
    let owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.owner",
        method_name
    )))?;
    let rent_sysvar = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.rent_sysvar",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "account": account,
            "mint": mint,
            "owner": owner,
            "rent_sysvar": rent_sysvar,
        }),
    ))
}

fn initialize_multisig(accounts: Vec<String>, m: u8) -> Result<Value> {
    let method_name = "InitializeMultisig";

    let multisig_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.multisig_account",
        method_name
    )))?;
    let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account",
        method_name
    )))?;
    let attendees = &accounts[2..];
    let required_signatures = m;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "multisig_account": multisig_account,
            "mint": mint,
            "attendees": attendees,
            "required_signatures": required_signatures,
        }),
    ))
}

fn transfer(accounts: Vec<String>, amount: u64) -> Result<Value> {
    let method_name = "Transfer";

    let source_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.source_account",
        method_name
    )))?;
    let destination_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_account",
        method_name
    )))?;
    let amount = amount.to_string();
    if is_multisig(&accounts, 3) {
        let multisig_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.multisig_account",
            method_name
        )))?;
        let signers = &accounts[3..];
        return Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
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
        PROGRAM_NAME,
        method_name,
        json!({
            "source_account": source_account,
            "destination_account": destination_account,
            "owner": owner,
            "amount": amount,
        }),
    ));
}

fn approve(accounts: Vec<String>, amount: u64) -> Result<Value> {
    let method_name = "Approve";

    let source_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.source_account",
        method_name
    )))?;
    let delegate_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.delegate_account",
        method_name
    )))?;
    let amount = amount.to_string();
    if is_multisig(&accounts, 3) {
        let multisig_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.multisig_account",
            method_name
        )))?;
        let signers = &accounts[3..];
        return Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "source_account": source_account,
                "delegate_account": delegate_account,
                "multisig_account": multisig_account,
                "signers": signers,
                "amount": amount,
            }),
        ));
    }
    let owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.owner",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "source_account": source_account,
            "delegate_account": delegate_account,
            "owner": owner,
            "amount": amount,
        }),
    ))
}

fn revoke(accounts: Vec<String>) -> Result<Value> {
    let method_name = "Revoke";

    let source_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.source_account",
        method_name
    )))?;
    if is_multisig(&accounts, 2) {
        let multisig_owner = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
            "{}.multisig_owner",
            method_name
        )))?;
        let signers = &accounts[2..];
        return Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "source_account": source_account,
                "multisig_owner": multisig_owner,
                "signers": signers,
            }),
        ));
    }
    let owner = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.owner",
        method_name
    )))?;
    return Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "source_account": source_account,
            "owner": owner,
        }),
    ));
}

fn set_authority(
    accounts: Vec<String>,
    authority_type: AuthorityType,
    new_authority: COption<Pubkey>,
) -> Result<Value> {
    let method_name = "SetAuthority";

    let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account",
        method_name
    )))?;
    let authority_type = match authority_type {
        AuthorityType::AccountOwner => "account owner",
        AuthorityType::CloseAccount => "close account",
        AuthorityType::MintTokens => "mint tokens",
        AuthorityType::FreezeAccount => "freeze account",
    };
    let new_authority = map_coption_to_option(new_authority.map(|v| v.to_string()));
    if is_multisig(&accounts, 2) {
        let multisig_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
            "{}.multisig_authority",
            method_name
        )))?;
        let signers = &accounts[2..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
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
            "{}.authority",
            method_name
        )))?;
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "authority": authority,
                "authority_type": authority_type,
                "new_authority": new_authority,
            }),
        ))
    }
}

fn mint_to(accounts: Vec<String>, amount: u64) -> Result<Value> {
    let method_name = "MintTo";

    let mint = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint",
        method_name
    )))?;
    let mint_to_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint_to_account",
        method_name
    )))?;
    let amount = amount.to_string();
    if is_multisig(&accounts, 3) {
        let multisig_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.multisig_authority",
            method_name
        )))?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "mint": mint,
                "mint_to_account": mint_to_account,
                "multisig_authority": multisig_authority,
                "signers": signers,
                "amount": amount,
            }),
        ))
    } else {
        let authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.authority",
            method_name
        )))?;
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "mint": mint,
                "mint_to_account": mint_to_account,
                "authority": authority,
                "amount": amount,
            }),
        ))
    }
}

fn burn(accounts: Vec<String>, amount: u64) -> Result<Value> {
    let method_name = "Burn";

    let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account",
        method_name
    )))?;
    let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint",
        method_name
    )))?;
    let amount = amount.to_string();
    if is_multisig(&accounts, 3) {
        let multisig_owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.multisig_owner",
            method_name
        )))?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "mint": mint,
                "multisig_owner": multisig_owner,
                "signers": signers,
                "amount": amount,
            }),
        ))
    } else {
        let owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.owner",
            method_name
        )))?;
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "mint": mint,
                "owner": owner,
                "amount": amount,
            }),
        ))
    }
}

fn close_account(accounts: Vec<String>) -> Result<Value> {
    let method_name = "CloseAccount";
    let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account",
        method_name
    )))?;
    let destination_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.destination_account",
        method_name
    )))?;
    if is_multisig(&accounts, 3) {
        let multisig_owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.multisig_owner",
            method_name
        )))?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
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
            PROGRAM_NAME,
            "Burn",
            json!({
                "account": account,
                "destination_account": destination_account,
                "owner": owner,
            }),
        ))
    }
}

fn freeze_account(accounts: Vec<String>) -> Result<Value> {
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
        let multisig_mint_freeze_authority = accounts.get(2).ok_or(
            SolanaError::AccountNotFound(format!("{}.multisig_mint_freeze_authority", method_name)),
        )?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
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
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "token_mint": token_mint,
                "mint_freeze_authority": mint_freeze_authority,
            }),
        ))
    }
}

fn thaw_account(accounts: Vec<String>) -> Result<Value> {
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
        let multisig_mint_freeze_authority = accounts.get(2).ok_or(
            SolanaError::AccountNotFound(format!("{}.multisig_mint_freeze_authority", method_name)),
        )?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
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
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "token_mint": token_mint,
                "mint_freeze_authority": mint_freeze_authority,
            }),
        ))
    }
}

fn transfer_checked(accounts: Vec<String>, decimals: u8, amount: u64) -> Result<Value> {
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
        let destination_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.destination_account",
            method_name
        )))?;
        let multisig_owner = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
            "{}.multisig_owner",
            method_name
        )))?;
        let signers = &accounts[4..];
        let amount = amount.to_string();
        Ok(template_instruction(
            PROGRAM_NAME,
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
        let destination_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.destination_account",
            method_name
        )))?;
        let owner = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
            "{}.owner",
            method_name
        )))?;
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "token_mint": token_mint,
                "destination_account": destination_account,
                "owner": owner,
                "decimals": decimals,
                "amount": amount.to_string(),
            }),
        ))
    }
}

fn approve_checked(accounts: Vec<String>, decimals: u8, amount: u64) -> Result<Value> {
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
        let multisig_owner = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
            "{}.multisig_owner",
            method_name
        )))?;
        let signers = &accounts[4..];
        let amount = amount.to_string();
        Ok(template_instruction(
            PROGRAM_NAME,
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
        let amount = amount.to_string();
        Ok(template_instruction(
            PROGRAM_NAME,
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

fn mint_to_checked(accounts: Vec<String>, decimals: u8, amount: u64) -> Result<Value> {
    let method_name = "MintToChecked";
    let mint = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint",
        method_name
    )))?;
    let mint_to_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint_to_account",
        method_name
    )))?;
    let amount = amount.to_string();
    if is_multisig(&accounts, 3) {
        let multisig_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.multisig_authority",
            method_name
        )))?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
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
            PROGRAM_NAME,
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

fn burn_checked(accounts: Vec<String>, decimals: u8, amount: u64) -> Result<Value> {
    let method_name = "BurnChecked";
    let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account",
        method_name
    )))?;
    let token_mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.token_mint",
        method_name
    )))?;
    let amount = amount.to_string();
    if is_multisig(&accounts, 3) {
        let multisig_owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.multisig_owner",
            method_name
        )))?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
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
            PROGRAM_NAME,
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

fn initialize_account_2(accounts: Vec<String>, owner: Pubkey) -> Result<Value> {
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
        PROGRAM_NAME,
        method_name,
        json!({
            "account": account,
            "mint": mint,
            "rent_sysvar": rent_sysvar,
            "owner": owner,
        }),
    ))
}

fn sync_native(accounts: Vec<String>) -> Result<Value> {
    let method_name = "SyncNative";
    let account_to_sync = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account_to_sync",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "account_to_sync": account_to_sync,
        }),
    ))
}

fn initialize_account_3(accounts: Vec<String>, owner: Pubkey) -> Result<Value> {
    let method_name = "InitializeAccount3";
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
        PROGRAM_NAME,
        method_name,
        json!({
            "account": account,
            "mint": mint,
            "owner": owner,
        }),
    ))
}

fn initialize_multisig_2(accounts: Vec<String>, m: u8) -> Result<Value> {
    let method_name = "InitializeMultisig2";
    let multisig_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.multisig_account",
        method_name
    )))?;
    let attendees = &accounts[1..];
    let required_signatures = m;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "multisig_account": multisig_account,
            "attendees": attendees,
            "required_signatures": required_signatures,
        }),
    ))
}

fn initialize_mint_2(
    accounts: Vec<String>,
    mint_authority: Pubkey,
    decimals: u8,
    freeze_authority: COption<Pubkey>,
) -> Result<Value> {
    let method_name = "InitializeMint2";
    let mint = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint",
        method_name
    )))?;
    let mint_authority = mint_authority.to_string();
    let freeze_authority = map_coption_to_option(freeze_authority.map(|v| v.to_string()));
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "mint": mint,
            "mint_authority": mint_authority,
            "freeze_authority": freeze_authority,
            "decimals": decimals,
        }),
    ))
}
