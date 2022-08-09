use crate::error::{Result, SolanaError};
use crate::resolvers::template_instruction;
use crate::solana_lib::solana_program::pubkey::Pubkey;
use serde_json::{json, Value};
use crate::solana_lib::solana_program::system_instruction::SystemInstruction;

static PROGRAM_NAME: &str = "System";

pub fn resolve(instruction: SystemInstruction, accounts: Vec<String>) -> Result<Value> {
    match instruction {
        SystemInstruction::CreateAccount {
            lamports,
            space,
            owner,
        } => resolve_create_account(accounts, lamports, space, owner),
        SystemInstruction::Assign { owner } => resolve_assign(accounts, owner),
        SystemInstruction::Transfer { lamports } => resolve_transfer(accounts, lamports),
        SystemInstruction::CreateAccountWithSeed {
            base,
            seed,
            lamports,
            space,
            owner,
        } => resolve_create_account_with_seed(accounts, base, seed, lamports, space, owner),
        SystemInstruction::AdvanceNonceAccount => resolve_advance_nonce_account(accounts),
        SystemInstruction::WithdrawNonceAccount(lamports) => {
            resolve_withdraw_nonce_account(accounts, lamports)
        }
        SystemInstruction::InitializeNonceAccount(pubkey) => {
            resolve_initialize_nonce_account(accounts, pubkey)
        }
        SystemInstruction::AuthorizeNonceAccount(pubkey) => {
            resolve_authorize_nonce_account(accounts, pubkey)
        }
        SystemInstruction::Allocate { space } => resolve_allocate(accounts, space),
        SystemInstruction::AllocateWithSeed {
            owner,
            base,
            seed,
            space,
        } => resolve_allocate_with_seed(accounts, owner, base, seed, space),
        SystemInstruction::AssignWithSeed { owner, seed, base } => {
            resolve_assign_with_seed(accounts, owner, seed, base)
        }
        SystemInstruction::TransferWithSeed {
            lamports,
            from_seed,
            from_owner,
        } => resolve_transfer_with_seed(accounts, lamports, from_seed, from_owner),
        SystemInstruction::UpgradeNonceAccount => resolve_upgrade_nonce_account(accounts),
    }
}

fn resolve_create_account(
    accounts: Vec<String>,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) -> Result<Value> {
    let method_name = "CreateAccount";
    let funding_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "CreateAccount.funding_account"
    )))?;
    let new_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "CreateAccount.new_account"
    )))?;
    let amount = lamports.to_string();
    let space = space.to_string();
    let owner = owner.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "funding_account": funding_account,
            "new_account": account,
            "amount": amount,
            "space": space,
            "owner": owner,
        }),
        json!({
            "funding_account": funding_account,
            "new_account": new_account,
            "amount": amount,
        })
    ))
}

fn resolve_assign(accounts: Vec<String>, owner: Pubkey) -> Result<Value> {
    let method_name = "Assign";
    let account = accounts
        .get(0)
        .ok_or(SolanaError::AccountNotFound(format!("{}.account", method_name)))?;
    let new_owner = owner.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "account": account,
            "new_owner": new_owner,
        }),
        json!({
            "account": account,
            "new_owner": new_owner,
        }),
    ))
}

fn resolve_transfer(accounts: Vec<String>, lamports: u64) -> Result<Value> {
    let method_name = "Transfer";
    let from = accounts
        .get(0)
        .ok_or(SolanaError::AccountNotFound(format!("{}.from", method_name)))?;
    let recipient = accounts
        .get(1)
        .ok_or(SolanaError::AccountNotFound(format!("{}.recipient", method_name)))?;
    let amount = lamports.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "from": from,
            "recipient": recipient,
            "amount": amount
        }),
        json!({
            "from": from,
            "recipient": recipient,
            "amount": amount
        }),
    ))
}

fn resolve_create_account_with_seed(
    accounts: Vec<String>,
    base: Pubkey,
    seed: String,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) -> Result<Value> {
    let method_name = "CreateAccountWithSeed";
    let funding_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.funding_account", method_name
    )))?;
    let new_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.new_account", method_name
    )))?;
    let base_account = accounts.get(2);
    let amount = lamports.to_string();
    let space = space.to_string();
    let owner = owner.to_string();
    let base_pubkey = base.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "funding_account": funding_account,
            "new_account": new_account,
            "base_account": base_account,
            "base_pubkey": base_pubkey,
            "seed": seed,
            "amount": amount,
            "space": space,
            "owner": owner,
        }),
        json!({
            "funding_account": funding_account,
            "new_account": new_account,
            "base_pubkey": base_pubkey,
            "seed": seed,
            "amount": amount,
            "space": space,
        })
    ))
}

fn resolve_advance_nonce_account(accounts: Vec<String>) -> Result<Value> {
    let method_name = "AdvanceNonceAccount";
    let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.nonce_account", method_name
    )))?;
    let recent_blockhashes_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(
        format!("{}.recent_blockhashes_sysvar", method_name),
    ))?;
    let nonce_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.nonce_authority_pubkey", method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "nonce_account": nonce_account,
            "recent_blockhashes_sysvar": recent_blockhashes_sysvar,
            "nonce_authority_pubkey": nonce_authority_pubkey,
        }),
        json!({
            "nonce_account": nonce_account,
        })
    ))
}

fn resolve_withdraw_nonce_account(accounts: Vec<String>, lamports: u64) -> Result<Value> {
    let method_name = "WithdrawNonceAccount";
    let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.nonce_account", method_name
    )))?;
    let recipient = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.recipient", method_name
    )))?;
    let recent_blockhashes_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(
        format!("{}.recent_blockhashes_sysvar", method_name),
    ))?;
    let rent_sysvar = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.rent_sysvar", method_name
    )))?;
    let nonce_authority_pubkey = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
        "{}.nonce_authority_pubkey", method_name
    )))?;
    let amount = lamports.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "nonce_account": nonce_account,
            "recipient": recipient,
            "recent_blockhashes_sysvar": recent_blockhashes_sysvar,
            "rent_sysvar": rent_sysvar,
            "nonce_authority_pubkey": nonce_authority_pubkey,
            "amount": amount,
        }),
        json!({
            "nonce_account": nonce_account,
            "recipient": recipient,
            "amount": amount,
        })
    ))
}

fn resolve_initialize_nonce_account(accounts: Vec<String>, pubkey: Pubkey) -> Result<Value> {
    let method_name = "InitializeNonceAccount";
    let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.nonce_account", method_name
    )))?;
    let sysvar_recent_blockhashes = accounts.get(1).ok_or(SolanaError::AccountNotFound(
        format!("{}.sysvar_recent_blockhashes", method_name),
    ))?;
    let sysvar_rent = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_rent", method_name
    )))?;
    let nonce_authority_pubkey = pubkey.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "nonce_account": nonce_account,
            "sysvar_recent_blockhashes": sysvar_recent_blockhashes,
            "sysvar_rent": sysvar_rent,
            "nonce_authority_pubkey": nonce_authority_pubkey,
        }),
        json!({
            "nonce_account": nonce_account,
            "nonce_authority_pubkey": nonce_authority_pubkey,
        })
    ))
}

fn resolve_authorize_nonce_account(accounts: Vec<String>, pubkey: Pubkey) -> Result<Value> {
    let method_name = "AuthorizeNonceAccount";
    let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.nonce_account", method_name
    )))?;
    let old_nonce_authority_pubkey = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.old_nonce_authority_pubkey", method_name
    )))?;
    let new_nonce_authority_pubkey = pubkey.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "nonce_account": nonce_account,
            "old_nonce_authority_pubkey": old_nonce_authority_pubkey,
            "new_nonce_authority_pubkey": new_nonce_authority_pubkey,
        }),
        json!({
            "nonce_account": nonce_account,
            "old_nonce_authority_pubkey": old_nonce_authority_pubkey,
            "new_nonce_authority_pubkey": new_nonce_authority_pubkey,
        })
    ))
}

fn resolve_allocate(accounts: Vec<String>, space: u64) -> Result<Value> {
    let method_name = "Allocate";
    let new_account = accounts
        .get(0)
        .ok_or(SolanaError::AccountNotFound(format!("{}.account", method_name)))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "new_account": new_account,
            "space": space.to_string(),
        }),
        json!({
            "new_account": new_account,
            "space": space.to_string(),
        })
    ))
}

fn resolve_allocate_with_seed(
    accounts: Vec<String>,
    owner: Pubkey,
    base_pubkey: Pubkey,
    seed: String,
    space: u64,
) -> Result<Value> {
    let method_name = "AllocateWithSeed";
    let allocated_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.allocated_account", method_name
    )))?;
    let base_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.base_account", method_name
    )))?;
    let owner = owner.to_string();
    let base = base_pubkey.to_string();
    let space = space.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "allocated_account": allocated_account,
            "base_account": base_account,
            "base_pubkey": base,
            "seed": seed,
            "space": space,
            "owner": owner,
        }),
        json!({
            "allocated_account": allocated_account,
            "base_account": base_account,
            "base_pubkey": base,
            "seed": seed,
            "space": space
        })
    ))
}

fn resolve_assign_with_seed(
    accounts: Vec<String>,
    owner: Pubkey,
    seed: String,
    base_pubkey: Pubkey,
) -> Result<Value> {
    let method_name = "AssignWithSeed";
    let assigned_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.assigned_account", method_name
    )))?;
    let base_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.base_account", method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "assigned_account": assigned_account,
            "base_account": base_account,
            "base_pubkey": base_pubkey.to_string(),
            "seed": seed,
            "owner": owner.to_string(),
        }),
        json!({
            "assigned_account": assigned_account,
            "base_account": base_account,
            "base_pubkey": base_pubkey.to_string(),
            "seed": seed,
        })
    ))
}

fn resolve_transfer_with_seed(
    accounts: Vec<String>,
    lamports: u64,
    from_seed: String,
    from_owner: Pubkey,
) -> Result<Value> {
    let method_name = "TransferWithSeed";
    let from = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.from", method_name
    )))?;
    let from_base_pubkey = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.from_base_pubkey", method_name
    )))?;
    let recipient = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.recipient", method_name
    )))?;
    let amount = lamports.to_string();
    let from_owner = from_owner.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "from": from,
            "recipient": recipient,
            "amount": amount,
            "from_base_pubkey": from_base_pubkey,
            "from_owner": from_owner,
            "from_seed": from_seed,
        }),
        json!({
            "from": from,
            "recipient": recipient,
            "amount": amount,
            "from_base_pubkey": from_base_pubkey,
            "from_seed": from_seed,
        })
    ))
}

fn resolve_upgrade_nonce_account(accounts: Vec<String>) -> Result<Value> {
    let method_name = "UpgradeNonceAccount";
    let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "UpgradeNonceAccount.nonce_account"
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "nonce_account": nonce_account,
        }),
        json!({
            "nonce_account": nonce_account,
        }),
    ))
}
