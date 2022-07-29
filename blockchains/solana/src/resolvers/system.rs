use crate::error::{Result, SolanaError};
use crate::resolvers::template_instruction;
use serde_json::{json, Value};
use solana_program::pubkey::Pubkey;
use solana_program::system_instruction::SystemInstruction;

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
    let funder = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "CreateAccount.funder"
    )))?;
    let account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "CreateAccount.account"
    )))?;
    let amount = lamports.to_string();
    let space = space.to_string();
    let owner = owner.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "funder": funder,
            "account": account,
            "amount": amount,
            "space": space,
            "owner": owner,
        }),
    ))
}

fn resolve_assign(accounts: Vec<String>, owner: Pubkey) -> Result<Value> {
    let method_name = "Assign";
    let account = accounts
        .get(0)
        .ok_or(SolanaError::AccountNotFound(format!("Allocate.account")))?;
    let new_owner = owner.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
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
        .ok_or(SolanaError::AccountNotFound(format!("Transfer.from")))?;
    let to = accounts
        .get(1)
        .ok_or(SolanaError::AccountNotFound(format!("Transfer.to")))?;
    let amount = lamports.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "from": from,
            "to": to,
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
    let funder = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "CreateAccountWithSeed.funder"
    )))?;
    let account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "CreateAccountWithSeed.account"
    )))?;
    let signer = accounts.get(2);
    let amount = lamports.to_string();
    let space = space.to_string();
    let owner = owner.to_string();
    let base = base.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "funder": funder,
            "account": account,
            "signer": signer,
            "base": base,
            "seed": seed,
            "amount": amount,
            "space": space,
            "owner": owner,
        }),
    ))
}

fn resolve_advance_nonce_account(accounts: Vec<String>) -> Result<Value> {
    let method_name = "AdvanceNonceAccount";
    let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "AdvanceNonceAccount.nonce_account"
    )))?;
    let recent_blockhashes_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(
        format!("AdvanceNonceAccount.recent_blockhashes_sysvar"),
    ))?;
    let authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "AdvanceNonceAccount.authority"
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "nonce_account": nonce_account,
            "recent_blockhashes_sysvar": recent_blockhashes_sysvar,
            "authority": authority,
        }),
    ))
}

fn resolve_withdraw_nonce_account(accounts: Vec<String>, lamports: u64) -> Result<Value> {
    let method_name = "WithdrawNonceAccount";
    let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "WithdrawNonceAccount.nonce_account"
    )))?;
    let recipient_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "WithdrawNonceAccount.recipient_account"
    )))?;
    let recent_blockhashes_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(
        format!("WithdrawNonceAccount.recent_blockhashes_sysvar"),
    ))?;
    let rent_sysvar = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "WithdrawNonceAccount.rent_sysvar"
    )))?;
    let nonce_authority = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
        "WithdrawNonceAccount.nonce_authority"
    )))?;
    let amount = lamports.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "nonce_account": nonce_account,
            "recipient_account": recipient_account,
            "recent_blockhashes_sysvar": recent_blockhashes_sysvar,
            "rent_sysvar": rent_sysvar,
            "nonce_authority": nonce_authority,
            "amount": amount,
        }),
    ))
}

fn resolve_initialize_nonce_account(accounts: Vec<String>, pubkey: Pubkey) -> Result<Value> {
    let method_name = "InitializeNonceAccount";
    let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "InitializeNonceAccount.nonce_account"
    )))?;
    let recent_blockhashes_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(
        format!("InitializeNonceAccount.recent_blockhashes_sysvar"),
    ))?;
    let rent_sysvar = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "InitializeNonceAccount.rent_sysvar"
    )))?;
    let authority = pubkey.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "nonce_account": nonce_account,
            "recent_blockhashes_sysvar": recent_blockhashes_sysvar,
            "rent_sysvar": rent_sysvar,
            "authority": authority,
        }),
    ))
}

fn resolve_authorize_nonce_account(accounts: Vec<String>, pubkey: Pubkey) -> Result<Value> {
    let method_name = "AuthorizeNonceAccount";
    let nonce_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "AuthorizeNonceAccount.nonce_account"
    )))?;
    let nonce_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "AuthorizeNonceAccount.nonce_authority"
    )))?;
    let new_authority = pubkey.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "nonce_account": nonce_account,
            "nonce_authority": nonce_authority,
            "new_authority": new_authority,
        }),
    ))
}

fn resolve_allocate(accounts: Vec<String>, space: u64) -> Result<Value> {
    let method_name = "Allocate";
    let account = accounts
        .get(0)
        .ok_or(SolanaError::AccountNotFound(format!("Allocate.account")))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "account": account,
            "space": space.to_string(),
        }),
    ))
}

fn resolve_allocate_with_seed(
    accounts: Vec<String>,
    owner: Pubkey,
    base: Pubkey,
    seed: String,
    space: u64,
) -> Result<Value> {
    let method_name = "AllocateWithSeed";
    let allocated_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "AllocateWithSeed.allocated_account"
    )))?;
    let base_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "AllocateWithSeed.base_account"
    )))?;
    let owner = owner.to_string();
    let base = base.to_string();
    let space = space.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "allocated_account": allocated_account,
            "base_account": base_account,
            "owner": owner,
            "base": base,
            "seed": seed,
            "space": space
        }),
    ))
}

fn resolve_assign_with_seed(
    accounts: Vec<String>,
    owner: Pubkey,
    seed: String,
    base: Pubkey,
) -> Result<Value> {
    let method_name = "AssignWithSeed";
    let assigned_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "AssignWithSeed.assigned_account"
    )))?;
    let base_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "AssignWithSeed.base_account"
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "assigned_account": assigned_account,
            "base_account": base_account,
            "seed": seed,
            "base": base.to_string(),
            "owner": owner.to_string(),
        }),
    ))
}

fn resolve_transfer_with_seed(
    accounts: Vec<String>,
    lamports: u64,
    from_seed: String,
    from_owner: Pubkey,
) -> Result<Value> {
    let method_name = "TransferWithSeed";
    let fund_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "TransferWithSeed.fund_account"
    )))?;
    let from_base = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "TransferWithSeed.from_base"
    )))?;
    let recipient_account = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "TransferWithSeed.recipient_account"
    )))?;
    let amount = lamports.to_string();
    let from_owner = from_owner.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "fund_account": fund_account,
            "recipient_account": recipient_account,
            "amount": amount,
            "from_base": from_base,
            "from_owner": from_owner,
            "from_seed": from_seed,
        }),
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
    ))
}
