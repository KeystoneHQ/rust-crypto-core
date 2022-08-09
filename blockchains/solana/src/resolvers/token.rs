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
            mint_authority_pubkey,
            decimals,
            freeze_authority_pubkey,
        } => initialize_mint(accounts, mint_authority_pubkey, decimals, freeze_authority_pubkey),
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
            mint_authority_pubkey,
            decimals,
            freeze_authority_pubkey,
        } => initialize_mint_2(accounts, mint_authority_pubkey, decimals, freeze_authority_pubkey),
    }
}

fn initialize_mint(
    accounts: Vec<String>,
    mint_authority_pubkey: Pubkey,
    decimals: u8,
    freeze_authority_pubkey: COption<Pubkey>,
) -> Result<Value> {
    let method_name = "InitializeMint";
    let mint = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint",
        method_name
    )))?;
    let sysver_rent = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysver_rent",
        method_name
    )))?;
    let mint_authority_pubkey = mint_authority_pubkey.to_string();
    let freeze_authority_pubkey = map_coption_to_option(freeze_authority_pubkey.map(|v| v.to_string()));
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "mint": mint,
            "sysver_rent": sysver_rent,
            "mint_authority_pubkey": mint_authority_pubkey,
            "freeze_authority_pubkey": freeze_authority_pubkey,
            "decimals": decimals,
        }),
        json!({
            "mint": mint,
            "mint_authority_pubkey": mint_authority_pubkey,
            "freeze_authority_pubkey": freeze_authority_pubkey,
            "decimals": decimals,
        })
    ))
}

fn initialize_account(accounts: Vec<String>) -> Result<Value> {
    let method_name = "InitializeAccount";

    let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account",
        method_name
    )))?;
    let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint",
        method_name
    )))?;
    let owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.owner",
        method_name
    )))?;
    let sysver_rent = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysver_rent",
        method_name
    )))?;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "account": account,
            "mint": mint,
            "owner": owner,
            "sysver_rent": sysver_rent,
        }),
        json!({
            "account": account,
            "mint": mint,
        })
    ))
}

fn initialize_multisig(accounts: Vec<String>, m: u8) -> Result<Value> {
    let method_name = "InitializeMultisig";

    let multisig_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.multisig_account",
        method_name
    )))?;
    let sysvar_rent = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysvar_rent",
        method_name
    )))?;
    let attendees = &accounts[2..];
    let required_signatures = m;
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "multisig_account": multisig_account,
            "sysvar_rent": sysvar_rent,
            "attendees": attendees,
            "required_signatures": required_signatures,
        }),
        json!({
            "multisig_account": multisig_account,
            "attendees": attendees,
            "required_signatures": required_signatures,
        })
    ))
}

fn transfer(accounts: Vec<String>, amount: u64) -> Result<Value> {
    let method_name = "Transfer";

    let source_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.source_account",
        method_name
    )))?;
    let recipient = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.recipient",
        method_name
    )))?;
    let amount = amount.to_string();
    if is_multisig(&accounts, 3) {
        let owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.owner",
            method_name
        )))?;
        let signers = &accounts[3..];
        return Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "source_account": source_account,
                "recipient": recipient,
                "owner": owner,
                "signers": signers,
                "amount": amount,
            }),
            json!({
                "source_account": source_account,
                "recipient": recipient,
                "amount": amount,
            })
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
        json!({
            "source_account": source_account,
            "destination_account": destination_account,
            "amount": amount,
        })
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
        let owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.owner",
            method_name
        )))?;
        let signers = &accounts[3..];
        return Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "source_account": source_account,
                "delegate_account": delegate_account,
                "owner": owner,
                "signers": signers,
                "amount": amount,
            }),
            json!({
                "source_account": source_account,
                "delegate_account": delegate_account,
                "amount": amount,
            })
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
        json!({
            "source_account": source_account,
            "delegate_account": delegate_account,
            "amount": amount,
        })
    ))
}

fn revoke(accounts: Vec<String>) -> Result<Value> {
    let method_name = "Revoke";

    let source_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.source_account",
        method_name
    )))?;
    if is_multisig(&accounts, 2) {
        let owner = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
            "{}.owner",
            method_name
        )))?;
        let signers = &accounts[2..];
        return Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "source_account": source_account,
                "owner": owner,
                "signers": signers,
            }),
            json!({
                "source_account": source_account,
            })
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
        json!({
            "source_account": source_account,
        })
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
    let new_authority_pubkey = map_coption_to_option(new_authority.map(|v| v.to_string()));
    if is_multisig(&accounts, 2) {
        let old_authority_pubkey = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
            "{}.old_authority_pubkey",
            method_name
        )))?;
        let signers = &accounts[2..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "old_authority_pubkey": old_authority_pubkey,
                "signers": signers,
                "authority_type": authority_type,
                "new_authority_pubkey": new_authority_pubkey,
            }),
            json!({
                "account": account,
                "old_authority_pubkey": old_authority_pubkey,
                "authority_type": authority_type,
                "new_authority_pubkey": new_authority_pubkey,
            })
        ))
    } else {
        let old_authority_pubkey = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
            "{}.old_authority_pubkey",
            method_name
        )))?;
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "old_authority_pubkey": old_authority_pubkey,
                "authority_type": authority_type,
                "new_authority_pubkey": new_authority_pubkey,
            }),
            json!({
                "account": account,
                "old_authority_pubkey": old_authority_pubkey,
                "authority_type": authority_type,
                "new_authority_pubkey": new_authority_pubkey,
            })
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
        let mint_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.mint_authority_pubkey",
            method_name
        )))?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "mint": mint,
                "mint_to_account": mint_to_account,
                "mint_authority_pubkey": mint_authority_pubkey,
                "signers": signers,
                "amount": amount,
            }),
            json!({
                "mint": mint,
                "mint_to_account": mint_to_account,
                "amount": amount,
            })
        ))
    } else {
        let mint_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.mint_authority_pubkey",
            method_name
        )))?;
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "mint": mint,
                "mint_to_account": mint_to_account,
                "mint_authority_pubkey": mint_authority_pubkey,
                "amount": amount,
            }),
            json!({
                "mint": mint,
                "mint_to_account": mint_to_account,
                "amount": amount,
            })
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
        let owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.owner",
            method_name
        )))?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "mint": mint,
                "owner": owner,
                "signers": signers,
                "amount": amount,
            }),
            json!({
                "account": account,
                "mint": mint,
                "amount": amount,
            })
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
            json!({
                "account": account,
                "mint": mint,
                "amount": amount,
            })
        ))
    }
}

fn close_account(accounts: Vec<String>) -> Result<Value> {
    let method_name = "CloseAccount";
    let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account",
        method_name
    )))?;
    let recipient = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.recipient",
        method_name
    )))?;
    if is_multisig(&accounts, 3) {
        let owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.owner",
            method_name
        )))?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "recipient": recipient,
                "owner": owner,
                "signers": signers,
            }),
            json!({
                "account": account,
                "recipient": recipient,
            })
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
                "recipient": recipient,
                "owner": owner,
            }),
            json!({
                "account": account,
                "recipient": recipient,
            })
        ))
    }
}

fn freeze_account(accounts: Vec<String>) -> Result<Value> {
    let method_name = "FreezeAccount";
    let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account",
        method_name
    )))?;
    let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint",
        method_name
    )))?;
    if is_multisig(&accounts, 3) {
        let mint_freeze_authority_pubkey = accounts.get(2).ok_or(
            SolanaError::AccountNotFound(format!("{}.mint_freeze_authority_pubkey", method_name)),
        )?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "mint": mint,
                "mint_freeze_authority_pubkey": mint_freeze_authority_pubkey,
                "signers": signers,
            }),
            json!({
                "account": account,
                "mint": mint,
            })
        ))
    } else {
        let mint_freeze_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(
            format!("{}.mint_freeze_authority_pubkey", method_name),
        ))?;
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "mint": mint,
                "mint_freeze_authority_pubkey": mint_freeze_authority_pubkey,
            }),
            json!({
                "account": account,
                "mint": mint,
            })
        ))
    }
}

fn thaw_account(accounts: Vec<String>) -> Result<Value> {
    let method_name = "ThawAccount";
    let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.account",
        method_name
    )))?;
    let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint",
        method_name
    )))?;
    if is_multisig(&accounts, 3) {
        let mint_freeze_authority_pubkey = accounts.get(2).ok_or(
            SolanaError::AccountNotFound(format!("{}.mint_freeze_authority_pubkey", method_name)),
        )?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "mint": mint,
                "mint_freeze_authority_pubkey": mint_freeze_authority_pubkey,
                "signers": signers,
            }),
            json!({
                "account": account,
                "mint": mint,
            })
        ))
    } else {
        let mint_freeze_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(
            format!("{}.mint_freeze_authority_pubkey", method_name),
        ))?;
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "mint": mint,
                "mint_freeze_authority_pubkey": mint_freeze_authority_pubkey,
            }),
            json!({
                "account": account,
                "mint": mint,
            })
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
        let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
            "{}.mint",
            method_name
        )))?;
        let recipient = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.recipient",
            method_name
        )))?;
        let owner = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
            "{}.owner",
            method_name
        )))?;
        let signers = &accounts[4..];
        let amount = amount.to_string();
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "mint": mint,
                "recipient": recipient,
                "owner": owner,
                "signers": signers,
                "decimals": decimals,
                "amount": amount,
            }),
            json!({
                "account": account,
                "mint": mint,
                "recipient": recipient,
                "decimals": decimals,
                "amount": amount,
            })
        ))
    } else {
        let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
            "{}.account",
            method_name
        )))?;
        let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
            "{}.mint",
            method_name
        )))?;
        let recipient = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.recipient",
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
                "mint": mint,
                "recipient": recipient,
                "owner": owner,
                "decimals": decimals,
                "amount": amount,
            }),
            json!({
                "account": account,
                "mint": mint,
                "recipient": recipient,
                "decimals": decimals,
                "amount": amount,
            })
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
        let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
            "{}.mint",
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
        let signers = &accounts[4..];
        let amount = amount.to_string();
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "mint": mint,
                "delegate": delegate,
                "owner": owner,
                "signers": signers,
                "decimals": decimals,
                "amount": amount,
            }), json!({
                "account": account,
                "mint": mint,
                "delegate": delegate,
                "decimals": decimals,
                "amount": amount,
            })
        ))
    } else {
        let account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
            "{}.account",
            method_name
        )))?;
        let mint = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
            "{}.mint",
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
                "mint": mint,
                "delegate": delegate,
                "owner": owner,
                "decimals": decimals,
                "amount": amount,
            }),
            json!({
                "account": account,
                "mint": mint,
                "delegate": delegate,
                "decimals": decimals,
                "amount": amount,
            })
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
        let mint_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.mint_authority_pubkey",
            method_name
        )))?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "mint": mint,
                "mint_to_account": mint_to_account,
                "mint_authority_pubkey": mint_authority_pubkey,
                "signers": signers,
                "decimals": decimals,
                "amount": amount,
            }), json!({
                "mint": mint,
                "mint_to_account": mint_to_account,
                "decimals": decimals,
                "amount": amount,
            })
        ))
    } else {
        let mint_authority_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.mint_authority_pubkey",
            method_name
        )))?;
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "mint": mint,
                "mint_to_account": mint_to_account,
                "mint_authority_pubkey": mint_authority_pubkey,
                "decimals": decimals,
                "amount": amount,
            }),
            json!({
                "mint": mint,
                "mint_to_account": mint_to_account,
                "decimals": decimals,
                "amount": amount,
            })
        ))
    }
}

fn burn_checked(accounts: Vec<String>, decimals: u8, amount: u64) -> Result<Value> {
    let method_name = "BurnChecked";
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
        let owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
            "{}.owner",
            method_name
        )))?;
        let signers = &accounts[3..];
        Ok(template_instruction(
            PROGRAM_NAME,
            method_name,
            json!({
                "account": account,
                "mint": mint,
                "owner": owner,
                "signers": signers,
                "decimals": decimals,
                "amount": amount,
            }),
            json!({
                "account": account,
                "mint": mint,
                "decimals": decimals,
                "amount": amount,
            })
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
                "decimals": decimals,
                "amount": amount,
            }),
            json!({
                "account": account,
                "mint": mint,
                "decimals": decimals,
                "amount": amount,
            })
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
    let sysver_rent = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
        "{}.sysver_rent",
        method_name
    )))?;
    let owner = owner.to_string();
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "account": account,
            "mint": mint,
            "sysver_rent": sysver_rent,
            "owner": owner,
        }),
        json!({
            "account": account,
            "mint": mint,
        })
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
        json!({
            "account_to_sync": account_to_sync,
        })
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
        json!({
            "account": account,
            "mint": mint,
        })
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
        json!({
            "multisig_account": multisig_account,
            "attendees": attendees,
            "required_signatures": required_signatures,
        })
    ))
}

fn initialize_mint_2(
    accounts: Vec<String>,
    mint_authority_pubkey: Pubkey,
    decimals: u8,
    freeze_authority_pubkey: COption<Pubkey>,
) -> Result<Value> {
    let method_name = "InitializeMint2";
    let mint = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
        "{}.mint",
        method_name
    )))?;
    let mint_authority_pubkey = mint_authority_pubkey.to_string();
    let freeze_authority_pubkey = map_coption_to_option(freeze_authority_pubkey.map(|v| v.to_string()));
    Ok(template_instruction(
        PROGRAM_NAME,
        method_name,
        json!({
            "mint": mint,
            "mint_authority_pubkey": mint_authority_pubkey,
            "freeze_authority_pubkey": freeze_authority_pubkey,
            "decimals": decimals,
        }),
        json!({
            "mint": mint,
            "mint_authority_pubkey": mint_authority_pubkey,
            "freeze_authority_pubkey": freeze_authority_pubkey,
            "decimals": decimals,
        })
    ))
}
