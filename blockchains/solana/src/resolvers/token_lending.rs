use crate::error::{Result, SolanaError};
use crate::resolvers::template_instruction;
use serde_json::{json, Value};
use spl_token_lending::instruction::LendingInstruction;

pub fn resolve(instruction: LendingInstruction, accounts: Vec<String>) -> Result<Value> {
    let program_name = "TokenLending";
    match instruction {
        LendingInstruction::InitLendingMarket {
            owner,
            quote_currency,
        } => {
            let method_name = "InitLendingMarket";
            let lending_market_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_account", method_name,),
            ))?;
            let rent_sysvar = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.account",
                method_name
            )))?;
            let token_program_id = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id",
                method_name
            )))?;
            let oracle_program_id = accounts.get(3).ok_or(SolanaError::AccountNotFound(
                format!("{}.oracle_program_id", method_name),
            ))?;
            let owner = owner.to_string();
            let quote_currency = std::str::from_utf8(&quote_currency)
                .map_err(|_| SolanaError::InvalidData(format!("{}.quote_currency", method_name)))?;
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "lending_market_account": lending_market_account,
                    "rent_sysvar": rent_sysvar,
                    "token_program_id": token_program_id,
                    "oracle_program_id": oracle_program_id,
                    "owner": owner,
                    "quote_currency": quote_currency,
                }),
            ))
        }
        LendingInstruction::SetLendingMarketOwner { new_owner } => {
            let method_name = "SetLendingMarketOwner";
            let lending_market_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_account", method_name,),
            ))?;
            let current_owner = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.current_owner",
                method_name
            )))?;
            let new_owner = new_owner.to_string();
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "lending_market_account": lending_market_account,
                    "current_owner": current_owner,
                    "new_owner": new_owner,
                }),
            ))
        }
        LendingInstruction::InitReserve {
            liquidity_amount,
            config,
        } => {
            let method_name = "SetLendingMarketOwner";
            let source_liquidity_pubkey = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_account", method_name,),
            ))?;
            let destination_collateral_pubkey = accounts.get(1).ok_or(
                SolanaError::AccountNotFound(format!("{}.current_owner", method_name)),
            )?;
            let reserve_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.reserve_liquidity_mint_pubkey",
                method_name
            )))?;
            let reserve_liquidity_mint_pubkey = accounts.get(3).ok_or(
                SolanaError::AccountNotFound(format!("{}.current_owner", method_name)),
            )?;
            let reserve_liquidity_supply_pubkey = accounts.get(4).ok_or(
                SolanaError::AccountNotFound(format!("{}.current_owner", method_name)),
            )?;
            let reserve_liquidity_fee_receiver_pubkey = accounts.get(5).ok_or(
                SolanaError::AccountNotFound(format!("{}.current_owner", method_name)),
            )?;
            let reserve_collateral_mint_pubkey = accounts.get(6).ok_or(
                SolanaError::AccountNotFound(format!("{}.current_owner", method_name)),
            )?;
            let reserve_collateral_supply_pubkey = accounts.get(7).ok_or(
                SolanaError::AccountNotFound(format!("{}.current_owner", method_name)),
            )?;
            let pyth_product_pubkey = accounts.get(8).ok_or(SolanaError::AccountNotFound(
                format!("{}.current_owner", method_name),
            ))?;
            let pyth_price_pubkey = accounts.get(9).ok_or(SolanaError::AccountNotFound(
                format!("{}.current_owner", method_name),
            ))?;
            let lending_market_pubkey =
                accounts
                    .get(10)
                    .ok_or(SolanaError::AccountNotFound(format!(
                        "{}.current_owner",
                        method_name
                    )))?;
            let lending_market_authority_pubkey =
                accounts
                    .get(11)
                    .ok_or(SolanaError::AccountNotFound(format!(
                        "{}.current_owner",
                        method_name
                    )))?;
            let lending_market_owner_pubkey =
                accounts
                    .get(12)
                    .ok_or(SolanaError::AccountNotFound(format!(
                        "{}.current_owner",
                        method_name
                    )))?;
            let user_transfer_authority_pubkey =
                accounts
                    .get(13)
                    .ok_or(SolanaError::AccountNotFound(format!(
                        "{}.current_owner",
                        method_name
                    )))?;
            let sysvar_clock = accounts
                .get(14)
                .ok_or(SolanaError::AccountNotFound(format!(
                    "{}.current_owner",
                    method_name
                )))?;
            let sysvar_rent = accounts
                .get(15)
                .ok_or(SolanaError::AccountNotFound(format!(
                    "{}.current_owner",
                    method_name
                )))?;
            let token_program_id =
                accounts
                    .get(16)
                    .ok_or(SolanaError::AccountNotFound(format!(
                        "{}.current_owner",
                        method_name
                    )))?;
            let liquidity_amount = liquidity_amount.to_string();
            let reserve_config = json!({
                "optimal_utilization_rate": config.optimal_utilization_rate,
                "loan_to_value_ratio": config.loan_to_value_ratio,
                "liquidation_bonus": config.liquidation_bonus,
                "liquidation_threshold": config.liquidation_threshold,
                "min_borrow_rate": config.min_borrow_rate,
                "optimal_borrow_rate": config.optimal_borrow_rate,
                "max_borrow_rate": config.max_borrow_rate,
                "fees": {
                    "borrow_fee_wad": config.fees.borrow_fee_wad.to_string(),
                    "flash_loan_fee_wad": config.fees.flash_loan_fee_wad.to_string(),
                    "host_fee_percentage": config.fees.host_fee_percentage.to_string(),
                },
            });
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "source_liquidity_pubkey": source_liquidity_pubkey,
                    "destination_collateral_pubkey": destination_collateral_pubkey,
                    "reserve_pubkey": reserve_pubkey,
                    "reserve_liquidity_mint_pubkey": reserve_liquidity_mint_pubkey,
                    "reserve_liquidity_supply_pubkey": reserve_liquidity_supply_pubkey,
                    "reserve_liquidity_fee_receiver_pubkey": reserve_liquidity_fee_receiver_pubkey,
                    "reserve_collateral_mint_pubkey": reserve_collateral_mint_pubkey,
                    "reserve_collateral_supply_pubkey": reserve_collateral_supply_pubkey,
                    "pyth_product_pubkey": pyth_product_pubkey,
                    "pyth_price_pubkey": pyth_price_pubkey,
                    "lending_market_pubkey": lending_market_pubkey,
                    "lending_market_authority_pubkey": lending_market_authority_pubkey,
                    "lending_market_owner_pubkey": lending_market_owner_pubkey,
                    "user_transfer_authority_pubkey": user_transfer_authority_pubkey,
                    "sysvar_clock": sysvar_clock,
                    "sysvar_rent": sysvar_rent,
                    "token_program_id": token_program_id,
                    "liquidity_amount": liquidity_amount,
                    "reserve_config": reserve_config,
                }),
            ))
        }
        LendingInstruction::RefreshReserve => {
            let method_name = "RefreshReserve";
            let reserve_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(format!(
                "{}.reserve_account",
                method_name,
            )))?;
            let reserve_liquidity_oracle_account =
                accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.reserve_liquidity_oracle_account",
                    method_name
                )))?;
            let sysvar_clock = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.sysvar_clock",
                method_name
            )))?;
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "reserve_account": reserve_account,
                    "reserve_liquidity_oracle_account": reserve_liquidity_oracle_account,
                    "sysvar_clock": sysvar_clock,
                }),
            ))
        }
        LendingInstruction::DepositReserveLiquidity { liquidity_amount } => {
            let method_name = "DepositReserveLiquidity";
            let source_liquidity_pubkey = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.source_liquidity_pubkey", method_name,),
            ))?;
            let destination_collateral_pubkey =
                accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.destination_collateral_pubkey",
                    method_name
                )))?;
            let reserve_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.reserve_pubkey",
                method_name
            )))?;
            let reserve_liquidity_supply_pubkey =
                accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.reserve_liquidity_supply_pubkey",
                    method_name
                )))?;
            let reserve_collateral_mint_pubkey =
                accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.reserve_collateral_mint_pubkey",
                    method_name
                )))?;
            let lending_market_pubkey = accounts.get(5).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_pubkey", method_name),
            ))?;
            let lending_market_authority_pubkey =
                accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.lending_market_authority_pubkey",
                    method_name
                )))?;
            let user_transfer_authority_pubkey =
                accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.user_transfer_authority_pubkey",
                    method_name
                )))?;
            let sysvar_clock = accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                "{}.sysvar_clock",
                method_name
            )))?;
            let token_program_id = accounts.get(9).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id",
                method_name
            )))?;
            let liquidity_amount = liquidity_amount.to_string();
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "source_liquidity_pubkey": source_liquidity_pubkey,
                    "destination_collateral_pubkey": destination_collateral_pubkey,
                    "reserve_pubkey": reserve_pubkey,
                    "reserve_liquidity_supply_pubkey": reserve_liquidity_supply_pubkey,
                    "reserve_collateral_mint_pubkey": reserve_collateral_mint_pubkey,
                    "lending_market_pubkey": lending_market_pubkey,
                    "lending_market_authority_pubkey": lending_market_authority_pubkey,
                    "user_transfer_authority_pubkey": user_transfer_authority_pubkey,
                    "sysvar_clock": sysvar_clock,
                    "token_program_id": token_program_id,
                    "liquidity_amount": liquidity_amount,
                }),
            ))
        }
        LendingInstruction::RedeemReserveCollateral { collateral_amount } => {
            let method_name = "RedeemReserveCollateral";
            let source_collateral_pubkey = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.source_collateral_pubkey", method_name,),
            ))?;
            let destination_liquidity_pubkey =
                accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.destination_liquidity_pubkey",
                    method_name
                )))?;
            let reserve_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.reserve_pubkey",
                method_name
            )))?;
            let reserve_collateral_mint_pubkey =
                accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.reserve_collateral_mint_pubkey",
                    method_name
                )))?;
            let reserve_liquidity_supply_pubkey =
                accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.reserve_liquidity_supply_pubkey",
                    method_name
                )))?;
            let lending_market_pubkey = accounts.get(5).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_pubkey", method_name),
            ))?;
            let lending_market_authority_pubkey =
                accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.lending_market_authority_pubkey",
                    method_name
                )))?;
            let user_transfer_authority_pubkey =
                accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.user_transfer_authority_pubkey",
                    method_name
                )))?;
            let sysvar_clock = accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                "{}.sysvar_clock",
                method_name
            )))?;
            let token_program_id = accounts.get(9).ok_or(SolanaError::AccountNotFound(format!(
                "{}.sysvar_clock",
                method_name
            )))?;

            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "source_collateral_pubkey": source_collateral_pubkey,
                    "destination_liquidity_pubkey": destination_liquidity_pubkey,
                    "reserve_pubkey": reserve_pubkey,
                    "reserve_liquidity_supply_pubkey": reserve_liquidity_supply_pubkey,
                    "reserve_collateral_mint_pubkey": reserve_collateral_mint_pubkey,
                    "lending_market_pubkey": lending_market_pubkey,
                    "lending_market_authority_pubkey": lending_market_authority_pubkey,
                    "user_transfer_authority_pubkey": user_transfer_authority_pubkey,
                    "sysvar_clock": sysvar_clock,
                    "token_program_id": token_program_id,
                    "collateral_amount": collateral_amount.to_string(),
                }),
            ))
        }
        LendingInstruction::InitObligation => {
            let method_name = "InitObligation";
            let obligation_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.obligation_account", method_name,),
            ))?;
            let lending_market_account = accounts.get(1).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_account", method_name),
            ))?;
            let obligation_owner = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.obligation_owner",
                method_name
            )))?;
            let sysvar_clock = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "{}.sysvar_clock",
                method_name
            )))?;
            let sysvar_rent = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
                "{}.sysvar_rent",
                method_name
            )))?;
            let token_program_id = accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id",
                method_name
            )))?;

            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "obligation_account": obligation_account,
                    "lending_market_account": lending_market_account,
                    "obligation_owner": obligation_owner,
                    "sysvar_clock": sysvar_clock,
                    "sysvar_rent": sysvar_rent,
                    "token_program_id": token_program_id,
                }),
            ))
        }
        LendingInstruction::RefreshObligation => {
            let method_name = "RefreshObligation";
            let obligation_account = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.obligation_account", method_name,),
            ))?;
            let sysvar_clock = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.sysvar_clock",
                method_name
            )))?;
            let keys = &accounts[2..];

            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "obligation_account": obligation_account,
                    "sysvar_clock": sysvar_clock,
                    "keys": keys,
                }),
            ))
        }
        LendingInstruction::DepositObligationCollateral { collateral_amount } => {
            let method_name = "DepositObligationCollateral";
            let source_collateral_pubkey = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.source_collateral_pubkey", method_name,),
            ))?;
            let destination_collateral_pubkey =
                accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.destination_collateral_pubkey",
                    method_name
                )))?;
            let deposit_reserve_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                format!("{}.deposit_reserve_pubkey", method_name),
            ))?;
            let obligation_pubkey = accounts.get(3).ok_or(SolanaError::AccountNotFound(
                format!("{}.obligation_pubkey", method_name),
            ))?;
            let lending_market_pubkey = accounts.get(4).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_pubkey", method_name),
            ))?;
            let obligation_owner_pubkey = accounts.get(5).ok_or(SolanaError::AccountNotFound(
                format!("{}.obligation_owner_pubkey", method_name),
            ))?;
            let user_transfer_authority_pubkey =
                accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.user_transfer_authority_pubkey",
                    method_name
                )))?;
            let sysvar_clock = accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                "{}.sysvar_clock",
                method_name
            )))?;
            let token_program_id = accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id",
                method_name
            )))?;

            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "source_collateral_pubkey": source_collateral_pubkey,
                    "destination_collateral_pubkey": destination_collateral_pubkey,
                    "deposit_reserve_pubkey": deposit_reserve_pubkey,
                    "obligation_pubkey": obligation_pubkey,
                    "lending_market_pubkey": lending_market_pubkey,
                    "obligation_owner_pubkey": obligation_owner_pubkey,
                    "user_transfer_authority_pubkey": user_transfer_authority_pubkey,
                    "sysvar_clock": sysvar_clock,
                    "token_program_id": token_program_id,
                    "collateral_amount": collateral_amount.to_string(),
                }),
            ))
        }
        LendingInstruction::WithdrawObligationCollateral { collateral_amount } => {
            let method_name = "WithdrawObligationCollateral";
            let source_collateral_pubkey = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.source_collateral_pubkey", method_name,),
            ))?;
            let destination_collateral_pubkey =
                accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.destination_collateral_pubkey",
                    method_name
                )))?;
            let withdraw_reserve_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                format!("{}.deposit_reserve_pubkey", method_name),
            ))?;
            let obligation_pubkey = accounts.get(3).ok_or(SolanaError::AccountNotFound(
                format!("{}.obligation_pubkey", method_name),
            ))?;
            let lending_market_pubkey = accounts.get(4).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_pubkey", method_name),
            ))?;
            let lending_market_authority_pubkey =
                accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.lending_market_authority_pubkey",
                    method_name
                )))?;
            let obligation_owner_pubkey = accounts.get(6).ok_or(SolanaError::AccountNotFound(
                format!("{}.obligation_owner_pubkey", method_name),
            ))?;
            let sysvar_clock = accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                "{}.sysvar_clock",
                method_name
            )))?;
            let token_program_id = accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id",
                method_name
            )))?;

            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "source_collateral_pubkey": source_collateral_pubkey,
                    "destination_collateral_pubkey": destination_collateral_pubkey,
                    "withdraw_reserve_pubkey": withdraw_reserve_pubkey,
                    "obligation_pubkey": obligation_pubkey,
                    "lending_market_pubkey": lending_market_pubkey,
                    "lending_market_authority_pubkey": lending_market_authority_pubkey,
                    "obligation_owner_pubkey": obligation_owner_pubkey,
                    "sysvar_clock": sysvar_clock,
                    "token_program_id": token_program_id,
                    "collateral_amount": collateral_amount.to_string(),
                }),
            ))
        }
        LendingInstruction::BorrowObligationLiquidity { liquidity_amount } => {
            let method_name = "BorrowObligationLiquidity";
            let source_liquidity_pubkey = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.source_liquidity_pubkey", method_name,),
            ))?;
            let destination_liquidity_pubkey =
                accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.destination_liquidity_pubkey",
                    method_name
                )))?;
            let borrow_reserve_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                format!("{}.borrow_reserve_pubkey", method_name),
            ))?;
            let borrow_reserve_liquidity_fee_receiver_pubkey =
                accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.borrow_reserve_liquidity_fee_receiver_pubkey",
                    method_name
                )))?;
            let obligation_pubkey = accounts.get(4).ok_or(SolanaError::AccountNotFound(
                format!("{}.obligation_pubkey", method_name),
            ))?;
            let lending_market_pubkey = accounts.get(5).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_pubkey", method_name),
            ))?;
            let lending_market_authority_pubkey =
                accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.lending_market_authority_pubkey",
                    method_name
                )))?;
            let obligation_owner_pubkey = accounts.get(7).ok_or(SolanaError::AccountNotFound(
                format!("{}.obligation_owner_pubkey", method_name),
            ))?;
            let sysvar_clock = accounts.get(9).ok_or(SolanaError::AccountNotFound(format!(
                "{}.sysvar_clock",
                method_name
            )))?;
            let token_program_id = accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id",
                method_name
            )))?;
            let host_fee_receiver_pubkey = accounts.get(10);

            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "source_liquidity_pubkey": source_liquidity_pubkey,
                    "destination_liquidity_pubkey": destination_liquidity_pubkey,
                    "borrow_reserve_pubkey": borrow_reserve_pubkey,
                    "borrow_reserve_liquidity_fee_receiver_pubkey": borrow_reserve_liquidity_fee_receiver_pubkey,
                    "obligation_pubkey": obligation_pubkey,
                    "lending_market_pubkey": lending_market_pubkey,
                    "lending_market_authority_pubkey": lending_market_authority_pubkey,
                    "obligation_owner_pubkey": obligation_owner_pubkey,
                    "sysvar_clock": sysvar_clock,
                    "token_program_id": token_program_id,
                    "host_fee_receiver_pubkey": host_fee_receiver_pubkey,
                    "liquidity_amount": liquidity_amount.to_string(),
                }),
            ))
        }
        LendingInstruction::RepayObligationLiquidity { liquidity_amount } => {
            let method_name = "RepayObligationLiquidity";

            let source_liquidity_pubkey = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.source_liquidity_pubkey", method_name,),
            ))?;
            let destination_liquidity_pubkey =
                accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.destination_liquidity_pubkey",
                    method_name
                )))?;
            let repay_reserve_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                format!("{}.repay_reserve_pubkey", method_name),
            ))?;
            let obligation_pubkey = accounts.get(3).ok_or(SolanaError::AccountNotFound(
                format!("{}.obligation_pubkey", method_name),
            ))?;
            let lending_market_pubkey = accounts.get(4).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_pubkey", method_name),
            ))?;
            let user_transfer_authority_pubkey =
                accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.lending_market_authority_pubkey",
                    method_name
                )))?;
            let sysvar_clock = accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                "{}.sysvar_clock",
                method_name
            )))?;
            let token_program_id = accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id",
                method_name
            )))?;

            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "source_liquidity_pubkey": source_liquidity_pubkey,
                    "destination_liquidity_pubkey": destination_liquidity_pubkey,
                    "repay_reserve_pubkey": repay_reserve_pubkey,
                    "obligation_pubkey": obligation_pubkey,
                    "lending_market_pubkey": lending_market_pubkey,
                    "user_transfer_authority_pubkey": user_transfer_authority_pubkey,
                    "sysvar_clock": sysvar_clock,
                    "token_program_id": token_program_id,
                    "liquidity_amount": liquidity_amount.to_string(),
                }),
            ))
        }
        LendingInstruction::LiquidateObligation { liquidity_amount } => {
            let method_name = "LiquidateObligation";
            let source_liquidity_pubkey = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.source_liquidity_pubkey", method_name,),
            ))?;
            let destination_collateral_pubkey =
                accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.destination_collateral_pubkey",
                    method_name
                )))?;
            let repay_reserve_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(
                format!("{}.repay_reserve_pubkey", method_name),
            ))?;
            let repay_reserve_liquidity_supply_pubkey =
                accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.repay_reserve_liquidity_supply_pubkey",
                    method_name
                )))?;
            let withdraw_reserve_pubkey = accounts.get(4).ok_or(SolanaError::AccountNotFound(
                format!("{}.withdraw_reserve_pubkey", method_name),
            ))?;
            let withdraw_reserve_collateral_supply_pubkey =
                accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.withdraw_reserve_collateral_supply_pubkey",
                    method_name
                )))?;
            let obligation_pubkey = accounts.get(6).ok_or(SolanaError::AccountNotFound(
                format!("{}.obligation_pubkey", method_name),
            ))?;
            let lending_market_pubkey = accounts.get(7).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_pubkey", method_name),
            ))?;
            let lending_market_authority_pubkey =
                accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.lending_market_authority_pubkey",
                    method_name
                )))?;
            let user_transfer_authority_pubkey =
                accounts.get(9).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.user_transfer_authority_pubkey",
                    method_name
                )))?;
            let sysvar_clock = accounts
                .get(10)
                .ok_or(SolanaError::AccountNotFound(format!(
                    "{}.sysvar_clock",
                    method_name
                )))?;
            let token_program_id =
                accounts
                    .get(11)
                    .ok_or(SolanaError::AccountNotFound(format!(
                        "{}.token_program_id",
                        method_name
                    )))?;

            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "source_liquidity_pubkey": source_liquidity_pubkey,
                    "destination_liquidity_pubkey": destination_collateral_pubkey,
                    "repay_reserve_pubkey": repay_reserve_pubkey,
                    "repay_reserve_liquidity_supply_pubkey": repay_reserve_liquidity_supply_pubkey,
                    "withdraw_reserve_pubkey": withdraw_reserve_pubkey,
                    "withdraw_reserve_collateral_supply_pubkey": withdraw_reserve_collateral_supply_pubkey,
                    "obligation_pubkey": obligation_pubkey,
                    "lending_market_pubkey": lending_market_pubkey,
                    "lending_market_authority_pubkey": lending_market_authority_pubkey,
                    "user_transfer_authority_pubkey": user_transfer_authority_pubkey,
                    "sysvar_clock": sysvar_clock,
                    "token_program_id": token_program_id,
                    "liquidity_amount": liquidity_amount.to_string(),
                }),
            ))
        }
        LendingInstruction::FlashLoan { amount } => {
            let method_name = "FlashLoan";
            let source_liquidity_pubkey = accounts.get(0).ok_or(SolanaError::AccountNotFound(
                format!("{}.source_liquidity_pubkey", method_name,),
            ))?;
            let destination_liquidity_pubkey =
                accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.destination_liquidity_pubkey",
                    method_name
                )))?;
            let reserve_pubkey = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.reserve_pubkey",
                method_name
            )))?;
            let reserve_liquidity_fee_receiver_pubkey =
                accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.reserve_liquidity_fee_receiver_pubkey",
                    method_name
                )))?;
            let host_fee_receiver_pubkey = accounts.get(4).ok_or(SolanaError::AccountNotFound(
                format!("{}.host_fee_receiver_pubkey", method_name),
            ))?;
            let lending_market_pubkey = accounts.get(5).ok_or(SolanaError::AccountNotFound(
                format!("{}.lending_market_pubkey", method_name),
            ))?;
            let lending_market_authority_pubkey =
                accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.lending_market_authority_pubkey",
                    method_name
                )))?;
            let token_program_id = accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id",
                method_name
            )))?;
            let flash_loan_receiver_program_id =
                accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                    "{}.flash_loan_receiver_program_id",
                    method_name
                )))?;
            let flash_loan_receiver_program_accounts = &accounts[9..];

            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "source_liquidity_pubkey": source_liquidity_pubkey,
                    "destination_liquidity_pubkey": destination_liquidity_pubkey,
                    "reserve_pubkey": reserve_pubkey,
                    "reserve_liquidity_fee_receiver_pubkey": reserve_liquidity_fee_receiver_pubkey,
                    "host_fee_receiver_pubkey": host_fee_receiver_pubkey,
                    "lending_market_pubkey": lending_market_pubkey,
                    "lending_market_authority_pubkey": lending_market_authority_pubkey,
                    "token_program_id": token_program_id,
                    "flash_loan_receiver_program_id": flash_loan_receiver_program_id,
                    "flash_loan_receiver_program_accounts": flash_loan_receiver_program_accounts,
                    "amount": amount.to_string(),
                }),
            ))
        }
    }
}
