use crate::error::{Result, SolanaError};
use crate::types::resolvers::template_instruction;
use serde_json::{json, Value};
use solana_program::program_option::COption;
use spl_token_swap::curve::base::CurveType;
use spl_token_swap::instruction::{SwapInstruction};
use crate::error::SolanaError::UnknownInstruction;

pub fn resolve(instruction: SwapInstruction, accounts: Vec<String>) -> Result<Value> {
    let program_name = "TokenSwap";
    match instruction {
        SwapInstruction::Initialize(initialize) => {
            let method_name = "Initialize";
            let token_swap = accounts
                .get(0)
                .ok_or(SolanaError::AccountNotFound(format!("{}.token_swap", method_name)))?;
            let swap_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.swap_authority", method_name
            )))?;
            let token_a = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_a", method_name
            )))?;
            let token_b = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_b", method_name
            )))?;
            let pool_token_mint = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
                "{}.pool_token_mint", method_name
            )))?;
            let pool_token_account_1 = accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
                "{}.pool_token_account_1", method_name
            )))?;
            let pool_token_account_2 = accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                "{}.pool_token_account_2", method_name
            )))?;
            let token_program_id = accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id", method_name
            )))?;
            let curve_type = match initialize.swap_curve.curve_type {
                CurveType::Offset => "offset",
                CurveType::Stable => "stable",
                CurveType::ConstantPrice => "constant_price",
                CurveType::ConstantProduct => "constant_product",
            };
            let initialize = json!({
                "fees": {
                    "trade_fee_numerator": initialize.fees.trade_fee_numerator,
                    "trade_fee_denominator": initialize.fees.trade_fee_numerator,
                    "owner_trade_fee_numerator": initialize.fees.trade_fee_numerator,
                    "owner_trade_fee_denominator": initialize.fees.trade_fee_numerator,
                    "owner_withdraw_fee_numerator": initialize.fees.trade_fee_numerator,
                    "owner_withdraw_fee_denominator": initialize.fees.trade_fee_numerator,
                    "host_fee_numerator": initialize.fees.trade_fee_numerator,
                    "host_fee_denominator": initialize.fees.trade_fee_numerator,
                    "trade_fee_numerator": initialize.fees.trade_fee_numerator,
                },
                "swap_curve": {
                    "curve_type": curve_type
                }
            });
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "token_swap": token_swap,
                    "swap_authority": swap_authority,
                    "token_a": token_a,
                    "token_b": token_b,
                    "pool_token_mint": pool_token_mint,
                    "pool_token_account_1": pool_token_account_1,
                    "pool_token_account_2": pool_token_account_2,
                    "token_program_id": token_program_id,
                    "initialize": initialize,
                }),
            ))
        }
        SwapInstruction::Swap(swap) => {
            let method_name = "Swap";
            let token_swap = accounts
                .get(0)
                .ok_or(SolanaError::AccountNotFound(format!("{}.token_swap", method_name)))?;
            let swap_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.swap_authority", method_name
            )))?;
            let user_transfer_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.user_transfer_authority", method_name
            )))?;
            let source_account = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "{}.source_account", method_name
            )))?;
            let source_token = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
                "{}.source_token", method_name
            )))?;
            let destination_token = accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
                "{}.destination_token", method_name
            )))?;
            let destination_account = accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                "{}.destination_account", method_name
            )))?;
            let pool_token_mint = accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                "{}.pool_token_mint", method_name
            )))?;
            let fee_account = accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                "{}.fee_account", method_name
            )))?;
            let token_program_id = accounts.get(9).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id", method_name
            )))?;
            let host_fee_account = accounts.get(10);
            let swap = json!({
                "amount_in": swap.amount_in,
                "minimum_amount_out": swap.minimum_amount_out,
            });
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "token_swap": token_swap,
                    "swap_authority": swap_authority,
                    "user_transfer_authority": user_transfer_authority,
                    "source_account": source_account,
                    "source_token": source_token,
                    "destination_token": destination_token,
                    "destination_account": destination_account,
                    "pool_token_mint": pool_token_mint,
                    "fee_account": fee_account,
                    "token_program_id": token_program_id,
                    "host_fee_account": host_fee_account,
                    "swap": swap,
                }),
            ))
        }
        SwapInstruction::DepositAllTokenTypes(args) => {
            let method_name = "DepositAllTokenTypes";
            let token_swap = accounts
                .get(0)
                .ok_or(SolanaError::AccountNotFound(format!("{}.token_swap", method_name)))?;
            let swap_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.swap_authority", method_name
            )))?;
            let user_transfer_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.user_transfer_authority", method_name
            )))?;
            let token_a_user_transfer_authority = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_a_user_transfer_authority", method_name
            )))?;
            let token_b_user_transfer_authority = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_b_user_transfer_authority", method_name
            )))?;
            let token_a_base_account = accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_a_base_account", method_name
            )))?;
            let token_b_base_account = accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_b_base_account", method_name
            )))?;
            let pool_mint_account = accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                "{}.pool_mint_account", method_name
            )))?;
            let pool_account = accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                "{}.pool_account", method_name
            )))?;
            let token_program_id = accounts.get(9).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id", method_name
            )))?;
            let deposit_all_token_types = json!({
                "pool_token_amount": args.pool_token_amount,
                "maximum_token_a_amount": args.maximum_token_a_amount,
                "maximum_token_b_amount": args.maximum_token_b_amount,
            });
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "token_swap": token_swap,
                    "swap_authority": swap_authority,
                    "user_transfer_authority": user_transfer_authority,
                    "token_a_user_transfer_authority": token_a_user_transfer_authority,
                    "token_b_user_transfer_authority": token_b_user_transfer_authority,
                    "token_a_base_account": token_a_base_account,
                    "token_b_base_account": token_b_base_account,
                    "pool_mint_account": pool_mint_account,
                    "pool_account": pool_account,
                    "token_program_id": token_program_id,
                    "deposit_all_token_types": deposit_all_token_types,
                }),
            ))
        }
        SwapInstruction::WithdrawAllTokenTypes(args) => {
            let method_name = "WithdrawAllTokenTypes";
            let token_swap = accounts
                .get(0)
                .ok_or(SolanaError::AccountNotFound(format!("{}.token_swap", method_name)))?;
            let swap_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.swap_authority", method_name
            )))?;
            let user_transfer_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.user_transfer_authority", method_name
            )))?;
            let pool_mint_account = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "{}.pool_mint_account", method_name
            )))?;
            let source_pool_account = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
                "{}.source_pool_account", method_name
            )))?;
            let token_a_swap_account = accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_a_swap_account", method_name
            )))?;
            let token_b_swap_account = accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_b_swap_account", method_name
            )))?;
            let token_a_user_account = accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_a_user_account", method_name
            )))?;
            let token_b_user_account = accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_b_user_account", method_name
            )))?;
            let fee_account = accounts.get(9).ok_or(SolanaError::AccountNotFound(format!(
                "{}.fee_account", method_name
            )))?;
            let token_program_id = accounts.get(10).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id", method_name
            )))?;
            let withdraw_all_token_types = json!({
                "pool_token_amount": args.pool_token_amount,
                "maximum_token_a_amount": args.maximum_token_a_amount,
                "maximum_token_b_amount": args.maximum_token_b_amount,
            });
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "token_swap": token_swap,
                    "swap_authority": swap_authority,
                    "user_transfer_authority": user_transfer_authority,
                    "pool_mint_account": pool_mint_account,
                    "token_a_swap_account": token_a_swap_account,
                    "token_b_swap_account": token_b_swap_account,
                    "token_a_user_account": token_a_user_account,
                    "token_b_user_account": token_b_user_account,
                    "fee_account": fee_account,
                    "token_program_id": token_program_id,
                    "withdraw_all_token_types": withdraw_all_token_types,
                }),
            ))
        }
        SwapInstruction::DepositSingleTokenTypeExactAmountIn(args) => {
            let method_name = "DepositSingleTokenTypeExactAmountIn";
            let token_swap = accounts
                .get(0)
                .ok_or(SolanaError::AccountNotFound(format!("{}.token_swap", method_name)))?;
            let swap_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.swap_authority", method_name
            )))?;
            let user_transfer_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.user_transfer_authority", method_name
            )))?;
            let token_source_account = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_source_account", method_name
            )))?;
            let token_a_swap_account = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_a_swap_account", method_name
            )))?;
            let token_b_swap_account = accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_b_swap_account", method_name
            )))?;
            let pool_mint_account = accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                "{}.pool_mint_account", method_name
            )))?;
            let pool_account = accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                "{}.pool_account", method_name
            )))?;
            let token_program_id = accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id", method_name
            )))?;
            let arguments = json!({
                "source_token_amount": args.source_token_amount,
                "minimum_pool_token_amount": args.minimum_pool_token_amount,
            });
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "token_swap": token_swap,
                    "swap_authority": swap_authority,
                    "user_transfer_authority": user_transfer_authority,
                    "token_source_account": token_source_account,
                    "token_a_swap_account": token_a_swap_account,
                    "token_b_swap_account": token_b_swap_account,
                    "pool_mint_account": pool_mint_account,
                    "fee_account": fee_account,
                    "token_program_id": token_program_id,
                    "arguments": arguments,
                }),
            ))
        }
        SwapInstruction::WithdrawSingleTokenTypeExactAmountOut(args) => {
            let method_name = "WithdrawSingleTokenTypeExactAmountOut";
            let token_swap = accounts
                .get(0)
                .ok_or(SolanaError::AccountNotFound(format!("{}.token_swap", method_name)))?;
            let swap_authority = accounts.get(1).ok_or(SolanaError::AccountNotFound(format!(
                "{}.swap_authority", method_name
            )))?;
            let user_transfer_authority = accounts.get(2).ok_or(SolanaError::AccountNotFound(format!(
                "{}.user_transfer_authority", method_name
            )))?;
            let pool_mint_account = accounts.get(3).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_source_account", method_name
            )))?;
            let source_pool_account = accounts.get(4).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_a_swap_account", method_name
            )))?;
            let token_a_swap_account = accounts.get(5).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_b_swap_account", method_name
            )))?;
            let token_b_swap_account = accounts.get(6).ok_or(SolanaError::AccountNotFound(format!(
                "{}.pool_mint_account", method_name
            )))?;
            let token_user_account = accounts.get(7).ok_or(SolanaError::AccountNotFound(format!(
                "{}.pool_account", method_name
            )))?;
            let fee_account = accounts.get(8).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id", method_name
            )))?;
            let token_program_id = accounts.get(9).ok_or(SolanaError::AccountNotFound(format!(
                "{}.token_program_id", method_name
            )))?;
            let arguments = json!({
                "source_token_amount": args.destination_token_amount,
                "maximum_pool_token_amount": args.maximum_pool_token_amount,
            });
            Ok(template_instruction(
                program_name,
                method_name,
                json!({
                    "token_swap": token_swap,
                    "swap_authority": swap_authority,
                    "user_transfer_authority": user_transfer_authority,
                    "pool_mint_account": pool_mint_account,
                    "source_pool_account": source_pool_account,
                    "token_a_swap_account": token_a_swap_account,
                    "token_b_swap_account": token_b_swap_account,
                    "token_user_account": token_user_account,
                    "fee_account": fee_account,
                    "token_program_id": token_program_id,
                    "arguments": arguments,
                }),
            ))
        }
    }
}
