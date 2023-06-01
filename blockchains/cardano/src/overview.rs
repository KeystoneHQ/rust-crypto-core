use serde_json::{json, Value};
use crate::impl_public_struct;
use crate::traits::ToJSON;

impl_public_struct!(CardanoOverview {
    header_card: CardanoHeaderCard
});

impl ToJSON for CardanoOverview {
    fn to_json(&self) -> Value {
        self.get_header_card().to_json()
    }
}

#[derive(Debug, Clone)]
pub enum CardanoHeaderCard {
    Transfer(CardanoOverviewTransferCard),
    Stake(CardanoOverviewStakeCard),
    Withdrawal(CardanoOverviewWithdrawalCard),
}

impl CardanoHeaderCard {
    pub fn get_type(&self) -> String {
        match self {
            Self::Transfer(_) => "Transfer".to_string(),
            Self::Stake(_) => { "Stake".to_string() }
            Self::Withdrawal(_) => { "Withdrawal".to_string() }
        }
    }
    pub fn as_transfer(&self) -> Option<CardanoOverviewTransferCard> {
        match self {
            Self::Transfer(x) => Some(x.clone()),
            _ => None
        }
    }
    pub fn as_stake(&self) -> Option<CardanoOverviewStakeCard> {
        match self {
            Self::Stake(x) => Some(x.clone()),
            _ => None
        }
    }
    pub fn as_withdrawal(&self) -> Option<CardanoOverviewWithdrawalCard> {
        match self {
            Self::Withdrawal(x) => Some(x.clone()),
            _ => None
        }
    }
}

impl ToJSON for CardanoHeaderCard {
    fn to_json(&self) -> Value {
        json!({
            "header_type": self.get_type(),
            "transfer": self.as_transfer().map(|v| v.to_json()),
            "stake": self.as_stake().map(|v| v.to_json()),
            "withdrawal": self.as_withdrawal().map(|v| v.to_json())
        })
    }
}

impl_public_struct!(CardanoOverviewTransferCard {
    total_output_amount: String
});

impl ToJSON for CardanoOverviewTransferCard {
    fn to_json(&self) -> Value {
        json!({
            "total_output_amount": self.get_total_output_amount(),
        })
    }
}

impl Default for CardanoHeaderCard {
    fn default() -> Self {
        CardanoHeaderCard::Transfer(CardanoOverviewTransferCard::default())
    }
}

impl_public_struct!(CardanoOverviewStakeCard {
    stake_amount: String,
    deposit: Option<String>
});

impl ToJSON for CardanoOverviewStakeCard {
    fn to_json(&self) -> Value {
        json!({
            "stake_amount": self.get_stake_amount(),
            "deposit": self.get_deposit(),
        })
    }
}

impl_public_struct!(CardanoOverviewWithdrawalCard {
    reward_amount: String,
    deposit_reclaim: Option<String>,
    reward_account: Option<String>
});

impl ToJSON for CardanoOverviewWithdrawalCard {
    fn to_json(&self) -> Value {
        json!({
            "reward_amount": self.get_reward_amount(),
            "deposit_reclaim": self.get_deposit_reclaim(),
            "reward_account": self.get_reward_account(),
        })
    }
}