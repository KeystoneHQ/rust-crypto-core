use serde_json::{json, Value};
use crate::impl_public_struct;
use crate::traits::ToJSON;

impl_public_struct!(CardanoDetail {
    total_input_amount: String,
    total_output_amount: String,
    deposit_reclaim: Option<String>,
    deposit: Option<String>,
    stake_content: Option<Vec<CardanoDetailStakeAction>>
});

impl ToJSON for CardanoDetail {
    fn to_json(&self) -> Value {
        let stake_content = self.get_stake_content().map(|v| v.iter().map(|v| v.to_json()).collect::<Vec<Value>>());
        json!({
            "total_input_amount": self.get_total_input_amount(),
            "total_output_amount": self.get_total_output_amount(),
            "deposit_reclaim": self.get_deposit_reclaim(),
            "deposit": self.get_deposit(),
            "stake_content": stake_content,
        })
    }
}

#[derive(Clone, Debug)]
pub enum CardanoDetailStakeAction {
    // special scenario
    // user delegation to a pool, contain a Delegation and an optional matched Registration
    Stake(CardanoStake),
    // user withdraw from a pool, contain a Withdrawal and an optional matched Deregistration.
    // we treat a Deregistration as a kind of Withdrawal which reward_amount is 0
    Withdrawal(CardanoWithdrawal),
    //Plain action
    Registration(CardanoRegistration),
}

impl CardanoDetailStakeAction {
    pub fn get_type(&self) -> String {
        match self {
            Self::Stake(_) => "Stake".to_string(),
            Self::Withdrawal(_) => "Withdrawal".to_string(),
            Self::Registration(_) => "Registration".to_string(),
        }
    }
    pub fn as_stake(&self) -> Option<CardanoStake> {
        match self {
            Self::Stake(x) => Some(x.clone()),
            _ => None
        }
    }
    pub fn as_withdrawal(&self) -> Option<CardanoWithdrawal> {
        match self {
            Self::Withdrawal(x) => Some(x.clone()),
            _ => None
        }
    }
    pub fn as_registration(&self) -> Option<CardanoRegistration> {
        match self {
            Self::Registration(x) => Some(x.clone()),
            _ => None
        }
    }
}

impl ToJSON for CardanoDetailStakeAction {
    fn to_json(&self) -> Value {
        json!({
            "action_type": self.get_type(),
            "stake": self.as_stake().map(|v| v.to_json()),
            "withdrawal": self.as_withdrawal().map(|v| v.to_json()),
            "registration": self.as_registration().map(|v| v.to_json()),
        })
    }
}

impl Default for CardanoDetailStakeAction {
    fn default() -> Self {
        Self::Stake(CardanoStake::default())
    }
}

impl_public_struct!(CardanoStake {
    stake_key: String,
    pool: String
});

impl ToJSON for CardanoStake {
    fn to_json(&self) -> Value {
        json!( {
            "stake_key": self.get_stake_key(),
            "pool": self.get_pool(),
        })
    }
}

impl_public_struct!(CardanoRegistration {
    registration_stake_key: String
});

impl ToJSON for CardanoRegistration {
    fn to_json(&self) -> Value {
        json!({
            "registration_stake_key": self.get_registration_stake_key(),
        })
    }
}

impl_public_struct!(CardanoWithdrawal {
    reward_address: Option<String>,
    reward_amount: Option<String>,
    value: u64,
    deregistration_stake_key: Option<String>
});

impl ToJSON for CardanoWithdrawal {
    fn to_json(&self) -> Value {
        json!({
            "reward_address": self.get_reward_address(),
            "reward_amount": self.get_reward_amount(),
            "deregistration_stake_key": self.get_deregistration_stake_key()
        })
    }
}