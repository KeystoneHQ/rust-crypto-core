use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{AsRef as DeriveAsRef};
use serde::{Deserialize, Serialize};
use near_crypto::PublicKey;

use near_primitives_core::hash::CryptoHash;
use near_primitives_core::serialize::u128_dec_format;
pub use near_primitives_core::types::*;

/// Epoch identifier -- wrapped hash, to make it easier to distinguish.
/// EpochId of epoch T is the hash of last block in T-2
/// EpochId of first two epochs is 0
#[cfg_attr(feature = "deepsize_feature", derive(deepsize::DeepSizeOf))]
#[derive(
Debug,
Clone,
Default,
Hash,
Eq,
PartialEq,
PartialOrd,
DeriveAsRef,
BorshSerialize,
BorshDeserialize,
Serialize,
Deserialize,
)]
#[as_ref(forward)]
pub struct EpochId(pub CryptoHash);

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountWithPublicKey {
    pub account_id: AccountId,
    pub public_key: PublicKey,
}

/// Account info for validators
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct AccountInfo {
    pub account_id: AccountId,
    pub public_key: PublicKey,
    #[serde(with = "u128_dec_format")]
    pub amount: Balance,
}