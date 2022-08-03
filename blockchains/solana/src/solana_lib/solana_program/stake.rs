pub mod state {
    use crate::solana_lib::solana_program::clock::{Epoch, UnixTimestamp};
    use crate::solana_lib::solana_program::pubkey::Pubkey;
    use serde_derive::{Serialize, Deserialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct Authorized {
        pub staker: Pubkey,
        pub withdrawer: Pubkey,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub enum StakeAuthorize {
        Staker,
        Withdrawer,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct Lockup {
        /// UnixTimestamp at which this stake will allow withdrawal, unless the
        ///   transaction is signed by the custodian
        pub unix_timestamp: UnixTimestamp,
        /// epoch height at which this stake will allow withdrawal, unless the
        ///   transaction is signed by the custodian
        pub epoch: Epoch,
        /// custodian signature on a transaction exempts the operation from
        ///  lockup constraints
        pub custodian: Pubkey,
    }
}

pub mod instruction {
    use crate::solana_lib::solana_program::clock::{Epoch, UnixTimestamp};
    use crate::solana_lib::solana_program::pubkey::Pubkey;
    use crate::solana_lib::solana_program::stake::state::{Authorized, Lockup, StakeAuthorize};
    use serde_derive::{Serialize, Deserialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct LockupArgs {
        pub unix_timestamp: Option<UnixTimestamp>,
        pub epoch: Option<Epoch>,
        pub custodian: Option<Pubkey>,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct AuthorizeWithSeedArgs {
        pub new_authorized_pubkey: Pubkey,
        pub stake_authorize: StakeAuthorize,
        pub authority_seed: String,
        pub authority_owner: Pubkey,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct AuthorizeCheckedWithSeedArgs {
        pub stake_authorize: StakeAuthorize,
        pub authority_seed: String,
        pub authority_owner: Pubkey,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct LockupCheckedArgs {
        pub unix_timestamp: Option<UnixTimestamp>,
        pub epoch: Option<Epoch>,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub enum StakeInstruction {
        /// Initialize a stake with lockup and authorization information
        ///
        /// # Account references
        ///   0. `[WRITE]` Uninitialized stake account
        ///   1. `[]` Rent sysvar
        ///
        /// Authorized carries pubkeys that must sign staker transactions
        ///   and withdrawer transactions.
        /// Lockup carries information about withdrawal restrictions
        Initialize(Authorized, Lockup),

        /// Authorize a key to manage stake or withdrawal
        ///
        /// # Account references
        ///   0. `[WRITE]` Stake account to be updated
        ///   1. `[]` Clock sysvar
        ///   2. `[SIGNER]` The stake or withdraw authority
        ///   3. Optional: `[SIGNER]` Lockup authority, if updating StakeAuthorize::Withdrawer before
        ///      lockup expiration
        Authorize(Pubkey, StakeAuthorize),

        /// Delegate a stake to a particular vote account
        ///
        /// # Account references
        ///   0. `[WRITE]` Initialized stake account to be delegated
        ///   1. `[]` Vote account to which this stake will be delegated
        ///   2. `[]` Clock sysvar
        ///   3. `[]` Stake history sysvar that carries stake warmup/cooldown history
        ///   4. `[]` Address of config account that carries stake config
        ///   5. `[SIGNER]` Stake authority
        ///
        /// The entire balance of the staking account is staked.  DelegateStake
        ///   can be called multiple times, but re-delegation is delayed
        ///   by one epoch
        DelegateStake,

        /// Split u64 tokens and stake off a stake account into another stake account.
        ///
        /// # Account references
        ///   0. `[WRITE]` Stake account to be split; must be in the Initialized or Stake state
        ///   1. `[WRITE]` Uninitialized stake account that will take the split-off amount
        ///   2. `[SIGNER]` Stake authority
        Split(u64),

        /// Withdraw unstaked lamports from the stake account
        ///
        /// # Account references
        ///   0. `[WRITE]` Stake account from which to withdraw
        ///   1. `[WRITE]` Recipient account
        ///   2. `[]` Clock sysvar
        ///   3. `[]` Stake history sysvar that carries stake warmup/cooldown history
        ///   4. `[SIGNER]` Withdraw authority
        ///   5. Optional: `[SIGNER]` Lockup authority, if before lockup expiration
        ///
        /// The u64 is the portion of the stake account balance to be withdrawn,
        ///    must be `<= StakeAccount.lamports - staked_lamports`.
        Withdraw(u64),

        /// Deactivates the stake in the account
        ///
        /// # Account references
        ///   0. `[WRITE]` Delegated stake account
        ///   1. `[]` Clock sysvar
        ///   2. `[SIGNER]` Stake authority
        Deactivate,

        /// Set stake lockup
        ///
        /// If a lockup is not active, the withdraw authority may set a new lockup
        /// If a lockup is active, the lockup custodian may update the lockup parameters
        ///
        /// # Account references
        ///   0. `[WRITE]` Initialized stake account
        ///   1. `[SIGNER]` Lockup authority or withdraw authority
        SetLockup(LockupArgs),

        /// Merge two stake accounts.
        ///
        /// Both accounts must have identical lockup and authority keys. A merge
        /// is possible between two stakes in the following states with no additional
        /// conditions:
        ///
        /// * two deactivated stakes
        /// * an inactive stake into an activating stake during its activation epoch
        ///
        /// For the following cases, the voter pubkey and vote credits observed must match:
        ///
        /// * two activated stakes
        /// * two activating accounts that share an activation epoch, during the activation epoch
        ///
        /// All other combinations of stake states will fail to merge, including all
        /// "transient" states, where a stake is activating or deactivating with a
        /// non-zero effective stake.
        ///
        /// # Account references
        ///   0. `[WRITE]` Destination stake account for the merge
        ///   1. `[WRITE]` Source stake account for to merge.  This account will be drained
        ///   2. `[]` Clock sysvar
        ///   3. `[]` Stake history sysvar that carries stake warmup/cooldown history
        ///   4. `[SIGNER]` Stake authority
        Merge,

        /// Authorize a key to manage stake or withdrawal with a derived key
        ///
        /// # Account references
        ///   0. `[WRITE]` Stake account to be updated
        ///   1. `[SIGNER]` Base key of stake or withdraw authority
        ///   2. `[]` Clock sysvar
        ///   3. Optional: `[SIGNER]` Lockup authority, if updating StakeAuthorize::Withdrawer before
        ///      lockup expiration
        AuthorizeWithSeed(AuthorizeWithSeedArgs),

        /// Initialize a stake with authorization information
        ///
        /// This instruction is similar to `Initialize` except that the withdraw authority
        /// must be a signer, and no lockup is applied to the account.
        ///
        /// # Account references
        ///   0. `[WRITE]` Uninitialized stake account
        ///   1. `[]` Rent sysvar
        ///   2. `[]` The stake authority
        ///   3. `[SIGNER]` The withdraw authority
        ///
        InitializeChecked,

        /// Authorize a key to manage stake or withdrawal
        ///
        /// This instruction behaves like `Authorize` with the additional requirement that the new
        /// stake or withdraw authority must also be a signer.
        ///
        /// # Account references
        ///   0. `[WRITE]` Stake account to be updated
        ///   1. `[]` Clock sysvar
        ///   2. `[SIGNER]` The stake or withdraw authority
        ///   3. `[SIGNER]` The new stake or withdraw authority
        ///   4. Optional: `[SIGNER]` Lockup authority, if updating StakeAuthorize::Withdrawer before
        ///      lockup expiration
        AuthorizeChecked(StakeAuthorize),

        /// Authorize a key to manage stake or withdrawal with a derived key
        ///
        /// This instruction behaves like `AuthorizeWithSeed` with the additional requirement that
        /// the new stake or withdraw authority must also be a signer.
        ///
        /// # Account references
        ///   0. `[WRITE]` Stake account to be updated
        ///   1. `[SIGNER]` Base key of stake or withdraw authority
        ///   2. `[]` Clock sysvar
        ///   3. `[SIGNER]` The new stake or withdraw authority
        ///   4. Optional: `[SIGNER]` Lockup authority, if updating StakeAuthorize::Withdrawer before
        ///      lockup expiration
        AuthorizeCheckedWithSeed(AuthorizeCheckedWithSeedArgs),

        /// Set stake lockup
        ///
        /// This instruction behaves like `SetLockup` with the additional requirement that
        /// the new lockup authority also be a signer.
        ///
        /// If a lockup is not active, the withdraw authority may set a new lockup
        /// If a lockup is active, the lockup custodian may update the lockup parameters
        ///
        /// # Account references
        ///   0. `[WRITE]` Initialized stake account
        ///   1. `[SIGNER]` Lockup authority or withdraw authority
        ///   2. Optional: `[SIGNER]` New lockup authority
        SetLockupChecked(LockupCheckedArgs),

        /// Get the minimum stake delegation, in lamports
        ///
        /// # Account references
        ///   None
        ///
        /// Returns the minimum delegation as a little-endian encoded u64 value.
        /// Programs can use the [`get_minimum_delegation()`] helper function to invoke and
        /// retrieve the return value for this instruction.
        ///
        /// [`get_minimum_delegation()`]: super::tools::get_minimum_delegation
        GetMinimumDelegation,

        /// Deactivate stake delegated to a vote account that has been delinquent for at least
        /// `MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION` epochs.
        ///
        /// No signer is required for this instruction as it is a common good to deactivate abandoned
        /// stake.
        ///
        /// # Account references
        ///   0. `[WRITE]` Delegated stake account
        ///   1. `[]` Delinquent vote account for the delegated stake account
        ///   2. `[]` Reference vote account that has voted at least once in the last
        ///      `MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION` epochs
        DeactivateDelinquent,
    }
}