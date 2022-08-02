use bincode;
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Deserialize with a limit based the maximum amount of data a program can expect to get.
/// This function should be used in place of direct deserialization to help prevent OOM errors
pub fn limited_deserialize<T>(instruction_data: &[u8], limit: u64) -> Result<T, InstructionError>
where
    T: serde::de::DeserializeOwned,
{
    bincode::options()
        .with_limit(limit)
        .with_fixint_encoding() // As per https://github.com/servo/bincode/issues/333, these two options are needed
        .allow_trailing_bytes() // to retain the behavior of bincode::deserialize with the new `options()` method
        .deserialize_from(instruction_data)
        .map_err(|_| InstructionError::InvalidInstructionData)
}

/// Reasons the runtime might have rejected an instruction.
///
/// Instructions errors are included in the bank hashes and therefore are
/// included as part of the transaction results when determining consensus.
/// Because of this, members of this enum must not be removed, but new ones can
/// be added.  Also, it is crucial that meta-information if any that comes along
/// with an error be consistent across software versions.  For example, it is
/// dangerous to include error strings from 3rd party crates because they could
/// change at any time and changes to them are difficult to detect.
#[derive(Error, Debug)]
pub enum InstructionError {
    /// Deprecated! Use CustomError instead!
    /// The program instruction returned an error
    #[error("generic instruction error")]
    GenericError,

    /// The arguments provided to a program were invalid
    #[error("invalid program argument")]
    InvalidArgument,

    /// An instruction's data contents were invalid
    #[error("invalid instruction data")]
    InvalidInstructionData,

    /// An account's data contents was invalid
    #[error("invalid account data for instruction")]
    InvalidAccountData,

    /// An account's data was too small
    #[error("account data too small for instruction")]
    AccountDataTooSmall,

    /// An account's balance was too small to complete the instruction
    #[error("insufficient funds for instruction")]
    InsufficientFunds,

    /// The account did not have the expected program id
    #[error("incorrect program id for instruction")]
    IncorrectProgramId,

    /// A signature was required but not found
    #[error("missing required signature for instruction")]
    MissingRequiredSignature,

    /// An initialize instruction was sent to an account that has already been initialized.
    #[error("instruction requires an uninitialized account")]
    AccountAlreadyInitialized,

    /// An attempt to operate on an account that hasn't been initialized.
    #[error("instruction requires an initialized account")]
    UninitializedAccount,

    /// Program's instruction lamport balance does not equal the balance after the instruction
    #[error("sum of account balances before and after instruction do not match")]
    UnbalancedInstruction,

    /// Program illegally modified an account's program id
    #[error("instruction illegally modified the program id of an account")]
    ModifiedProgramId,

    /// Program spent the lamports of an account that doesn't belong to it
    #[error("instruction spent from the balance of an account it does not own")]
    ExternalAccountLamportSpend,

    /// Program modified the data of an account that doesn't belong to it
    #[error("instruction modified data of an account it does not own")]
    ExternalAccountDataModified,

    /// Read-only account's lamports modified
    #[error("instruction changed the balance of a read-only account")]
    ReadonlyLamportChange,

    /// Read-only account's data was modified
    #[error("instruction modified data of a read-only account")]
    ReadonlyDataModified,

    /// An account was referenced more than once in a single instruction
    // Deprecated, instructions can now contain duplicate accounts
    #[error("instruction contains duplicate accounts")]
    DuplicateAccountIndex,

    /// Executable bit on account changed, but shouldn't have
    #[error("instruction changed executable bit of an account")]
    ExecutableModified,

    /// Rent_epoch account changed, but shouldn't have
    #[error("instruction modified rent epoch of an account")]
    RentEpochModified,

    /// The instruction expected additional account keys
    #[error("insufficient account keys for instruction")]
    NotEnoughAccountKeys,

    /// Program other than the account's owner changed the size of the account data
    #[error("program other than the account's owner changed the size of the account data")]
    AccountDataSizeChanged,

    /// The instruction expected an executable account
    #[error("instruction expected an executable account")]
    AccountNotExecutable,

    /// Failed to borrow a reference to account data, already borrowed
    #[error("instruction tries to borrow reference for an account which is already borrowed")]
    AccountBorrowFailed,

    /// Account data has an outstanding reference after a program's execution
    #[error("instruction left account with an outstanding borrowed reference")]
    AccountBorrowOutstanding,

    /// The same account was multiply passed to an on-chain program's entrypoint, but the program
    /// modified them differently.  A program can only modify one instance of the account because
    /// the runtime cannot determine which changes to pick or how to merge them if both are modified
    #[error("instruction modifications of multiply-passed account differ")]
    DuplicateAccountOutOfSync,

    /// Allows on-chain programs to implement program-specific error types and see them returned
    /// by the Solana runtime. A program-specific error may be any type that is represented as
    /// or serialized to a u32 integer.
    #[error("custom program error: {0:#x}")]
    Custom(u32),

    /// The return value from the program was invalid.  Valid errors are either a defined builtin
    /// error value or a user-defined error in the lower 32 bits.
    #[error("program returned invalid error code")]
    InvalidError,

    /// Executable account's data was modified
    #[error("instruction changed executable accounts data")]
    ExecutableDataModified,

    /// Executable account's lamports modified
    #[error("instruction changed the balance of a executable account")]
    ExecutableLamportChange,

    /// Executable accounts must be rent exempt
    #[error("executable accounts must be rent exempt")]
    ExecutableAccountNotRentExempt,

    /// Unsupported program id
    #[error("Unsupported program id")]
    UnsupportedProgramId,

    /// Cross-program invocation call depth too deep
    #[error("Cross-program invocation call depth too deep")]
    CallDepth,

    /// An account required by the instruction is missing
    #[error("An account required by the instruction is missing")]
    MissingAccount,

    /// Cross-program invocation reentrancy not allowed for this instruction
    #[error("Cross-program invocation reentrancy not allowed for this instruction")]
    ReentrancyNotAllowed,

    /// Length of the seed is too long for address generation
    #[error("Length of the seed is too long for address generation")]
    MaxSeedLengthExceeded,

    /// Provided seeds do not result in a valid address
    #[error("Provided seeds do not result in a valid address")]
    InvalidSeeds,

    /// Failed to reallocate account data of this length
    #[error("Failed to reallocate account data")]
    InvalidRealloc,

    /// Computational budget exceeded
    #[error("Computational budget exceeded")]
    ComputationalBudgetExceeded,

    /// Cross-program invocation with unauthorized signer or writable account
    #[error("Cross-program invocation with unauthorized signer or writable account")]
    PrivilegeEscalation,

    /// Failed to create program execution environment
    #[error("Failed to create program execution environment")]
    ProgramEnvironmentSetupFailure,

    /// Program failed to complete
    #[error("Program failed to complete")]
    ProgramFailedToComplete,

    /// Program failed to compile
    #[error("Program failed to compile")]
    ProgramFailedToCompile,

    /// Account is immutable
    #[error("Account is immutable")]
    Immutable,

    /// Incorrect authority provided
    #[error("Incorrect authority provided")]
    IncorrectAuthority,

    /// Failed to serialize or deserialize account data
    ///
    /// Warning: This error should never be emitted by the runtime.
    ///
    /// This error includes strings from the underlying 3rd party Borsh crate
    /// which can be dangerous because the error strings could change across
    /// Borsh versions. Only programs can use this error because they are
    /// consistent across Solana software versions.
    ///
    #[error("Failed to serialize or deserialize account data: {0}")]
    BorshIoError(String),

    /// An account does not have enough lamports to be rent-exempt
    #[error("An account does not have enough lamports to be rent-exempt")]
    AccountNotRentExempt,

    /// Invalid account owner
    #[error("Invalid account owner")]
    InvalidAccountOwner,

    /// Program arithmetic overflowed
    #[error("Program arithmetic overflowed")]
    ArithmeticOverflow,

    /// Unsupported sysvar
    #[error("Unsupported sysvar")]
    UnsupportedSysvar,

    /// Illegal account owner
    #[error("Provided owner is not allowed")]
    IllegalOwner,

    /// Account data allocation exceeded the maximum accounts data size limit
    #[error("Account data allocation exceeded the maximum accounts data size limit")]
    MaxAccountsDataSizeExceeded,

    /// Max accounts exceeded
    #[error("Max accounts exceeded")]
    MaxAccountsExceeded,
    // Note: For any new error added here an equivalent ProgramError and its
    // conversions must also be added
}
#[derive(Clone, Copy, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Pubkey(pub(crate) [u8; 32]);

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

#[repr(C)]
#[derive(Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
pub enum COption<T> {
    /// No value
    None,
    /// Some value `T`
    Some(T),
}

pub type UnixTimestamp = i64;

pub type Epoch = u64;

pub type Slot = u64;

pub const HASH_BYTES: usize = 32;

#[derive(Serialize, Deserialize, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Hash(pub(crate) [u8; HASH_BYTES]);

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

pub mod stake {
    use crate::solana_lib::solana_program::Epoch;
    use crate::solana_lib::solana_program::Pubkey;
    use crate::solana_lib::solana_program::UnixTimestamp;
    use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SystemInstruction {
    /// Create a new account
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE, SIGNER]` New account
    CreateAccount {
        /// Number of lamports to transfer to the new account
        lamports: u64,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Address of program that will own the new account
        owner: Pubkey,
    },

    /// Assign account to a program
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Assigned account public key
    Assign {
        /// Owner program account
        owner: Pubkey,
    },

    /// Transfer lamports
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE]` Recipient account
    Transfer { lamports: u64 },

    /// Create a new account at an address derived from a base pubkey and a seed
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE]` Created account
    ///   2. `[SIGNER]` (optional) Base account; the account matching the base Pubkey below must be
    ///                          provided as a signer, but may be the same as the funding account
    ///                          and provided as account 0
    CreateAccountWithSeed {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `Pubkey::MAX_SEED_LEN`
        seed: String,

        /// Number of lamports to transfer to the new account
        lamports: u64,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Owner program account address
        owner: Pubkey,
    },

    /// Consumes a stored nonce, replacing it with a successor
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[]` RecentBlockhashes sysvar
    ///   2. `[SIGNER]` Nonce authority
    AdvanceNonceAccount,

    /// Withdraw funds from a nonce account
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[WRITE]` Recipient account
    ///   2. `[]` RecentBlockhashes sysvar
    ///   3. `[]` Rent sysvar
    ///   4. `[SIGNER]` Nonce authority
    ///
    /// The `u64` parameter is the lamports to withdraw, which must leave the
    /// account balance above the rent exempt reserve or at zero.
    WithdrawNonceAccount(u64),

    /// Drive state of Uninitialized nonce account to Initialized, setting the nonce value
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[]` RecentBlockhashes sysvar
    ///   2. `[]` Rent sysvar
    ///
    /// The `Pubkey` parameter specifies the entity authorized to execute nonce
    /// instruction on the account
    ///
    /// No signatures are required to execute this instruction, enabling derived
    /// nonce account addresses
    InitializeNonceAccount(Pubkey),

    /// Change the entity authorized to execute nonce instructions on the account
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[SIGNER]` Nonce authority
    ///
    /// The `Pubkey` parameter identifies the entity to authorize
    AuthorizeNonceAccount(Pubkey),

    /// Allocate space in a (possibly new) account without funding
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` New account
    Allocate {
        /// Number of bytes of memory to allocate
        space: u64,
    },

    /// Allocate space for and assign an account at an address
    ///    derived from a base public key and a seed
    ///
    /// # Account references
    ///   0. `[WRITE]` Allocated account
    ///   1. `[SIGNER]` Base account
    AllocateWithSeed {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `pubkey::MAX_SEED_LEN`
        seed: String,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Owner program account
        owner: Pubkey,
    },

    /// Assign account to a program based on a seed
    ///
    /// # Account references
    ///   0. `[WRITE]` Assigned account
    ///   1. `[SIGNER]` Base account
    AssignWithSeed {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `pubkey::MAX_SEED_LEN`
        seed: String,

        /// Owner program account
        owner: Pubkey,
    },

    /// Transfer lamports from a derived address
    ///
    /// # Account references
    ///   0. `[WRITE]` Funding account
    ///   1. `[SIGNER]` Base for funding account
    ///   2. `[WRITE]` Recipient account
    TransferWithSeed {
        /// Amount to transfer
        lamports: u64,

        /// Seed to use to derive the funding account address
        from_seed: String,

        /// Owner to use to derive the funding account address
        from_owner: Pubkey,
    },

    /// One-time idempotent upgrade of legacy nonce versions in order to bump
    /// them out of chain blockhash domain.
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    UpgradeNonceAccount,
}

pub mod vote {
    use crate::solana_lib::solana_program::{Hash, Pubkey, Slot, UnixTimestamp};
    use serde::{Deserialize, Serialize};
    use std::collections::VecDeque;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct VoteInit {
        pub node_pubkey: Pubkey,
        pub authorized_voter: Pubkey,
        pub authorized_withdrawer: Pubkey,
        pub commission: u8,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub enum VoteAuthorize {
        Voter,
        Withdrawer,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct VoteAuthorizeCheckedWithSeedArgs {
        pub authorization_type: VoteAuthorize,
        pub current_authority_derived_key_owner: Pubkey,
        pub current_authority_derived_key_seed: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct VoteAuthorizeWithSeedArgs {
        pub authorization_type: VoteAuthorize,
        pub current_authority_derived_key_owner: Pubkey,
        pub current_authority_derived_key_seed: String,
        pub new_authority: Pubkey,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct BlockTimestamp {
        pub slot: Slot,
        pub timestamp: UnixTimestamp,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct Vote {
        /// A stack of votes starting with the oldest vote
        pub slots: Vec<Slot>,
        /// signature of the bank's state at the last slot
        pub hash: Hash,
        /// processing timestamp of last slot
        pub timestamp: Option<UnixTimestamp>,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct Lockout {
        pub slot: Slot,
        pub confirmation_count: u32,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    pub struct VoteStateUpdate {
        /// The proposed tower
        pub lockouts: VecDeque<Lockout>,
        /// The proposed root
        pub root: Option<Slot>,
        /// signature of the bank's state at the last slot
        pub hash: Hash,
        /// processing timestamp of last slot
        pub timestamp: Option<UnixTimestamp>,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub enum VoteInstruction {
        /// Initialize a vote account
        ///
        /// # Account references
        ///   0. `[WRITE]` Uninitialized vote account
        ///   1. `[]` Rent sysvar
        ///   2. `[]` Clock sysvar
        ///   3. `[SIGNER]` New validator identity (node_pubkey)
        InitializeAccount(VoteInit),

        /// Authorize a key to send votes or issue a withdrawal
        ///
        /// # Account references
        ///   0. `[WRITE]` Vote account to be updated with the Pubkey for authorization
        ///   1. `[]` Clock sysvar
        ///   2. `[SIGNER]` Vote or withdraw authority
        Authorize(Pubkey, VoteAuthorize),

        /// A Vote instruction with recent votes
        ///
        /// # Account references
        ///   0. `[WRITE]` Vote account to vote with
        ///   1. `[]` Slot hashes sysvar
        ///   2. `[]` Clock sysvar
        ///   3. `[SIGNER]` Vote authority
        Vote(Vote),

        /// Withdraw some amount of funds
        ///
        /// # Account references
        ///   0. `[WRITE]` Vote account to withdraw from
        ///   1. `[WRITE]` Recipient account
        ///   2. `[SIGNER]` Withdraw authority
        Withdraw(u64),

        /// Update the vote account's validator identity (node_pubkey)
        ///
        /// # Account references
        ///   0. `[WRITE]` Vote account to be updated with the given authority public key
        ///   1. `[SIGNER]` New validator identity (node_pubkey)
        ///   2. `[SIGNER]` Withdraw authority
        UpdateValidatorIdentity,

        /// Update the commission for the vote account
        ///
        /// # Account references
        ///   0. `[WRITE]` Vote account to be updated
        ///   1. `[SIGNER]` Withdraw authority
        UpdateCommission(u8),

        /// A Vote instruction with recent votes
        ///
        /// # Account references
        ///   0. `[WRITE]` Vote account to vote with
        ///   1. `[]` Slot hashes sysvar
        ///   2. `[]` Clock sysvar
        ///   3. `[SIGNER]` Vote authority
        VoteSwitch(Vote, Hash),

        /// Authorize a key to send votes or issue a withdrawal
        ///
        /// This instruction behaves like `Authorize` with the additional requirement that the new vote
        /// or withdraw authority must also be a signer.
        ///
        /// # Account references
        ///   0. `[WRITE]` Vote account to be updated with the Pubkey for authorization
        ///   1. `[]` Clock sysvar
        ///   2. `[SIGNER]` Vote or withdraw authority
        ///   3. `[SIGNER]` New vote or withdraw authority
        AuthorizeChecked(VoteAuthorize),

        /// Update the onchain vote state for the signer.
        ///
        /// # Account references
        ///   0. `[Write]` Vote account to vote with
        ///   1. `[SIGNER]` Vote authority
        UpdateVoteState(VoteStateUpdate),

        /// Update the onchain vote state for the signer along with a switching proof.
        ///
        /// # Account references
        ///   0. `[Write]` Vote account to vote with
        ///   1. `[SIGNER]` Vote authority
        UpdateVoteStateSwitch(VoteStateUpdate, Hash),

        /// Given that the current Voter or Withdrawer authority is a derived key,
        /// this instruction allows someone who can sign for that derived key's
        /// base key to authorize a new Voter or Withdrawer for a vote account.
        ///
        /// # Account references
        ///   0. `[Write]` Vote account to be updated
        ///   1. `[]` Clock sysvar
        ///   2. `[SIGNER]` Base key of current Voter or Withdrawer authority's derived key
        AuthorizeWithSeed(VoteAuthorizeWithSeedArgs),

        /// Given that the current Voter or Withdrawer authority is a derived key,
        /// this instruction allows someone who can sign for that derived key's
        /// base key to authorize a new Voter or Withdrawer for a vote account.
        ///
        /// This instruction behaves like `AuthorizeWithSeed` with the additional requirement
        /// that the new vote or withdraw authority must also be a signer.
        ///
        /// # Account references
        ///   0. `[Write]` Vote account to be updated
        ///   1. `[]` Clock sysvar
        ///   2. `[SIGNER]` Base key of current Voter or Withdrawer authority's derived key
        ///   3. `[SIGNER]` New vote or withdraw authority
        AuthorizeCheckedWithSeed(VoteAuthorizeCheckedWithSeedArgs),
    }
}
