pub mod program_option;
pub mod stake;
pub mod system_instruction;
pub mod vote;
pub mod program_pack;

pub mod clock {
    pub type Slot = u64;

    /// Uniquely distinguishes every version of a slot, even if the
    /// slot number is the same, i.e. duplicate slots
    pub type BankId = u64;

    /// Epoch is a unit of time a given leader schedule is honored,
    ///  some number of Slots.
    pub type Epoch = u64;

    /// SlotIndex is an index to the slots of a epoch
    pub type SlotIndex = u64;

    /// SlotCount is the number of slots in a epoch
    pub type SlotCount = u64;

    /// UnixTimestamp is an approximate measure of real-world time,
    /// expressed as Unix time (ie. seconds since the Unix epoch)
    pub type UnixTimestamp = i64;
}

pub mod program_utils {
    use bincode::Options;
    use crate::solana_lib::solana_program::instruction::InstructionError;

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
}

pub mod instruction {
    use thiserror::Error;
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

}

pub mod pubkey {
    use std::fmt;
    use serde_derive::{Serialize, Deserialize};

    pub const PUBKEY_BYTES: usize = 32;

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

    impl Pubkey {
        pub fn new(pubkey_vec: &[u8]) -> Self {
            Self(
                <[u8; 32]>::try_from(<&[u8]>::clone(&pubkey_vec))
                    .expect("Slice must be the same length as a Pubkey"),
            )
        }
    }
}

pub mod hash {
    use serde_derive::{Serialize, Deserialize};
    use std::fmt;

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
}

pub mod program_error {
    use thiserror::Error;
    use serde_derive::{Serialize, Deserialize};
    /// Reasons the program may fail
    #[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
    pub enum ProgramError {
        /// Allows on-chain programs to implement program-specific error types and see them returned
        /// by the Solana runtime. A program-specific error may be any type that is represented as
        /// or serialized to a u32 integer.
        #[error("Custom program error: {0:#x}")]
        Custom(u32),
        #[error("The arguments provided to a program instruction where invalid")]
        InvalidArgument,
        #[error("An instruction's data contents was invalid")]
        InvalidInstructionData,
        #[error("An account's data contents was invalid")]
        InvalidAccountData,
        #[error("An account's data was too small")]
        AccountDataTooSmall,
        #[error("An account's balance was too small to complete the instruction")]
        InsufficientFunds,
        #[error("The account did not have the expected program id")]
        IncorrectProgramId,
        #[error("A signature was required but not found")]
        MissingRequiredSignature,
        #[error("An initialize instruction was sent to an account that has already been initialized")]
        AccountAlreadyInitialized,
        #[error("An attempt to operate on an account that hasn't been initialized")]
        UninitializedAccount,
        #[error("The instruction expected additional account keys")]
        NotEnoughAccountKeys,
        #[error("Failed to borrow a reference to account data, already borrowed")]
        AccountBorrowFailed,
        #[error("Length of the seed is too long for address generation")]
        MaxSeedLengthExceeded,
        #[error("Provided seeds do not result in a valid address")]
        InvalidSeeds,
        #[error("IO Error: {0}")]
        BorshIoError(String),
        #[error("An account does not have enough lamports to be rent-exempt")]
        AccountNotRentExempt,
        #[error("Unsupported sysvar")]
        UnsupportedSysvar,
        #[error("Provided owner is not allowed")]
        IllegalOwner,
        #[error("Account data allocation exceeded the maximum accounts data size limit")]
        MaxAccountsDataSizeExceeded,
        #[error("Account data reallocation was invalid")]
        InvalidRealloc,
    }
}