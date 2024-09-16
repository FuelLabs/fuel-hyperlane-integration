library;

use std::{
    b512::B512,
    bytes::Bytes,
    storage::*,
    storage::storage_string::StorageString,
    storage::storage_vec::*,
    string::String,
    vm::evm::evm_address::EvmAddress,
};

/// Event emitted when a validator announces their storage location.
pub struct ValidatorAnnouncementEvent {
    /// The address of the announcing validator
    pub validator: EvmAddress,
    /// The storage location being announced
    pub storage_location: String,
}

/// Official Hyperlane V3 Interface
abi ValidatorAnnounce {
    /// Returns a list of validators that have made announcements
    ///
    /// ### Returns
    ///
    /// * [Vec<b256>] - The list of validators that have made announcements
    #[storage(read)]
    fn get_announced_validators() -> Vec<b256>;

    /// Returns a list of all announced storage locations   
    ///
    /// ### Arguments
    ///
    /// * `validators`: [Vec<b256>] - The list of validators to get storage locations for
    ///
    /// ### Returns
    ///
    /// * [Vec<Vec<String>>] - The list of storage locations for each validator
    #[storage(read)]
    fn get_announced_storage_locations(validators: Vec<b256>) -> Vec<Vec<String>>;

    /// Announces a validator signature storage location    
    ///
    /// ### Arguments
    ///
    /// * `validator`: [b256] - The address of the validator
    /// * `storage_location`: [string] - Information encoding the location of signed checkpoints
    /// * `signature`: [bytes] - The signed validator announcement
    ///
    /// ### Returns
    ///
    /// * [bool] - Whether the announcement was successful
    #[storage(read, write)]
    fn announce(
        validator: EvmAddress,
        storage_location: String,
        signature: Bytes,
    ) -> bool;
}

/// Additional functions which can be used for additional VA functionality
abi ValidatorAnnounceFunctions {
    /// Returns the mailbox contract ID set on the VA
    ///
    /// ### Returns
    ///
    /// * [ContractId] - The mailbox contract ID
    #[storage(read)]
    fn get_mailbox() -> ContractId;

    /// Returns the local domain of the VA
    ///
    /// ### Returns
    ///
    /// * [u32] - The local domain
    #[storage(read)]
    fn get_local_domain() -> u32;

    /// Returns the storage location announced by a validator
    ///
    /// ### Arguments
    ///
    /// * `validator`: [EvmAddress] - The address of the validator
    ///
    /// ### Returns
    ///
    /// * [String] - The storage location announced by the validator
    #[storage(read)]
    fn get_announced_storage_location(validator: EvmAddress) -> String;

    /// Returns the number of validators that have made announcements
    ///
    /// ### Returns
    ///
    /// * [u64] - The number of validators that have made announcements
    #[storage(read)]
    fn get_validator_count() -> u64;

    /// Sets the mailbox contract ID on the VA
    ///
    /// ### Arguments
    ///
    /// * `mailbox`: [ContractId] - The mailbox contract ID
    #[storage(write)]
    fn set_mailbox(mailbox: ContractId);

    /// Sets the local domain of the VA
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The local domain
    #[storage(write)]
    fn set_local_domain(domain: u32);
}
