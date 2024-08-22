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

pub struct ValidatorAnnouncementEvent {
    pub validator: EvmAddress,
    pub storage_location: String,
}

 // Official Hyperlane V3 Interface
abi ValidatorAnnounce {
    #[storage(read)]
    fn get_announced_validators() -> Vec<b256>;

    #[storage(read)]
    fn get_announced_storage_locations(validators: Vec<b256>) -> Vec<Vec<String>>;

    #[storage(read, write)]
    fn announce(
        validator: EvmAddress,
        storage_location: String,
        signature: Bytes,
    ) -> bool;
}

// Additional functions which can be used for additional VA functionality
abi ValidatorAnnounceFunctions {
    #[storage(read)]
    fn get_mailbox() -> ContractId;

    #[storage(read)]
    fn get_local_domain() -> u32;

    #[storage(read)]
    fn get_announced_storage_location(validator: EvmAddress) -> String;

    #[storage(read)]
    fn get_validator_count() -> u64;

    #[storage(write)]
    fn set_mailbox(mailbox: ContractId);

    #[storage(write)]
    fn set_local_domain(domain: u32);
}
