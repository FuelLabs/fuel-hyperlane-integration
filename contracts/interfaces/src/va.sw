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
    pub storage_location: StorageString,
}
abi ValidatorAnnounce {
    #[storage(read)]
    fn get_validators() -> Vec<b256>;

    #[storage(read)]
    fn get_mailbox() -> ContractId;

    #[storage(read)]
    fn get_local_domain() -> u32;

    #[storage(read)]
    fn get_announced_storage_locations(validators: Vec<b256>) -> Vec<String>;

    #[storage(read)]
    fn get_announced_storage_location(validator: EvmAddress) -> String;

    #[storage(read)]
    fn get_validator_count() -> u64;

    #[storage(write)]
    fn set_mailbox(mailbox: ContractId);

    #[storage(write)]
    fn set_local_domain(domain: u32);

    #[storage(read, write)]
    fn announce(
        validator: EvmAddress,
        storage_location: Bytes,
        signature: B512,
    );
}
