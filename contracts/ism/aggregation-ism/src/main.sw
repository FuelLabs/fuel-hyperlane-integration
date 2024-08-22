contract;

use std::{bytes::Bytes, storage::storage_vec::*};
use interfaces::{isms::{aggregation_ism::*, ism::*}, ownable::*};
use aggregation_ism_metadata::*;
use standards::src5::State;
use sway_libs::ownership::*;

enum AggregationIsmError {
    DidNotMeetThreshold: (),
    AlreadyInitialized: (),
    NotInitialized: (),
}

storage {
    modules: StorageVec<ContractId> = StorageVec {},
    threshold: u8 = 0,
}

impl InterchainSecurityModule for Contract {
    fn module_type() -> ModuleType {
        ModuleType::AGGREGATION
    }

    #[storage(read)]
    fn verify(metadata: Bytes, message: Bytes) -> bool {
        let (modules, mut threshold) = _modules_and_threshold(message);

        let count = u8::try_from(modules.len()).unwrap();
        let mut index: u8 = 0;
        while threshold > 0 {
            if index >= count {
                break;
            }

            let metadata = AggregationIsmMetadata::new(metadata);
            if !metadata.has_metadata(index) {
                index += 1;
                continue;
            }

            let ism_id = b256::from(modules.get(u64::from(index)).unwrap());
            let ism = abi(InterchainSecurityModule, ism_id);
            if ism.verify(
                    AggregationIsmMetadata::metadata_at(metadata, index),
                    message,
                )
            {
                threshold -= 1;
            }
            index += 1;
        }
        require(threshold == 0, AggregationIsmError::DidNotMeetThreshold);
        true
    }
}
impl AggregationIsm for Contract {
    #[storage(read)]
    fn modules_and_threshold(message: Bytes) -> (Vec<ContractId>, u8) {
        _modules_and_threshold(message)
    }
}

// --- Utility functions not essential for the Hyperlane Protocol ---

impl AggregationIsmFunctions for Contract {
    #[storage(read, write)]
    fn initialize(owner: b256) {
        only_not_initialized();
        initialize_ownership(Identity::Address(Address::from(owner)));
    }
    #[storage(write)]
    fn set_threshold(threshold: u8) {
        only_initialized();
        only_owner();
        storage.threshold.write(threshold);
    }
    #[storage(write)]
    fn enroll_module(module: ContractId) {
        only_initialized();
        only_owner();
        storage.modules.push(module);
    }
}
// --- Ownable implementation ---

impl Ownable for Contract {
    #[storage(read)]
    fn owner() -> State {
        _owner()
    }
    #[storage(read)]
    fn only_owner() {
        only_owner();
    }
    #[storage(write)]
    fn transfer_ownership(new_owner: Identity) {
        transfer_ownership(new_owner);
    }
    #[storage(read, write)]
    fn initialize_ownership(new_owner: Identity) {
        initialize_ownership(new_owner);
    }
    #[storage(read, write)]
    fn renounce_ownership() {
        renounce_ownership();
    }
}
// --- Internal functions ---

#[storage(read)]
fn _modules_and_threshold(_message: Bytes) -> (Vec<ContractId>, u8) {
    let modules = storage.modules.load_vec();
    let threshold = storage.threshold.read();
    (modules, threshold)
}
// --- Guards ---

#[storage(read)]
fn only_not_initialized() {
    require(
        _owner() == State::Uninitialized,
        AggregationIsmError::AlreadyInitialized,
    );
}
#[storage(read)]
fn only_initialized() {
    require(
        _owner() != State::Uninitialized,
        AggregationIsmError::NotInitialized,
    );
}
