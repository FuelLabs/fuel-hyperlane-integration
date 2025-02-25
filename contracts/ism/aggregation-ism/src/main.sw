contract;

use std::{bytes::Bytes, storage::storage_vec::*};
use interfaces::{isms::{aggregation_ism::*, ism::*}, ownable::*};
use aggregation_ism_metadata::*;
use standards::src5::State;
use sway_libs::ownership::*;

configurable {
    EXPECTED_INITIALIZER: b256 = b256::zero(),
}

storage {
    /// The list of modules to be used for message verification.
    modules: StorageVec<ContractId> = StorageVec {},
    /// The threshold of approval for the Aggregation ISM.
    threshold: u8 = 0,
}

impl InterchainSecurityModule for Contract {
    /// Returns an enum that represents the type of security model
    /// encoded by this ISM. Relayers infer how to fetch and format metadata.
    ///
    /// ### Returns
    ///
    /// * [ModuleType] - The type of security model.
    fn module_type() -> ModuleType {
        ModuleType::AGGREGATION
    }

    /// Verifies the message using the metadata.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata to be used for verification.
    /// * `message`: [Bytes] - The message to be verified.
    ///
    /// ### Returns
    ///
    /// * [bool] - True if the message is verified successfully.
    ///
    /// ### Reverts
    ///
    /// * If any external call fails.
    /// * If the verifications do not meet the threshold.
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
            require(
                ism.verify(
                    AggregationIsmMetadata::metadata_at(metadata, index),
                    message,
                ), 
                AggregationIsmError::FailedToVerify
            );

            threshold -= 1;
            index += 1;
        }
        require(threshold == 0, AggregationIsmError::DidNotMeetThreshold);
        true
    }
}

impl AggregationIsm for Contract {
    /// Returns the modules and threshold for the Aggregation ISM for the given message.
    ///
    /// ### Arguments
    ///
    /// * `message`: [Bytes] - The message to be processed.
    ///
    /// ### Returns
    ///
    /// * [Vec<ContractId>] - The list of modules to be used for message verification.
    /// * [u8] - The threshold of approval for the Aggregation ISM.
    #[storage(read)]
    fn modules_and_threshold(message: Bytes) -> (Vec<ContractId>, u8) {
        _modules_and_threshold(message)
    }
}

// --- Utility functions not essential for the Hyperlane Protocol ---

impl AggregationIsmFunctions for Contract {
    /// Initializes the contract.
    ///
    /// ### Arguments
    ///
    /// * `owner`: [Identity] - The address to be set as the owner of the contract.
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized.
    #[storage(read, write)]
    fn initialize(owner: Identity, modules: Vec<ContractId>, threshold: u8) {
        _is_expected_caller();
        initialize_ownership(owner);
        storage.modules.store_vec(modules);
        storage.threshold.write(threshold);
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

// Front-run guard
fn _is_expected_caller() {
    let sender = msg_sender().unwrap().bits();
    require(sender == EXPECTED_INITIALIZER, AggregationIsmError::UnexpectedInitAddress);
}
