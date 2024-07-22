contract;

use std::{
    bytes::Bytes,
    constants::ZERO_B256,
    logging::log,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
};

use message::{EncodedMessage, Message};

// use merkle::StorageMerkleTree;


use interfaces::{
    ism::{
        InterchainSecurityModule,
        ModuleType,
    },
    multisig_ism::MultisigIsm,
    ownable::Ownable,
};

use std::{hash::Hash, storage::storage_vec::*};
use sway_libs::ownership::*;
use standards::src5::State;

use multisig_ism_metadata::MultisigMetadata;

// See https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/solidity/contracts/isms/MultisigIsm.sol
/// for the reference implementation.
storage {
    validators: StorageVec<StorageVec<EvmAddress>> = StorageVec {},
    threshold: StorageMap<u32, u8> = StorageMap {},
}

// Returns index of the validator on the multisig for the domain
/// Currently O(n) but could be O(1) with a set data structure
#[storage(read)]
fn index_of(domain: u32, validator: EvmAddress) -> Option<u64> {
    let validators = storage.validators.get(u64::from(domain));
    if validators.is_none() {
        return Option::None;
    }
    let validator_vec = validators.unwrap();

    let len = validator_vec.len();

    let mut i: u64 = 0;
    while i < len {
        if validator_vec.get(i).unwrap().read() == validator {
            return Option::Some(i);
        }
        i += 1;
    }
    return Option::None;
}

// Returns true if the validator is on the multisig for the domain
#[storage(read)]
fn is_enrolled(domain: u32, validator: EvmAddress) -> bool {
    // let validators = storage.validators.get(u64::from(domain));
    // if validators.is_some() {
    //     let len = validators.unwrap().len();
    //     return index_of()
    // }
    return index_of(domain, validator).is_some();
}

// TODO fix when merkle tree is implemented
// Returns true if the metadata merkle proof verifies the inclusion of the message in the root.
pub fn verify_merkle_proof(metadata: MultisigMetadata, message: EncodedMessage) -> bool {
    // let calculated_root = StorageMerkleTree::branch_root(message.id(), metadata.proof, metadata.index);
    // return calculated_root == metadata.root;
    true
}

// Returns true if a threshold of metadata signatures match the stored validator set and threshold.
#[storage(read)]
pub fn verify_validator_signatures(
    threshold: u64,
    metadata: MultisigMetadata,
    message: EncodedMessage,
) -> bool {
    let origin = message.origin();
    let origin_u64 = u64::from(origin);
    let digest = metadata.checkpoint_digest(origin);
    let validators = storage.validators.get(origin_u64).unwrap();
    let validator_count = validators.len();
    let mut validator_index = 0;
    let mut signature_index = 0;
    // // Assumes that signatures are ordered by validator
    while signature_index < threshold {
        let signature = metadata.signatures.get(signature_index).unwrap();
        let signer = ec_recover_evm_address(signature, digest).unwrap();
        // Loop through remaining validators until we find a match
        while validator_index < validator_count {
            // Not defined in the loop declatation as it breaks with 2 checks combined with &&
            if signer == validators.get(validator_index).unwrap().read()
            {
                break;
            }
            validator_index += 1;
        }

        // Fail if we didn't find a match
        if (validator_index >= validator_count) {
            return false;
        }
        validator_index += 1;
        signature_index += 1;
    }
    return true;
}

// Enrolls a validator without updating the commitment.
#[storage(read, write)]
fn enroll_validator(domain: u32, validator: EvmAddress) {
    require(validator != EvmAddress::from(ZERO_B256), "zero address");
    require(!is_enrolled(domain, validator), "enrolled");

    let domain_u64 = u64::from(domain);
    let validators = storage.validators.get(domain_u64);
    if validators.is_some() {
        let validators = validators.unwrap();
        validators.push(validator);
    } else {
        storage.validators.set(domain_u64, StorageVec {});
        let new_vec = storage.validators.get(domain_u64).unwrap();
        new_vec.push(validator);
        // TODO check if need to re set the vec or is pushing after get is enough

        // new_vec.push(validator);
        // storage.validators.set(domain_u64, new_vec);
    }
    // storage.validators.push(domain, validator);
}

// Sets the threshold for the domain. Must be less than or equal to the number of validators.
#[storage(read, write)]
fn set_threshold(domain: u32, threshold: u8) {
    let domain_u64 = u64::from(domain);
    let validators = storage.validators.get(domain_u64);
    let val_len = if validators.is_some() {
        validators.unwrap().len()
    } else {
        0
    };

    require(threshold > 0 && u64::from(threshold) <= val_len, "!range");
    storage.threshold.insert(domain, threshold);
}

#[storage(read)]
fn threshold(domain: u32) -> u8 {
    storage.threshold.get(domain).try_read().unwrap_or(0)
}

// Returns the validator set enrolled for the domain.
#[storage(read)]
fn validators(domain: u32) -> Vec<EvmAddress> {
    let validators = storage.validators.get(u64::from(domain));
    if validators.is_none() {
        return Vec::new();
    }
    validators.unwrap().load_vec()
}

impl InterchainSecurityModule for Contract {
    // #[storage(read)]
    // fn module_type() -> ModuleType {
    //     ModuleType::MULTISIG
    // }

    #[storage(read, write)]
    fn verify(metadata: Bytes, message: Bytes) -> bool {
        let message = EncodedMessage { bytes: message };
        let threshold = threshold(message.origin());
        let metadata = MultisigMetadata::from_bytes(metadata, u64::from(threshold));
        require(verify_merkle_proof(metadata, message), "!merkle");
        require(
            verify_validator_signatures(u64::from(threshold), metadata, message),
            "!signatures",
        );
        return true;
    }
}

impl MultisigIsm for Contract {

    // Returns the threshold for the domain.
    // #[storage(read)]
    // fn threshold(domain: u32) -> u8 {
    //     threshold(domain)
    // }

    // Returns the validator set enrolled for the domain.
    // #[storage(read)]
    // fn validators(domain: u32) -> Vec<EvmAddress> {
    //     validators(domain)
    // }

    // #[storage(read)]
    // fn validators_and_threshold(message: Bytes) -> (Vec<EvmAddress>, u8) {
    //     let message = EncodedMessage { bytes: message };
    //     let domain = message.origin();
    //     return (validators(domain), threshold(domain));
    // }

    // Returns true if the validator is enrolled for the domain.
    // #[storage(read)]
    // fn is_enrolled(domain: u32, validator: EvmAddress) -> bool {
    //     return is_enrolled(domain, validator);
    // }

    // Sets the threshold for the domain.
    // Must be less than or equal to the number of validators.
    // #[storage(read, write)]
    // fn set_threshold(domain: u32, threshold: u8) {
    //     only_owner();
    //     set_threshold(domain, threshold);
    // }

    // Enrolls a validator for the domain (and updates commitment).
    // Must not already be enrolled.
    // #[storage(read, write)]
    // fn enroll_validator(domain: u32, validator: EvmAddress) {
    //     only_owner();
    //     enroll_validator(domain, validator);
    // }

    // Batches validator enrollment for a list of domains.
    // #[storage(read, write)]
    // fn enroll_validators(domains: Vec<u32>, validators: Vec<Vec<EvmAddress>>) {
    //     only_owner();
    //     let domain_len = domains.len();
    //     require(domain_len == validators.len(), "!length");
    //     let mut i = 0;
    //     while i < domain_len {
    //         let domain = domains.get(i).unwrap();
    //         let domain_validators = validators.get(i).unwrap();
    //         let mut j = 0;
    //         let validator_len = domain_validators.len();
    //         while j < validator_len {
    //             let validator = domain_validators.get(j).unwrap();
    //             enroll_validator(domain, validator);
    //             j += 1;
    //         }
    //         i += 1;
    //     }
    // }

    // Batches threshold setting for a list of domains.
    // #[storage(read, write)]
    // fn set_thresholds(domains: Vec<u32>, thresholds: Vec<u8>) {
    //     only_owner();
    //     let domain_len = domains.len();
    //     require(domain_len == thresholds.len(), "!length");
    //     let mut i = 0;
    //     while i < domain_len {
    //         set_threshold(domains.get(i).unwrap(), thresholds.get(i).unwrap());
    //         i += 1;
    //     }
    // }

    // Unenrolls a validator for the domain (and updates commitment).
    // #[storage(read, write)]
    // fn unenroll_validator(domain: u32, validator: EvmAddress) {
    //     only_owner();
    //     let index = index_of(domain, validator);
    //     require(index.is_some(), "!enrolled");
    //     let validators = storage.validators.get(u64::from(domain)).unwrap();
    //     let removed = validators.swap_remove(index.unwrap());
    //     assert(removed == validator);
    // }
}

// impl Ownable for Contract {
//     #[storage(read)]
//     fn owner() -> State {
//         _owner()
//     }

//     #[storage(read)]
//     fn only_owner() {
//         only_owner();
//     }

//     #[storage(write)]
//     fn transfer_ownership(new_owner: Identity) {
//         transfer_ownership(new_owner);
//     }

//     #[storage(read, write)]
//     fn initialize_ownership(new_owner: Identity) {
//         initialize_ownership(new_owner);
//     }

//     #[storage(read, write)]
//     fn renounce_ownership() {
//         renounce_ownership();
//     }
// }
