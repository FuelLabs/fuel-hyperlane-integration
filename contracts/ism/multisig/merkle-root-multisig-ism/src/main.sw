contract;

use std::{
    b512::B512,
    bytes::Bytes,
    storage::storage_vec::*,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    }};
use interfaces::isms::{ism::*, multisig::multisig_ism::*};
use checkpoint::{digest, domain_hash};
use merkle_root_multisig_ism_metadata::MerkleRootMultisigIsmMetadata;
use message::EncodedMessage;
use std_lib_extended::bytes::*;
use merkle::*;

enum MerkleRootMultisigError {
    NoMultisigThreshold: (),
    NoValidatorMatch: (),
    FailedToRecoverSigner: (),
    InvalidMerkleIndexMetadata: (),
    FailedToRecoverSignature: (Bytes),
}

storage {
    validators: StorageVec<EvmAddress> = StorageVec {},
    threshold: u8 = 0,
}

impl InterchainSecurityModule for Contract {
    fn module_type() -> ModuleType {
        ModuleType::MERKLE_ROOT_MULTISIG
    }

    #[storage(read)]
    fn verify(metadata: Bytes, message: Bytes) -> bool {
        let digest = _digest(metadata, message);
        let (validators, threshold) = _validators_and_threshold(message);
        require(threshold > 0, MerkleRootMultisigError::NoMultisigThreshold);

        let validator_count = validators.len();
        let mut validator_index = 0;
        let mut loop_index: u8 = 0;
        // Assumes that signatures are ordered by validator
        while loop_index < threshold {
            let signature_recover_result = _signature_at(metadata, u32::from(loop_index)); // works
            let sig_transformed = signature_recover_result.to_compact_signature();
            require(
                sig_transformed
                    .is_some(),
                MerkleRootMultisigError::FailedToRecoverSignature(signature_recover_result),
            );

            let signature = sig_transformed.unwrap();
            let address_recover_result = ec_recover_evm_address(
                signature,
                Bytes::to_eth_signed_message_hash(b256::from(digest)),
            );
            require(
                address_recover_result
                    .is_ok(),
                MerkleRootMultisigError::FailedToRecoverSigner,
            );

            let signer = address_recover_result.unwrap();

            // Loop through remaining validators until we find a match
            let mut validator_match = false;
            while !validator_match {
                if validator_index >= validator_count {
                    break;
                }
                validator_match = signer == validators.get(validator_index).unwrap();
                validator_index += 1;
            }

            // Fail if we never found a match
            require(
                validator_index < validator_count,
                MerkleRootMultisigError::NoValidatorMatch,
            );
            validator_index += 1;
            loop_index += 1;
        }
        true
    }
}

impl MultisigIsm for Contract {
    #[storage(read)]
    fn validators_and_threshold(message: Bytes) -> (Vec<EvmAddress>, u8) {
        _validators_and_threshold(message)
    }

    fn digest(metadata: Bytes, message: Bytes) -> Bytes {
        _digest(metadata, message)
    }

    fn signature_at(metadata: Bytes, index: u32) -> Bytes {
        _signature_at(metadata, index)
    }
}

impl MultisigIsmFunctions for Contract {
    #[storage(write)]
    fn enroll_validator(validator: EvmAddress) {
        storage.validators.push(validator);
    }

    #[storage(write)]
    fn set_threshold(threshold: u8) {
        storage.threshold.write(threshold);
    }
}

// --- Internal Functions ---

fn _digest(metadata: Bytes, message: Bytes) -> Bytes {
    let metadata = MerkleRootMultisigIsmMetadata::new(metadata);
    let message = EncodedMessage::from_bytes(message);

    require(
        metadata
            .message_index() == metadata
            .signed_index(),
        MerkleRootMultisigError::InvalidMerkleIndexMetadata,
    );

    let signed_root = StorageMerkleTree::branch_root(
        message
            .id(),
        metadata
            .proof(),
        u64::from(metadata.message_index()),
    );

    digest(
        message
            .origin(),
        metadata
            .origin_merkle_tree_hook(),
        Bytes::from(signed_root),
        metadata
            .signed_index(),
        metadata
            .signed_message_id(),
    )
}
#[storage(read)]
fn _validators_and_threshold(_message: Bytes) -> (Vec<EvmAddress>, u8) {
    let validators = storage.validators.load_vec();
    let threshold = storage.threshold.read();
    (validators, threshold)
}

fn _signature_at(metadata: Bytes, index: u32) -> Bytes {
    MerkleRootMultisigIsmMetadata::new(metadata).signature_at(index)
}
