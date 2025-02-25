contract;

use std::{
    b512::B512,
    bytes::Bytes,
    storage::storage_vec::*,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
};
use std::array_conversions::b256::*;
use interfaces::isms::{ism::*, multisig::multisig_ism::*};
use checkpoint::{digest, domain_hash};
use message_id_multisig_ism_metadata::MessageIdMultisigIsmMetadata;
use message::EncodedMessage;
use std_lib_extended::bytes::*;

configurable {
    /// Since the Multisig ISM is a static ISM, we can store the threshold as a configurable.
    /// This allows us to avoid storage reads when accessing it.
    /// We cannot store the validators as a configurable since we do not know the size of the array.
    ///
    /// The threshold of approval for the Multisig ISM.
    THRESHOLD: u8 = 0,
    EXPECTED_INITIALIZER: b256 = b256::zero(),

}

storage {
    /// The list of validators that can approve messages.
    validators: StorageVec<EvmAddress> = StorageVec {},
}

impl InterchainSecurityModule for Contract {
    /// Returns an enum that represents the type of security model
    /// encoded by this ISM. Relayers infer how to fetch and format metadata.
    ///
    /// ### Returns
    ///
    /// * [ModuleType] - The type of security model.
    fn module_type() -> ModuleType {
        ModuleType::MESSAGE_ID_MULTISIG
    }

    /// Verifies the message using the metadata.
    /// Assumes the signatures are in the same order as the validators.
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
    /// * If the threshold is not set or is less than 0.
    /// * If the signature recovery fails.
    /// * If the signer recovery fails.
    /// * If no validator matches the signer.
    #[storage(read)]
    fn verify(metadata: Bytes, message: Bytes) -> bool {
        let digest = _digest(metadata, message);
        let (validators, threshold) = _validators_and_threshold(message);
        require(threshold > 0, MessageIdMultisigError::NoMultisigThreshold);

        let validator_count = validators.len();
        let mut validator_index: u64 = 0;
        let mut loop_index: u32 = 0;
        while loop_index < u32::from(threshold) {
            let signature_recover_result = _signature_at(metadata, loop_index);
            let sig_transformed = signature_recover_result.to_compact_signature();
            require(
                sig_transformed
                    .is_some(),
                MessageIdMultisigError::FailedToRecoverSignature(signature_recover_result),
            );

            let signature = sig_transformed.unwrap();
            let address_recover_result = ec_recover_evm_address(signature, b256::from(digest));
            require(
                address_recover_result
                    .is_ok(),
                MessageIdMultisigError::FailedToRecoverSigner,
            );

            let signer = address_recover_result.unwrap();

            // Loop through remaining validators until we find a match
            while validator_index < validator_count && signer != storage.validators.get(validator_index).unwrap().read() {
                validator_index += 1;
            }

            // Fail if we never found a match
            require(
                validator_index < validator_count,
                MessageIdMultisigError::NoValidatorMatch,
            );

            validator_index += 1;
            loop_index += 1;
        }
        true
    }
}

impl MultisigIsm for Contract {
    /// Returns the validators and threshold for the Multisig ISM for the given message.
    ///
    /// ### Arguments
    ///
    /// * `message`: [Bytes] - The message to be processed.
    ///
    /// ### Returns
    ///
    /// * [Vec<EvmAddress>] - The list of validators that are set to approve the message.
    /// * [u8] - The threshold of approval for the Multisig ISM.
    #[storage(read)]
    fn validators_and_threshold(message: Bytes) -> (Vec<EvmAddress>, u8) {
        _validators_and_threshold(message)
    }

    /// Returns the digest to be used for signature verification.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - ABI encoded module metadata.
    /// * `message`: [Bytes] - Formatted Hyperlane message.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - The digest to be signed by validators.
    fn digest(metadata: Bytes, message: Bytes) -> Bytes {
        _digest(metadata, message)
    }

    /// Returns the signature at a given index from the metadata.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - ABI encoded module metadata.
    /// * `index`: [u32] - The index of the signature to be retrieved.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - Packed encoding of signature (65 bytes).
    fn signature_at(metadata: Bytes, index: u32) -> Bytes {
        _signature_at(metadata, index)
    }
}

impl MultisigIsmFunctions for Contract {
    /// Initializes the contract.
    ///
    /// ### Arguments
    ///
    /// * `validators`: [Vec<EvmAddress>] - The list of validators which can approve messages.
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized.
    #[storage(read, write)]
    fn initialize(validators: Vec<EvmAddress>) {
        _is_expected_caller();
        require(
            storage.validators.is_empty(),
            MerkleRootMultisigError::AlreadyInitialized,
        );
        storage.validators.store_vec(validators);
    }
}

// --- Internal Functions ---

fn _digest(metadata: Bytes, message: Bytes) -> Bytes {
    let metadata = MessageIdMultisigIsmMetadata::new(metadata);
    let message = EncodedMessage::from_bytes(message);
    digest(
        message
            .origin(),
        metadata
            .origin_merkle_tree_hook(),
        metadata
            .root(),
        metadata
            .index(),
        message
            .id(),
    )
}

#[storage(read)]
fn _validators_and_threshold(_message: Bytes) -> (Vec<EvmAddress>, u8) {
    let validators = storage.validators.load_vec();
    (validators, THRESHOLD)
}

fn _signature_at(metadata: Bytes, index: u32) -> Bytes {
    MessageIdMultisigIsmMetadata::new(metadata).signature_at(index)
}


// Front-run guard
fn _is_expected_caller() {
    let sender: b256 = msg_sender().unwrap().bits();
    require(sender == EXPECTED_INITIALIZER, MessageIdMultisigError::UnexpectedInitAddress);
}
