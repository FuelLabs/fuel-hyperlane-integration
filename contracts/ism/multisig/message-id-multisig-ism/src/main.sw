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

enum MessageIdMultisigError {
    NoMultisigThreshold: (),
    NoValidatorMatch: (),
    FailedToRecoverSigner: (),
    FailedToRecoverSignature: Bytes,
}

storage {
    validators: StorageVec<EvmAddress> = StorageVec {},
    threshold: u8 = 0,
}

impl InterchainSecurityModule for Contract {
    fn module_type() -> ModuleType {
        ModuleType::MESSAGE_ID_MULTISIG
    }

    #[storage(read)]
    fn verify(metadata: Bytes, message: Bytes) -> bool {
        let digest = _digest(metadata, message);
        let (validators, threshold) = _validators_and_threshold(message);
        require(threshold > 0, MessageIdMultisigError::NoMultisigThreshold);

        let validator_count = validators.len();
        let mut loop_index: u8 = 0;
        // Assumes that signatures are ordered by validator
        while loop_index < threshold {
            let signature_recover_result = _signature_at(metadata, u32::from(loop_index)); // works
            let sig_transformed = signature_recover_result.to_compact_signature();
            require(
                sig_transformed
                    .is_some(),
                MessageIdMultisigError::FailedToRecoverSignature(signature_recover_result),
            );

            let signature = sig_transformed.unwrap();
            let address_recover_result = ec_recover_evm_address(
                signature,
                Bytes::to_eth_signed_message_hash(b256::from(digest)),
            );
            require(
                address_recover_result
                    .is_ok(),
                MessageIdMultisigError::FailedToRecoverSigner,
            );

            let signer = address_recover_result.unwrap();

            // Loop through remaining validators until we find a match
            let mut validator_match = false;
            let mut validator_index = 0;
            while !validator_match {
                if validator_index >= validator_count {
                    break;
                }
                validator_match = signer == storage.validators.get(validator_index).unwrap().read();
                if !validator_match {
                    validator_index += 1;
                }
            }

            // Fail if we never found a match
            require(validator_match, MessageIdMultisigError::NoValidatorMatch);

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
    let threshold = storage.threshold.read();
    (validators, threshold)
}

fn _signature_at(metadata: Bytes, index: u32) -> Bytes {
    MessageIdMultisigIsmMetadata::new(metadata).signature_at(index)
}

// fn _to_compact_signature(signature: Bytes) -> Option<B512> {
//     // Ensure the signature is properly formatted
//     if signature.len() != 65 {
//         return None
//     }
//     let (r, rest) = signature.split_at(32);
//     let (s, v) = rest.split_at(32);
//     let r_bytes: b256 = BufferReader::from_parts(r.ptr(), r.len()).decode();
//     let r_bytes: [u8; 32] = r_bytes.to_be_bytes();
//     let mut y_parity_and_s_bytes: b256 = BufferReader::from_parts(s.ptr(), s.len()).decode();
//     let mut y_parity_and_s_bytes: [u8; 32] = y_parity_and_s_bytes.to_be_bytes();
//     let v = v.read_u8(0);
//     if v == 28 {
//         y_parity_and_s_bytes[0] = __or(y_parity_and_s_bytes[0], 0x80);
//     }

//     let buffer = Buffer::new();
//     let buffer = y_parity_and_s_bytes.abi_encode(buffer);
//     let bytes = Bytes::from(buffer.as_raw_slice());
//     let y_parity_and_s_bytes = b256::from(bytes);

//     let buffer = Buffer::new();
//     let buffer = r_bytes.abi_encode(buffer);
//     let bytes = Bytes::from(buffer.as_raw_slice());
//     let r_bytes = b256::from(bytes);
//     Some(B512::from((r_bytes, y_parity_and_s_bytes)))
// }
