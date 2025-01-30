library;

use std::{bytes::Bytes, vm::evm::evm_address::EvmAddress};

pub enum MerkleRootMultisigError {
    NoMultisigThreshold: (),
    NoValidatorMatch: (),
    FailedToRecoverSigner: (),
    InvalidMerkleIndexMetadata: (),
    FailedToRecoverSignature: Bytes,
}

pub enum MessageIdMultisigError {
    NoMultisigThreshold: (),
    NoValidatorMatch: (),
    FailedToRecoverSigner: (),
    FailedToRecoverSignature: Bytes,
}

// Official Multisig ISM interface for Hyperlane V3
abi MultisigIsm {
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
    fn validators_and_threshold(message: Bytes) -> (Vec<EvmAddress>, u8);

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
    fn digest(metadata: Bytes, message: Bytes) -> Bytes;

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
    fn signature_at(metadata: Bytes, index: u32) -> Bytes;
}

// Additional functions added for the fully functional implementation of the Multisig ISM
abi MultisigIsmFunctions {
    /// Enrolls a validator to the Multisig ISM.
    ///
    /// ### Arguments
    ///
    /// * `validator`: [EvmAddress] - The address of the validator to be enrolled.
    #[storage(write)]
    fn enroll_validator(validator: EvmAddress);

    /// Sets the threshold for the Multisig ISM.
    ///
    /// ### Arguments
    ///
    /// * `threshold`: [u8] - The threshold of approval for the Multisig ISM.
    #[storage(write)]
    fn set_threshold(threshold: u8);
}
