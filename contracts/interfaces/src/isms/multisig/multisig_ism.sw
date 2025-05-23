library;

use std::{bytes::Bytes, vm::evm::evm_address::EvmAddress};

pub enum MerkleRootMultisigError {
    NoMultisigThreshold: (),
    NoValidatorMatch: (),
    FailedToRecoverSigner: (),
    InvalidMerkleIndexMetadata: (),
    FailedToRecoverSignature: Bytes,
    AlreadyInitialized: (),
    UnexpectedInitAddress: (),
}

pub enum MessageIdMultisigError {
    NoMultisigThreshold: (),
    NoValidatorMatch: (),
    FailedToRecoverSigner: (),
    FailedToRecoverSignature: Bytes,
    UnexpectedInitAddress: (),
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
// Since Mutltisig ISMs are static and we do not have factories, we get around this to mimic the 
// way they would be deployed on the EVM
abi MultisigIsmFunctions {
    /// Initializes the Multisig ISM with the given validators.
    /// Threshold is excluded since it's a configurable set at deployment.
    ///
    /// ### Arguments
    ///
    /// * `validators`: [Vec<EvmAddress>] - The list of validators which can approve messages.
    #[storage(read, write)]
    fn initialize(validators: Vec<EvmAddress>);
}
