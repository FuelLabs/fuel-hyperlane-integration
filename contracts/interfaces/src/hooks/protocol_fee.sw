library;

use std::bytes::Bytes;

/// Errors that can be emitted by the ProtocolFee contract
pub enum ProtocolFeeError {
    /// The provided protocol fee payment was insufficient
    InsufficientProtocolFee: (),
    /// The provided protocol fee exceeds the maximum allowed
    ExceedsMaxProtocolFee: (),
    /// The provided beneficiary address/contract is invalid (zero)
    InvalidBeneficiary: (),
    /// The protocol fee contract is already initialized
    ProtocolFeeAlreadyInitialized: (),
    /// The protocol fee contract is not initialized
    ProtocolFeeNotInitialized: (),
    /// The metadata is not valid
    UnsupportedMetadataFormat: (),
}

abi ProtocolFee {
    /// Initializes the protocol fee contract.
    ///
    /// ### Arguments
    ///
    /// * `max_protocol_fee`: [u64] - The maximum protocol fee that can be set
    /// * `protocol_fee`: [u64] - The initial protocol fee
    /// * `beneficiary`: [Identity] - The beneficiary of protocol fees
    /// * `owner`: [Identity] - The owner of the contract
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized
    /// * If protocol_fee > max_protocol_fee
    /// * If beneficiary is zero address/contract
    #[storage(read, write)]
    fn initialize(max_protocol_fee: u64, protocol_fee: u64, beneficiary: Identity, owner: Identity);

    /// Sets a new protocol fee.
    ///
    /// ### Arguments
    ///
    /// * `new_fee`: [u64] - The new protocol fee to set
    ///
    /// ### Reverts
    ///
    /// * If caller is not the owner
    /// * If new_fee > max_protocol_fee
    ///
    /// ### Events
    ///
    /// * ProtocolFeeSet - Emitted when the protocol fee is updated
    #[storage(read, write)]
    fn set_protocol_fee(new_fee: u64);

    /// Collects accumulated protocol fees and sends them to the beneficiary.
    ///
    /// ### Reverts
    ///
    /// * If transfer to beneficiary fails
    #[storage(read)]
    fn collect_protocol_fees();

    /// Returns the maximum protocol fee that can be set
    #[storage(read)]
    fn max_protocol_fee() -> u64;

    /// Returns the current protocol fee
    #[storage(read)]
    fn protocol_fee() -> u64;
}

/// Events emitted by the ProtocolFee contract
pub struct ProtocolFeeSet {
    /// The new protocol fee that was set
    pub protocol_fee: u64,
}

pub struct BeneficiarySet {
    /// The new beneficiary that was set
    pub beneficiary: Identity,
}