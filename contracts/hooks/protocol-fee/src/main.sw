contract;

use std::{
    asset::transfer,
    auth::msg_sender,
    bytes::Bytes,
    call_frames::msg_asset_id,
    constants::ZERO_B256,
    context::{
        msg_amount,
        this_balance,
    },
    revert::revert,
};

use sway_libs::ownership::*;
use standards::src5::State;
use std_hook_metadata::*;
use interfaces::{hooks::{post_dispatch_hook::*, protocol_fee::*}, ownable::*,};

configurable {
    MAX_PROTOCOL_FEE: u64 = 0,
}

storage {
    /// The current protocol fee
    protocol_fee: u64 = 0,
    /// The beneficiary of protocol fees
    beneficiary: Identity = Identity::ContractId(ContractId::zero()),
}

impl ProtocolFee for Contract {
    /// Initializes the ProtocolFee contract.
    ///
    /// ### Arguments
    ///
    /// * `max_protocol_fee`: [u64] - The maximum protocol fee that can be set
    /// * `protocol_fee`: [u64] - The current protocol fee
    /// * `beneficiary`: [Identity] - The beneficiary of protocol fees
    /// * `owner`: [Identity] - The owner of the contract
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized
    /// * If the beneficiary is invalid
    #[storage(read, write)]
    fn initialize(protocol_fee: u64, beneficiary: Identity, owner: Identity) {
        initialize_ownership(owner);
        _set_beneficiary(beneficiary);
        _set_protocol_fee(protocol_fee);
    }

    /// Returns the maximum protocol fee that can be set
    ///
    /// ### Returns
    ///
    /// * [u64] - The maximum protocol fee
    fn max_protocol_fee() -> u64 {
        MAX_PROTOCOL_FEE
    }

    /// Returns the current protocol fee
    ///
    /// ### Returns
    ///
    /// * [u64] - The current protocol fee
    #[storage(read)]
    fn protocol_fee() -> u64 {
        storage.protocol_fee.read()
    }

    /// Sets the protocol fee to `new_fee`. Only callable by the owner.
    ///
    /// ### Arguments
    ///
    /// * `new_fee`: [u64] - The new protocol fee
    ///
    /// ### Reverts
    ///
    /// * If the caller is not the owner
    /// * If the new fee exceeds the maximum protocol fee
    #[storage(read, write)]
    fn set_protocol_fee(new_fee: u64) {
        only_owner();
        _set_protocol_fee(new_fee);
    }

    /// Collects protocol fees.
    ///
    #[storage(read)]
    fn collect_protocol_fees() {
        _collect_protocol_fees(None);
    }

    /// Gets the current beneficiary.
    ///
    /// ### Returns
    ///
    /// * [Identity] - The beneficiary.
    #[storage(read)]
    fn beneficiary() -> Identity {
        storage.beneficiary.read()
    }

    /// Sets the beneficiary to `beneficiary`. Only callable by the owner.
    ///
    /// ### Arguments
    ///
    /// * `beneficiary`: [Identity] - The new beneficiary.
    ///
    /// ### Reverts
    ///
    /// * If the caller is not the owner.
    #[storage(read, write)]
    fn set_beneficiary(beneficiary: Identity) {
        only_owner();
        _set_beneficiary(beneficiary);
    }
}

impl PostDispatchHook for Contract {
    /// Returns the type of the hook
    ///
    /// ### Returns
    ///
    /// * [PostDispatchHookType] - The type of the hook
    fn hook_type() -> PostDispatchHookType {
        PostDispatchHookType::PROTOCOL_FEE
    }

    /// Checks if the metadata is valid
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata to check
    ///
    /// ### Returns
    ///
    /// * [bool] - Whether the metadata is valid
    #[storage(read)]
    fn supports_metadata(metadata: Bytes) -> bool {
        StandardHookMetadata::is_valid(metadata)
    }

    /// Handles the post-dispatch hook.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata to handle
    /// * `message`: [Bytes] - The message to handle
    ///
    /// ### Reverts
    ///
    /// * If the metadata is invalid
    /// * If the protocol fee is insufficient
    #[payable]
    #[storage(read, write)]
    fn post_dispatch(metadata: Bytes, _message: Bytes) {
        let metadata_valid = StandardHookMetadata::is_valid(metadata);
        require(metadata_valid, ProtocolFeeError::UnsupportedMetadataFormat);

        let fee = storage.protocol_fee.read();
        require(
            msg_amount() >= fee,
            ProtocolFeeError::InsufficientProtocolFee,
        );

        let refund_amount = msg_amount() - fee;
        if refund_amount > 0 {
            let sender = msg_sender().unwrap().bits();
            let refund_address = StandardHookMetadata::get_refund_address(metadata, sender);
            let refund_identity = Identity::Address(Address::from(refund_address));
            transfer(refund_identity, AssetId::base(), refund_amount);
        }
    }

    /// Computes the payment required by the postDispatch call
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata required for the hook.
    /// * `message`: [Bytes] - The message to handle
    ///
    /// ### Returns
    ///
    /// * [u64] - The payment required
    #[storage(read)]
    fn quote_dispatch(_metadata: Bytes, _message: Bytes) -> u64 {
        storage.protocol_fee.read()
    }
}

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

// ------------------------------------------------------------
// ------------------ Internal Functions ----------------------
// ------------------------------------------------------------

/// Collects protocol fees.
///
/// ### Arguments
///
/// * `asset`: [Option<AssetId>] - The asset to collect fees from.
#[storage(read)]
fn _collect_protocol_fees(asset: Option<AssetId>) {
    let beneficiary = storage.beneficiary.read();
    let amount = this_balance(asset.unwrap_or(AssetId::base()));
    transfer(beneficiary, asset.unwrap_or(AssetId::base()), amount);
}

/// Sets the protocol fee to `new_fee`.
///
/// ### Arguments
///
/// * `new_fee`: [u64] - The new protocol fee.
#[storage(read, write)]
fn _set_protocol_fee(new_fee: u64) {
    require(
        new_fee <= MAX_PROTOCOL_FEE,
        ProtocolFeeError::ExceedsMaxProtocolFee,
    );

    storage.protocol_fee.write(new_fee);
    log(ProtocolFeeSet {
        protocol_fee: new_fee,
    });
}

/// Sets the beneficiary to `beneficiary`. Only callable by the owner.
///
/// ### Arguments
///
/// * `beneficiary`: [Identity] - The new beneficiary.
#[storage(read, write)]
fn _set_beneficiary(beneficiary: Identity) {
    require(
        beneficiary
            .bits() != ZERO_B256,
        ProtocolFeeError::InvalidBeneficiary,
    );
    storage.beneficiary.write(beneficiary);
    log(BeneficiarySetEvent {
        beneficiary: beneficiary,
    });
}
