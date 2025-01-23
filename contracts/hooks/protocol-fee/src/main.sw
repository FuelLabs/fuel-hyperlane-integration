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
use interfaces::{claimable::*, hooks::{post_dispatch_hook::*, protocol_fee::*}, ownable::*,};

storage {
    /// The maximum protocol fee that can be set
    max_protocol_fee: u64 = 0,
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
    fn initialize(
        max_protocol_fee: u64,
        protocol_fee: u64,
        beneficiary: Identity,
        owner: Identity,
    ) {
        require(
            !_is_initialized(),
            ProtocolFeeError::ProtocolFeeAlreadyInitialized,
        );
        require(
            beneficiary
                .bits() != ZERO_B256,
            ProtocolFeeError::InvalidBeneficiary,
        );

        initialize_ownership(owner);
        storage.beneficiary.write(beneficiary);
        storage.max_protocol_fee.write(max_protocol_fee);
        _set_protocol_fee(protocol_fee);
    }

    /// Returns the maximum protocol fee that can be set
    ///
    /// ### Returns
    ///
    /// * [u64] - The maximum protocol fee
    #[storage(read)]
    fn max_protocol_fee() -> u64 {
        storage.max_protocol_fee.read()
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
        require(_is_initialized(), ProtocolFeeError::ProtocolFeeNotInitialized);

        _set_protocol_fee(new_fee);
    }

    /// Collects protocol fees.
    ///
    /// ### Reverts
    ///
    /// * If the contract is not initialized
    #[storage(read)]
    fn collect_protocol_fees() {
        _collect_protocol_fees(None);
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
    /// * If the contract is not initialized
    /// * If the metadata is invalid
    /// * If the protocol fee is insufficient
    #[payable]
    #[storage(read, write)]
    fn post_dispatch(metadata: Bytes, _message: Bytes) {
        require(_is_initialized(), ProtocolFeeError::ProtocolFeeNotInitialized);

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

impl Claimable for Contract {
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
        require(
            beneficiary
                .bits() != ZERO_B256,
            ProtocolFeeError::InvalidBeneficiary,
        );
        storage.beneficiary.write(beneficiary);
        log(BeneficiarySetEvent {
            beneficiary: beneficiary.bits(),
        });
    }

    /// Sends all base asset funds to the beneficiary. Callable by anyone.
    ///
    /// ### Arguments
    ///
    /// * `asset`: [Option<AssetId>] - The asset to collect fees from, defaults to base asset.
    #[storage(read)]
    fn claim(asset: Option<AssetId>) {
        _collect_protocol_fees(asset);
    }
}

// ------------------------------------------------------------
// ------------------ Internal Functions ----------------------
// ------------------------------------------------------------

/// Checks if the contract is initialized.
///
/// ### Returns
///
/// * [bool] - Whether the contract is initialized.
#[storage(read)]
fn _is_initialized() -> bool {
    _owner() != State::Uninitialized
}

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
    let max_protocol_fee = storage.max_protocol_fee.read();
    require(
        new_fee <= max_protocol_fee,
        ProtocolFeeError::ExceedsMaxProtocolFee,
    );

    storage.protocol_fee.write(new_fee);
    log(ProtocolFeeSet {
        protocol_fee: new_fee,
    });
}
