contract;

use interfaces::{
    ownable::*,
    isms::ism::*
};
use standards::src5::State;
use sway_libs::{ownership::*, pausable::*};
use std::{bytes::Bytes};

configurable {
    EXPECTED_OWNER: b256 = b256::zero(),
}

impl InterchainSecurityModule for Contract {
    /// Returns an enum that represents the type of security model
    /// encoded by this ISM. Relayers infer how to fetch and format metadata.
    ///
    /// ### Returns
    ///
    /// * [ModuleType] - The type of security model.
    fn module_type() -> ModuleType {
        ModuleType::NULL
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
    /// * If the contract is paused.
    #[storage(read)]
    fn verify(_metadata: Bytes, _message: Bytes) -> bool {
        require_not_paused();
        true
}
}


/// All other functions for the PausableIsm Hyperlane interface are inherited through the Pausable abi.
/// Source: [sway-libs](https://github.com/FuelLabs/sway-libs/blob/master/libs/src/pausable.sw)
impl Pausable for Contract {
    #[storage(write)]
    fn pause() {
        only_owner();
        _pause();
    }

    #[storage(write)]
    fn unpause() {
        only_owner();
        _unpause();
    }

    #[storage(read)]
    fn is_paused() -> bool {
        _is_paused()
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
        _is_expected_owner(new_owner);
        initialize_ownership(new_owner);
    }

    #[storage(read, write)]
    fn renounce_ownership() {
        renounce_ownership();
    }
}



// Front-run guard
fn _is_expected_owner(owner: Identity) {
    require(owner.bits() == EXPECTED_OWNER, OwnableError::UnexpectedOwner);
}
