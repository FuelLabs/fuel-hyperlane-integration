library;

use sway_libs::ownership::*;
use standards::src5::State;

abi Ownable {
    /// Returns the owner of the contract.
    ///
    /// ### Returns
    ///
    /// * [State] - The owner of the contract.
    #[storage(read)]
    fn owner() -> State;

    /// Checks if the caller is the owner of the contract.
    #[storage(read)]
    fn only_owner();

    /// Transfers ownership of the contract to a new address.
    ///
    /// ### Arguments
    ///
    /// * `new_owner`: [Identity] - The address of the new owner.
    #[storage(write)]
    fn transfer_ownership(new_owner: Identity);

    /// Sets the owner of the contract.
    ///
    /// ### Arguments
    ///
    /// * `new_owner`: [Identity] - The address of the new owner.
    #[storage(read, write)]
    fn initialize_ownership(new_owner: Identity);

    /// Revokes ownership of the contract.
    #[storage(read, write)]
    fn renounce_ownership();
}


pub enum OwnableError {
    UnexpectedOwner: (),
}