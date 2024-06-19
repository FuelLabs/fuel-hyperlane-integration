library;

use sway_libs::ownership::*;

abi Ownable {
    /// Returns the owner of the contract.
    #[storage(read)]
    fn owner() -> Address;

    /// Transfers ownership of the contract to a new address.
    ///
    /// ### Arguments
    ///
    /// * `new_owner` - The address of the new owner.
    #[storage(write)]
    fn transfer_ownership(new_owner: Address);

    /// Sets the owner of the contract.
    ///
    /// ### Arguments
    ///
    /// * `new_owner` - The address of the new owner.
    #[storage(write)]
    fn set_owner(new_owner: Address);
}
