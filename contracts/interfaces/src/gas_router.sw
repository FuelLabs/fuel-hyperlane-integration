library;

use std::{bytes::Bytes, storage::*};
use message::EncodedMessage;


pub struct GasRouterConfig {
    pub domain: u32,
    pub gas: u64,
}

/// Interface for the GasRouter contract which handles gas for cross-chain token transfers
abi GasRouter {
    /// Sets the gas amount dispatched for each configured domain
    ///
    /// ### Arguments
    ///
    /// * `gasConfigs`: [Vec<GasRouterConfig>] - The array of GasRouterConfig structs
    #[storage(write)]
    fn set_destination_gas_configs(gas_configs: Vec<GasRouterConfig>);

    /// Sets the gas amount dispatched for a specific domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The destination domain ID
    /// * `gas`: [u64] - The gas limit
    #[storage(write)]
    fn set_destination_gas(domain: u32, gas: u64);

    /// Gets the metadata for the GasRouter hook
    ///
    /// ### Arguments
    ///
    /// * `destination`: [u32] - The destination domain ID
    ///
    /// ### Returns
    ///
    /// * [Bytes] - The metadata for the GasRouter hook
    #[storage(read)]
    fn gas_router_hook_metadata(destination: u32) -> Bytes;

    /// Gets the gas amount dispatched for a specific domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The destination domain ID
    ///
    /// ### Returns
    ///
    /// * [u64] - The gas limit
    #[storage(read)]
    fn destination_gas(domain: u32) -> u64;
}
