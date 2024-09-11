library;

use std::{bytes::Bytes, vm::evm::evm_address::EvmAddress};

/// Official Routing ISM interface for Hyperlane V3
abi RoutingIsm {
    /// Returns the ISM responsible for verifying the message.
    ///
    /// ### Arguments
    ///
    /// * `message`: [Bytes] - Formatted Hyperlane message
    ///
    /// ### Returns
    ///
    /// * [b256] - The ISM to use to verify the message
    #[storage(read)]
    fn route(message: Bytes) -> b256;
}
