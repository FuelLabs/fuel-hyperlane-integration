library;

use std::bytes::Bytes;

pub enum PostDispatchHookError {
    InvalidMetadata: (),
}

/// Types of post dispatch hooks.
pub enum PostDispatchHookType {
    UNUSED: (),
    ROUTING: (),
    AGGREGATION: (),
    MERKLE_TREE: (),
    INTERCHAIN_GAS_PAYMASTER: (),
    FALLBACK_ROUTING: (),
    ID_AUTH_ISM: (),
    PAUSABLE: (),
    PROTOCOL_FEE: (),
    LAYER_ZERO_V1: (),
    RATE_LIMITED_HOOK: (),
}

///  Official PostDispatchHook interface for Hyperlane V3
abi PostDispatchHook {
    /// Returns an enum that represents the type of hook
    ///
    /// ### Returns
    ///
    /// * [PostDispatchHookType] - The type of the hook.
    fn hook_type() -> PostDispatchHookType;

    /// Returns whether the hook supports metadata
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata to be checked.
    ///
    /// ### Returns
    ///
    /// * [bool] - Whether the hook supports the metadata.
    fn supports_metadata(metadata: Bytes) -> bool;

    /// Post action after a message is dispatched via the Mailbox
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata required for the hook.
    /// * `message`: [Bytes] - The message to be processed.
    #[payable]
    #[storage(read, write)]
    fn post_dispatch(metadata: Bytes, message: Bytes);

    /// Compute the payment required by the postDispatch call
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata required for the hook.
    /// * `message`: [Bytes] - The message to be processed.
    ///
    /// ### Returns
    ///
    /// * [u64] - The payment required for the postDispatch call.
    #[storage(read)]
    fn quote_dispatch(metadata: Bytes, message: Bytes) -> u64;
}
