library;

use std::bytes::Bytes;

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

abi PostDispatchHook {
    #[storage(read)]
    fn hook_type() -> PostDispatchHookType;

    #[storage(read)]
    fn supports_metadata(metadata: Bytes) -> bool;

    #[payable]
    #[storage(read, write)]
    fn post_dispatch(metadata: Bytes, message: Bytes);

    #[storage(read)]
    fn quote_dispatch(metadata: Bytes, message: Bytes) -> u64;
}
