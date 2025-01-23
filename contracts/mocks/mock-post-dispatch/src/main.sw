contract;

use std::bytes::Bytes;
use interfaces::hooks::post_dispatch_hook::*;

impl PostDispatchHook for Contract {
    fn hook_type() -> PostDispatchHookType {
        PostDispatchHookType::UNUSED
    }

    #[storage(read)]
    fn supports_metadata(metadata: Bytes) -> bool {
        true
    }

    #[payable]
    #[storage(read, write)]
    fn post_dispatch(metadata: Bytes, message: Bytes) {
        // Do nothing
    }

    #[storage(read)]
    fn quote_dispatch(metadata: Bytes, message: Bytes) -> u64 {
        0
    }
}
