contract;

use std::bytes::Bytes;
use interfaces::hooks::post_dispatch_hook::*;

storage {
    called: bool = false,
    quote: u64 = 0
}

impl PostDispatchHook for Contract {
    fn hook_type() -> PostDispatchHookType {
        PostDispatchHookType::UNUSED
    }

    fn supports_metadata(_metadata: Bytes) -> bool {
        true
    }

    #[payable]
    #[storage(read, write)]
    fn post_dispatch(_metadata: Bytes, _message: Bytes) {
        storage.called.write(true);
    }

    #[storage(read)]
    fn quote_dispatch(_metadata: Bytes, _message: Bytes) -> u64 {
        storage.quote.read()
    }
}

abi TestFuctions {
    #[storage(read)]
    fn was_called() -> bool;

    #[storage(write)]
    fn set_quote(quote: u64);
}

impl TestFuctions for Contract {
    #[storage(read)]
    fn was_called() -> bool {
        storage.called.read()
    }

    #[storage(write)]
    fn set_quote(quote: u64) {
        storage.quote.write(quote);
    }
}
