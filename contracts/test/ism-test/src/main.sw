contract;

use interfaces::ism::{InterchainSecurityModule, ModuleType};
use message::Message;
use std::bytes::Bytes;

storage {
    accept: bool = true,
    module_type: ModuleType = ModuleType::UNUSED_0,
}

abi TestISM {
    #[storage(write)]
    fn set_accept(accept: bool);
}

impl TestISM for Contract {
    #[storage(write)]
    fn set_accept(accept: bool) {
        storage.accept.write(accept);
    }
}

impl InterchainSecurityModule for Contract {
    #[storage(read, write)]
    fn verify(metadata: Bytes, message: Bytes) -> bool {
        storage.accept.read()
    }

    #[storage(read)]
    fn module_type() -> ModuleType {
        storage.module_type.read()
    }
}
