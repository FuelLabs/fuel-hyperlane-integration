contract;

use interfaces::isms::ism::*;
use message::Message;
use std::bytes::Bytes;

storage {
    accept: bool = true,
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
    #[storage(read)]
    fn verify(_metadata: Bytes, _message: Bytes) -> bool {
        storage.accept.read()
    }

    fn module_type() -> ModuleType {
        ModuleType::UNUSED
    }
}
