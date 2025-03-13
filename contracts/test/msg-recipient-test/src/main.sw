contract;

use std::{bytes::Bytes, logging::log};
use interfaces::message_recipient::MessageRecipient;

abi TestMessageRecipient {
    #[storage(read)]
    fn handled() -> bool;

    #[storage(read, write)]
    fn set_ism(module: ContractId);
}

storage {
    module: ContractId = ContractId::from(b256::zero()),
    handled: bool = false,
}

impl MessageRecipient for Contract {
    #[storage(read, write)]
    fn handle( _origin: u32, _sender: b256, _message_body: Bytes) {
        storage.handled.write(true);
    }

    #[storage(read)]
    fn interchain_security_module() -> ContractId {
        storage.module.read()
    }
}

impl TestMessageRecipient for Contract {
    #[storage(read)]
    fn handled() -> bool {
        storage.handled.read()
    }

    #[storage(read, write)]
    fn set_ism(module: ContractId) {
        storage.module.write(module)
    }
}
