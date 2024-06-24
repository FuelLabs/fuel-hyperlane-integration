contract;

use std::{bytes::Bytes, constants::ZERO_B256, logging::log};
use interfaces::message_recipient::MessageRecipient;

abi TestMessageRecipient {
    #[storage(read)]
    fn handled() -> bool;

}

storage {
    module: ContractId = ContractId::from(ZERO_B256),
    handled: bool = false,
}

impl MessageRecipient for Contract {
    #[storage(read, write)]
    fn handle(origin: u32, sender: b256, message_body: Bytes) {
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

}
