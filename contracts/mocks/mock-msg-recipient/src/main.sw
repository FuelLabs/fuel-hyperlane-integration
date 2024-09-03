contract;

use std::bytes::Bytes;
use interfaces::message_recipient::*;

// Used to generate the ABI of the contract
impl MessageRecipient for Contract {
    #[storage(read, write)]
    fn handle(_origin: u32, _sender: b256, _message_body: Bytes) {}

    #[storage(read)]
    fn interchain_security_module() -> ContractId {
        ContractId::zero()
    }
}
