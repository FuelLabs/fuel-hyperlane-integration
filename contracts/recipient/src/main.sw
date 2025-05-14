contract;

use std::{
    bytes::Bytes,
    logging::log,
    context::msg_amount,
    storage::storage_string::*,
    contract_id::ContractId,
    string::String
};
use sway_libs::ownership::*;
use standards::src5::State;
use interfaces::{message_recipient::MessageRecipient, ownable::*};

configurable {
    EXPECTED_OWNER: b256 = b256::zero(),
}

storage {
    interchain_security_module: ContractId = ContractId::from(b256::zero()),
    last_sender: b256 = b256::zero(),
    last_data: StorageString = StorageString {},
    last_caller: Identity = Identity::ContractId(ContractId::from(b256::zero())),
    last_call_message:StorageString = StorageString {}
}


pub struct ReceivedCallEvent {
    pub caller: Identity,
    pub amount: u64,
    pub message: String,
}

pub struct ReceivedMessageEvent{
    pub origin: u32,
    pub sender: b256,
    pub value: u64,
    pub message: Bytes
}


abi TestMessageRecipient {
    #[storage(write)]
    fn foo_bar(amount: u64, message: String);

    #[storage(write)]
    fn set_interchain_security_module(ism: ContractId);

    #[storage(read)]
    fn last_sender() -> b256;

    #[storage(read)]
    fn last_data() -> Option<String>;

    #[storage(read)]
    fn last_caller() -> Identity;
    
    #[storage(read)]
    fn last_call_message() -> Option<String>;
}

impl MessageRecipient for Contract {
    #[storage(read, write)]
    fn handle( origin: u32, sender: b256, message_body: Bytes) {
        log(ReceivedMessageEvent { origin, sender, value: msg_amount(), message: message_body  });
        storage.last_sender.write(sender);
        storage.last_data.write_slice(String::from_ascii(message_body));
    }

    #[storage(read)]
    fn interchain_security_module() -> ContractId {
        storage.interchain_security_module.read()
    }
}

impl TestMessageRecipient for Contract {
    #[storage(write)]
    fn foo_bar(amount: u64, message: String) {
        log(ReceivedCallEvent { caller: msg_sender().unwrap(),  amount, message });
        storage.last_caller.write(msg_sender().unwrap());
        storage.last_call_message.write_slice(message);
    }

    #[storage(write)]
    fn set_interchain_security_module(ism: ContractId) {
        only_owner();
        storage.interchain_security_module.write(ism);
    }

    #[storage(read)]
    fn last_sender() -> b256 {
        storage.last_sender.read()
    }

    #[storage(read)]
    fn last_data() -> Option<String> {
        storage.last_data.read_slice()
    }

    #[storage(read)]
    fn last_caller() -> Identity {
        storage.last_caller.read()
    }
    
    #[storage(read)]
    fn last_call_message() -> Option<String> {
        storage.last_call_message.read_slice()
    }

}

impl Ownable for Contract {
    #[storage(read)]
    fn owner() -> State {
        _owner()
    }

    #[storage(read)]
    fn only_owner() {
        only_owner();
    }

    #[storage(write)]
    fn transfer_ownership(new_owner: Identity) {
        transfer_ownership(new_owner);
    }

    #[storage(read, write)]
    fn initialize_ownership(new_owner: Identity) {
        _is_expected_owner(new_owner);
        initialize_ownership(new_owner);
    }

    #[storage(read, write)]
    fn renounce_ownership() {
        renounce_ownership();
    }
}

// Front-run guard
fn _is_expected_owner(owner: Identity) {
    require(owner.bits() == EXPECTED_OWNER, OwnableError::UnexpectedOwner);
}
