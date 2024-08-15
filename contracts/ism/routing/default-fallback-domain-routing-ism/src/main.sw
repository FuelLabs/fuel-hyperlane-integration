contract;

use std::{bytes::Bytes, hash::*, storage::storage_vec::*};
use standards::src5::State;
use sway_libs::{ownership::*};
use interfaces::{mailbox::mailbox::Mailbox, isms::{ism::*, routing::{default_fallback_domain_routing_ism::*, routing_ism::*}}, ownable::*};
use message::{EncodedMessage, Message};

enum DefaultFallbackDomainRoutingIsmError {
    AlreadyInitialized:(),
    NotInitialized:(),
    DomainModuleLengthMismatch:(u64, u64),
}

storage {
    domain_modules: StorageMap<u32, b256> = StorageMap {},
    domains: StorageVec<u32> = StorageVec {},
    mailbox: b256 = b256::zero(),
}

impl InterchainSecurityModule for Contract {
    fn module_type() -> ModuleType {
        ModuleType::ROUTING
    }

    #[storage(read)]
    fn verify(metadata: Bytes, message: Bytes) -> bool {
        only_initialized();

        let ism_id = _route(message);
        let ism = abi(InterchainSecurityModule, ism_id);
        ism.verify(metadata, message)
    }
}

impl RoutingIsm for Contract {
    #[storage(read)]
    fn route(message: Bytes) -> b256 {
        only_initialized();

        _route(message)
    }
}

impl DefaultFallbackDomainRoutingIsm for Contract {
    #[storage(write, read)]
    fn initialize(owner: b256, mailbox: b256){
        only_not_initialized();

        initialize_ownership(Identity::Address(Address::from(owner)));
        storage.mailbox.write(mailbox);
    }

    #[storage(write, read)]
    fn initialize_with_domains(owner: b256, mailbox: b256, domains: Vec<u32>, modules: Vec<b256>) {
        only_not_initialized();

        initialize_ownership(Identity::Address(Address::from(owner)));
        storage.mailbox.write(mailbox);
        let domain_count = domains.len();
        let module_count = modules.len();
        require(
            domain_count == module_count,
            DefaultFallbackDomainRoutingIsmError::DomainModuleLengthMismatch((domain_count, module_count)),
        );

        let mut domains = domains;
        let mut modules = modules;

        while true {
            let domain = domains.pop();
            let module = modules.pop();
            if domain.is_some() && module.is_some() {
                _set(domain.unwrap(), module.unwrap());
            } else {
                break;
            }
        }
        

    }

    #[storage(write, read)]
    fn set(domain: u32, module: b256) {
        only_initialized();
        only_owner();

        _set(domain, module);
    }   

    #[storage(write, read)]
    fn remove(domain: u32) {
        only_initialized();
        only_owner();

        let success = storage.domain_modules.remove(domain);
        if success {
            _remove_domain(domain);
        }
    }

    #[storage(read)]
    fn domains() -> Vec<u32> {
        storage.domains.load_vec()
    }

    #[storage(read)]
    fn module(domain: u32) -> b256 {
        storage.domain_modules.get(domain).try_read().unwrap_or(b256::zero())
    }
}

// --- Ownable implementation ---

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
        initialize_ownership(new_owner);
    }

    #[storage(read, write)]
    fn renounce_ownership() {
        renounce_ownership();
    }
}


// --- Internal functions ---

#[storage(read)]
fn _route(message: Bytes) -> b256 {
    let domain = EncodedMessage::from_bytes(message).origin();
    let module = storage.domain_modules.get(domain).try_read().unwrap_or(b256::zero());

    if module != b256::zero() {
        return module;
    }
    let mailbox_id = storage.mailbox.read();
    let mailbox = abi(Mailbox, mailbox_id);
    <b256 as From<ContractId>>::from(mailbox.default_ism())

        
}

#[storage(read)]
fn _domain_exists(domain: u32) -> bool {
    let domains = storage.domains.load_vec();

    for d in domains.iter() {
        if d == domain {
            return true;
        }
    }
    return false;
}

#[storage(read, write)]
fn _remove_domain(domain: u32) {
    let domains = storage.domains.load_vec();
    let mut index = 0;
    for d in domains.iter() {
        if d == domain {
            let _ = storage.domains.remove(index);
            return;
        }
        index += 1;
    }
}

#[storage(write, read)]
fn _set(domain: u32, module: b256) {
    if !_domain_exists(domain) {
        storage.domains.push(domain);
    }
    storage.domain_modules.insert(domain, module);
}

// --- Guards ---

#[storage(read)]
fn only_not_initialized() {
    require(
        _owner() == State::Uninitialized,
        DefaultFallbackDomainRoutingIsmError::AlreadyInitialized,
    );
}

#[storage(read)]
fn only_initialized() {
    require(
        _owner() != State::Uninitialized,
        DefaultFallbackDomainRoutingIsmError::NotInitialized,
    );
}