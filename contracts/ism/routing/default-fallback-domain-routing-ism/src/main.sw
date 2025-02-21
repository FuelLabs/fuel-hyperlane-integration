contract;

use std::{bytes::Bytes, hash::*, storage::storage_vec::*};
use standards::src5::State;
use sway_libs::{ownership::*};
use interfaces::{mailbox::mailbox::Mailbox, isms::{ism::*, routing::{default_fallback_domain_routing_ism::*, routing_ism::*}}, ownable::*};
use message::{EncodedMessage, Message};

configurable {
    EXPECTED_OWNER: b256 = b256::zero(),
}

storage {
    /// Mapping of modules which are used for specific domains.
    domain_modules: StorageMap<u32, b256> = StorageMap {},
    /// List of domains that have been set.
    domains: StorageVec<u32> = StorageVec {},
    /// Address of the mailbox from which the default ISM is fetched.
    mailbox: b256 = b256::zero(),
}

impl InterchainSecurityModule for Contract {
    /// Returns an enum that represents the type of security model
    /// encoded by this ISM. Relayers infer how to fetch and format metadata.
    ///
    /// ### Returns
    ///
    /// * [ModuleType] - The type of security model.
    fn module_type() -> ModuleType {
        ModuleType::ROUTING
    }

    /// Verifies the message using the metadata.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata to be used for verification.
    /// * `message`: [Bytes] - The message to be verified.
    ///
    /// ### Returns
    ///
    /// * [bool] - True if the message is verified successfully.
    ///
    /// ### Reverts
    ///
    /// * If the ISM call fails.
    #[storage(read)]
    fn verify(metadata: Bytes, message: Bytes) -> bool {
        let ism_id = _route(message);
        let ism = abi(InterchainSecurityModule, ism_id);
        ism.verify(metadata, message)
    }
}

impl RoutingIsm for Contract {
    /// Returns the ISM responsible for verifying the message.
    ///
    /// ### Arguments
    ///
    /// * `message`: [Bytes] - Formatted Hyperlane message
    ///
    /// ### Returns
    ///
    /// * [b256] - The ISM to use to verify the message
    #[storage(read)]
    fn route(message: Bytes) -> b256 {
        _route(message)
    }
}

impl DefaultFallbackDomainRoutingIsm for Contract {
    /// Sets the owner and mailbox of the ISM.
    ///
    /// ### Arguments
    ///
    /// * `owner`: [Identity] - The address of the owner.
    /// * `mailbox`: [b256] - The address of the mailbox.
    ///
    /// ### Reverts
    ///
    /// * If the ISM is already initialized.
    #[storage(write, read)]
    fn initialize(owner: Identity, mailbox: b256){
        initialize_ownership(owner);
        storage.mailbox.write(mailbox);
    }

    /// Sets the ISMs to be used for the specified origin domains
    ///
    /// ### Arguments
    ///
    /// * `owner`: [Identity] - The address of the owner.
    /// * `mailbox`: [b256] - The address of the mailbox.
    /// * `domains`: [Vec<u32>] - The list of origin domains.
    /// * `modules`: [Vec<b256>] - The list of ISMs to be used for the specified domains.
    ///
    /// ### Reverts
    ///
    /// * If the ISM is already initialized.
    /// * If the length of the domains and modules do not match.
    #[storage(write, read)]
    fn initialize_with_domains(owner: Identity, mailbox: b256, domains: Vec<u32>, modules: Vec<b256>) {
        initialize_ownership(owner);
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

    /// Sets the ISM to be used for the specified origin domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The origin domain.
    /// * `module`: [b256] - The ISM to be used for the specified domain.
    ///
    /// ### Reverts
    ///
    /// * If the ISM is not initialized.
    /// * If the caller is not the owner.
    #[storage(write, read)]
    fn set(domain: u32, module: b256) {
        only_owner();
        _set(domain, module);
    }   

    /// Removes the specified origin domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The origin domain.
    ///
    /// ### Reverts
    ///
    /// * If the ISM is not initialized.
    /// * If the caller is not the owner.
    #[storage(write, read)]
    fn remove(domain: u32) {
        only_owner();
        let success = storage.domain_modules.remove(domain);
        if success {
            _remove_domain(domain);
        }
    }

    /// Returns the domains that have been set
    ///
    /// ### Returns
    ///
    /// * [Vec<u32>] - The list of origin domains.
    #[storage(read)]
    fn domains() -> Vec<u32> {
        storage.domains.load_vec()
    }

    /// Returns the ISM to be used for the specified origin domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The origin domain.
    ///
    /// ### Returns
    ///
    /// * [b256] - The ISM to be used for the specified domain.
    #[storage(read)]
    fn module(domain: u32) -> b256 {
        storage.domain_modules.get(domain).try_read().unwrap_or(b256::zero())
    }

    /// Returns the fallback mailbox for the ISM
    ///
    /// ### Returns
    ///
    /// * [b256] - The address of the mailbox.
    #[storage(read)]
    fn mailbox() -> b256 {
        storage.mailbox.read()
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
        _is_expected_owner(new_owner);
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

// Front-run guard
fn _is_expected_owner(owner: Identity) {
    let raw_owner: b256 = match owner {
        Identity::Address(address) => address.bits(),
        Identity::ContractId(contract_id) => contract_id.bits(),
    };
    require(raw_owner == EXPECTED_OWNER, OwnableError::UnexpectedOwner);
}
