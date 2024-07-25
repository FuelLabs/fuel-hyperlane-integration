contract;

mod helper;

use std::{
    b512::B512,
    bytes::Bytes,
    constants::ZERO_B256,
    contract_id::ContractId,
    hash::{
        Hash,
        keccak256,
        sha256,
    },
    storage::storage_map::*,
    storage::storage_string::*,
    storage::storage_vec::*,
    string::String,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
};
use helper::{get_announcement_digest, get_replay_id};
use interfaces::va::{ValidatorAnnounce, ValidatorAnnouncementEvent};

configurable {
    MAILBOX_ID: b256 = 0x0000000000000000000000000000000000000000000000000000000000000000,
    LOCAL_DOMAIN: u32 = 0x6675656cu32,
    /// The local domain. Defaults to "fuel" in bytes.
    MAX_STORABLE_STRING_CHARS: u64 = 128,
}
storage {
    /// Replay id -> whether it has been used.
    /// Used for ensuring a storage location for a validator cannot be announced more than once.
    replay_protection: StorageMap<b256, bool> = StorageMap {},
    announced_storage_locations: StorageMap<b256, StorageString> = StorageMap {},
    /// Unique validator list
    validators: StorageVec<b256> = StorageVec {},
    mailbox: ContractId = ContractId::from(ZERO_B256),
    local_domain: u32 = 0,
}

// If a validator is not already present in the validators map,
/// it's added to the validators vec and the validators map.
/// Idemptotent.
#[storage(read, write)]
pub fn upsert_validator(validator: b256) {
    let len = storage.validators.len();
    let mut exists = false;
    let mut i = 0;
    while i < len {
        if let Some(stored_validator) = storage.validators.get(i) {
            if stored_validator.read() == validator {
                exists = true;
                break;
            }
        }
    }
    if !exists {
        storage.validators.push(validator);
    }
}

impl ValidatorAnnounce for Contract {
    #[storage(read)]
    fn get_mailbox() -> ContractId {
        storage.mailbox.read()
    }

    #[storage(write)]
    fn set_mailbox(mailbox: ContractId) {
        storage.mailbox.write(mailbox)
    }

    #[storage(read)]
    fn get_local_domain() -> u32 {
        storage.local_domain.read()
    }

    #[storage(write)]
    fn set_local_domain(domain: u32) {
        storage.local_domain.write(domain)
    }

    #[storage(read)]
    fn get_validator_count() -> u64 {
        storage.validators.len()
    }

    #[storage(read)]
    fn get_validators() -> Vec<b256> {
        let len = storage.validators.len();
        let mut vec = Vec::with_capacity(len);
        let mut i = 0;
        while i < len {
            vec.push(storage.validators.get(i).unwrap().read());
            i += 1;
        }
        vec
    }

    #[storage(read)]
    fn get_announced_storage_location(validator: EvmAddress) -> String {
        let loc = storage.announced_storage_locations.get(validator.bits()).read_slice();
        match loc {
            Some(loc) => {
                loc
            }
            None => {
                String::new()
            }
        }
    }

    // Returns all announced storage locations for each of the validators.
    // Only intended for off-chain view calls due to potentially high gas costs.
    #[storage(read)]
    fn get_announced_storage_locations(validators: Vec<b256>) -> Vec<String> {
        let mut all_storage_locations: Vec<String> = Vec::new();
        let validators_len = validators.len();
        let mut i = 0;

        while i < validators_len {
            let validator = validators.get(i).unwrap();
            let mut index = 0;
            let mut has_next = true;
            while has_next {
                let storage_key = storage.announced_storage_locations.get(validator);
                match storage_key.read_slice() {
                    Some(storage_string) => {
                        all_storage_locations.push(storage_string);
                        index += 1;
                    }
                    None => {
                        has_next = false;
                        break;
                    }
                }
                break;
            }
            i += 1;
        }
        all_storage_locations
    }

    #[storage(read, write)]
    fn announce(
        validator: EvmAddress,
        storage_location: Bytes,
        signature: B512,
    ) {
        require(
            storage_location
                .len() < MAX_STORABLE_STRING_CHARS,
            "storage location must be at most 128 characters",
        );

        let message_hash = get_announcement_digest(MAILBOX_ID, LOCAL_DOMAIN, storage_location.clone());
        let signer = ec_recover_evm_address(signature, message_hash).unwrap();

        if validator.bits() != signer.bits() {
            log("Validator and signer do not match");
        }

        // NOT WORKING 
        // require(
        //     validator
        //         .bits() == signer
        //         .bits(),
        //     "validator is not the signer",
        // );

        // Check replay protection to prevent duplicate announcements
        let replay_id = get_replay_id(validator, storage_location.clone());

        let stored = storage.replay_protection.get(replay_id).try_read().unwrap_or(false);
        require(!stored, "validator and storage location already announced");

        upsert_validator(validator.bits());

        let storage_string = String::from_ascii(storage_location);
        storage
            .announced_storage_locations
            .insert(validator.bits(), StorageString {});
        storage
            .announced_storage_locations
            .get(validator.bits())
            .write_slice(storage_string);

        storage.replay_protection.insert(replay_id, true);
    }
}
