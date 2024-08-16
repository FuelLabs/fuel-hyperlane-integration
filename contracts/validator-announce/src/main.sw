contract;

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
use std_lib_extended::bytes::*;
use interfaces::va::*;

enum ValidarorAnnounceError {
    ValidatorNotSigner: (),
    ReplayAnnouncement: (),
}

configurable {
    /// The local domain. Defaults to "fuel" in bytes.
    LOCAL_DOMAIN: u32 = 0x6675656cu32,
    MAILBOX_ID: ContractId = ContractId::from(ZERO_B256),
}

storage {
    /// Replay id -> whether it has been used.
    /// Used for ensuring a storage location for a validator cannot be announced more than once.
    replay_protection: StorageMap<b256, bool> = StorageMap {},
    announced_storage_locations: StorageMap<b256, StorageVec<StorageString>> = StorageMap {},
    /// Unique validator list
    validators: StorageVec<b256> = StorageVec {},
}

impl ValidatorAnnounce for Contract {
    #[storage(read)]
    fn get_announced_validators() -> Vec<b256> {
        _get_announced_validators()
    }

    // Returns all announced storage locations for each of the validators.
    // Only intended for off-chain view calls due to potentially high gas costs.
    #[storage(read)]
    fn get_announced_storage_locations(validators: Vec<b256>) -> Vec<Vec<String>> {
        let mut all_storage_locations: Vec<Vec<String>> = Vec::new();
        let validators_len = validators.len();
        let mut i = 0;

        while i < validators_len {
            let mut validator_storage_locations: Vec<String> = Vec::new();
            let validator = validators.get(i).unwrap();
            let storage_locations = storage.announced_storage_locations.get(validator);
            let storage_locations_len = storage_locations.len();
            let mut j = 0;

            while j < storage_locations_len {
                let storage_location = storage_locations.get(j).unwrap();
                validator_storage_locations.push(storage_location.read_slice().unwrap());
                j += 1;
            }

            all_storage_locations.push(validator_storage_locations);
            i += 1;
        }

        all_storage_locations
    }

    #[storage(read, write)]
    fn announce(
        validator: EvmAddress,
        storage_location: String,
        signature: Bytes,
    ) -> bool {
        let replay_id = _replay_id(validator, storage_location);
        let replayed = storage.replay_protection.get(replay_id).try_read().unwrap_or(false);
        require(!replayed, ValidarorAnnounceError::ReplayAnnouncement);
        storage.replay_protection.insert(replay_id, true);

        let announcement_digest = _get_announcement_digest(storage_location);
        let compact_signature = signature.to_compact_signature().unwrap();
        let signer = ec_recover_evm_address(compact_signature, announcement_digest).unwrap();
        require(
            validator
                .bits() == signer
                .bits(),
            ValidarorAnnounceError::ValidatorNotSigner,
        );

        if !_is_validator_stored(validator) {
          storage.validators.push(validator.bits());
        }
        _insert_announced_storage_location(validator.bits(), storage_location);
        log(ValidatorAnnouncementEvent{
            validator: validator,
            storage_location: storage_location,
        });

        true
    }
}

// ----------------------------------------------------------------
// ---------------------- INTERNAL FUNCTIONS ----------------------
// ----------------------------------------------------------------

fn _replay_id(validator: EvmAddress, storage_location: String) -> b256 {
    let buffer = Buffer::new();
    let buffer = validator.bits().abi_encode(buffer);
    // We don't need to cut out the string length, because the
    // same string will always result in the same hash.
    let buffer = storage_location.abi_encode(buffer);
    Bytes::from(buffer.as_raw_slice()).keccak256()
}

fn _get_announcement_digest(storage_location: String) -> b256 {
    let buffer = Buffer::new();
    let buffer = _domain_hash().abi_encode(buffer);
    let mut encoded_domain_hash = Bytes::from(buffer.as_raw_slice());

    let buffer = Buffer::new();
    let buffer = storage_location.abi_encode(buffer);
    let encoded_storage_location = Bytes::from(buffer.as_raw_slice()).split_at(8).1;

    encoded_domain_hash.append(encoded_storage_location);

    Bytes::to_eth_signed_message_hash(encoded_domain_hash.keccak256())
}

fn _domain_hash() -> b256 {
    let domain = LOCAL_DOMAIN;
    let mailbox_id = MAILBOX_ID.bits();
    let postfix = __to_str_array("HYPERLANE_ANNOUNCEMENT");

    let buffer = Buffer::new();
    let buffer = domain.abi_encode(buffer);
    let buffer = mailbox_id.abi_encode(buffer);
    let buffer = postfix.abi_encode(buffer);
    let bytes = Bytes::from(buffer.as_raw_slice());
    bytes.keccak256()
}

#[storage(read, write)]
fn _insert_announced_storage_location(validator: b256, storage_location: String) {
    let _ = storage.announced_storage_locations.try_insert(validator, StorageVec {});

    storage
        .announced_storage_locations
        .get(validator)
        .push(StorageString {});
    let index = storage.announced_storage_locations.get(validator).len() - 1;

    storage
        .announced_storage_locations
        .get(validator)
        .get(index)
        .unwrap()
        .write_slice(storage_location);
}

#[storage(read)]
fn _get_announced_validators() -> Vec<b256> {
    storage.validators.load_vec()
}

#[storage(read)]
fn _is_validator_stored(validator: EvmAddress) -> bool {
    let validators = _get_announced_validators();
    for stored_validator in validators.iter() {
        if stored_validator == validator.bits() {
            return true;
        }
    }
    false
}

// ----------------------------------------------------------------
// ---------------------- TESTS -----------------------------------
// ----------------------------------------------------------------

struct TestDomainHashData {
    mailbox_id: b256,
    expected: b256,
}

// The `expected` hash is derived by running the test data through the same function in Solidity
// https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/279516f28083863ff48047346aa19317fd23f504/solidity/contracts/isms/multisig/ValidatorAnnounce.sol#L123
const TEST_DOMAIN_DATA: [TestDomainHashData; 4] = [
    TestDomainHashData {
        mailbox_id: 0x676170cf14cbe655abf440d6d9c0b846c585269941c3c6d7066cfb7018e6ccd9,
        expected: 0xea0de3c5380866991ae35cf3bdead2335aa01384553533f50535306fc71f2e8b,
    },
    TestDomainHashData {
        mailbox_id: 0x8ca1704b7319911cc5c5b8646098ae8be23b4f99ba8bd2ff0e2aa6ec612ee94c,
        expected: 0xa7b8f97f47df0289638ae37f70a1915d816046968eb86ee4e5bfcccc67808aef,
    },
    TestDomainHashData {
        mailbox_id: 0x0283771fd0c98a35138244a70d8f663b55aceaaf7e095e9b503c0f7e0f5aca60,
        expected: 0xe362658ffe1bb3a8218217f48a9e0d1f213b6624d9f0b48dcbe789b322263f7c,
    },
    TestDomainHashData {
        mailbox_id: 0x37971c00dbcc46e364e8e97886f48a110b2f3cacf02f24c7df4686395d8d2aa2,
        expected: 0x4ee2b8cac076a2f6eb3a65e8e7434d393f08c2a81353df02bdb1be252b25dc26,
    },
];

struct TestAnnouncementDigestData {
    mailbox_id: b256,
    expected: b256,
}

// The `expected` hash is derived by running the test data through the same function in Solidity
// https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/279516f28083863ff48047346aa19317fd23f504/solidity/contracts/isms/multisig/ValidatorAnnounce.sol#L111
const TEST_ANNOUNCEMENT_DIGEST_DATA: [TestAnnouncementDigestData; 4] = [
    TestAnnouncementDigestData {
        mailbox_id: 0x676170cf14cbe655abf440d6d9c0b846c585269941c3c6d7066cfb7018e6ccd9,
        expected: 0x0733ba7dec612f80f4f0694f18605356ed5b81a55e264fed18f1454ed93150af,
    },
    TestAnnouncementDigestData {
        mailbox_id: 0x8ca1704b7319911cc5c5b8646098ae8be23b4f99ba8bd2ff0e2aa6ec612ee94c,
        expected: 0xa1eed844bcd579ddf9413a2259d2128f89851e3bbaaca47f44a1fbcfa3797897,
    },
    TestAnnouncementDigestData {
        mailbox_id: 0x0283771fd0c98a35138244a70d8f663b55aceaaf7e095e9b503c0f7e0f5aca60,
        expected: 0x5e10170422e19738bce465aeeb4abebd1bbfef5905b9aaf80ca75978b025c36d,
    },
    TestAnnouncementDigestData {
        mailbox_id: 0x37971c00dbcc46e364e8e97886f48a110b2f3cacf02f24c7df4686395d8d2aa2,
        expected: 0xff97e8eec083d6a00aefdbdfc5e43c8c6a169219505435e6a8f4a18dbe675b68,
    },
];

#[test]
fn domain_hash() {
    let mut index = 0;
    while index < 4 {
        let domain = 0x6675656cu32;
        let test_data = TEST_DOMAIN_DATA[index];
        let mailbox_id = test_data.mailbox_id;
        let postfix = __to_str_array("HYPERLANE_ANNOUNCEMENT");

        let buffer = Buffer::new();
        let buffer = domain.abi_encode(buffer);
        let buffer = mailbox_id.abi_encode(buffer);
        let buffer = postfix.abi_encode(buffer);
        let bytes = Bytes::from(buffer.as_raw_slice());

        assert_eq(bytes.keccak256(), test_data.expected);

        index += 1;
    }
}

#[test]
fn announcement_digest() {
    // Cannot add storage location str to the struct and initialize as const
    let storage_locations = [
        String::from_ascii_str("s3@test-location-123"),
        String::from_ascii_str("s3@test-location-456"),
        String::from_ascii_str("s3@test-location-789"),
        String::from_ascii_str("s3@test-location-420"),
    ];

    let mut index = 0;
    while index < 4 {
        let ann_test_data = TEST_ANNOUNCEMENT_DIGEST_DATA[index];

        // ⬇️ Domain hash logic ⬇️
        let domain = 0x6675656cu32;
        let domain_test_data = TEST_DOMAIN_DATA[index];
        let mailbox_id = domain_test_data.mailbox_id;
        let postfix = __to_str_array("HYPERLANE_ANNOUNCEMENT");

        let buffer = Buffer::new();
        let buffer = domain.abi_encode(buffer);
        let buffer = mailbox_id.abi_encode(buffer);
        let buffer = postfix.abi_encode(buffer);
        let bytes = Bytes::from(buffer.as_raw_slice());

        let domain_hash = bytes.keccak256();
        assert_eq(domain_hash, domain_test_data.expected); 
        // ⬆️ Domain hash logic ⬆️
        // ⬇️ Announcement digest logic ⬇️
        let storage_location = storage_locations[index];

        let buffer = Buffer::new();
        let buffer = domain_hash.abi_encode(buffer);
        let mut encoded_domain_hash = Bytes::from(buffer.as_raw_slice());

        let buffer = Buffer::new();
        let buffer = storage_location.abi_encode(buffer);
        let encoded_storage_location = Bytes::from(buffer.as_raw_slice()).split_at(8).1;

        encoded_domain_hash.append(encoded_storage_location);

        log(encoded_domain_hash.keccak256());

        assert_eq(
            Bytes::to_eth_signed_message_hash(encoded_domain_hash.keccak256()),
            ann_test_data
                .expected,
        ); 
        // ⬆️ Announcement digest logic ⬆️
        index += 1;
    }
}