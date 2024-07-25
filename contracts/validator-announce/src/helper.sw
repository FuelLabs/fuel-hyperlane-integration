library;

use std::string::String;
use std::{
    b512::B512,
    bytes::Bytes,
    constants::ZERO_B256,
    contract_id::ContractId,
    hash::{
        Hash,
        Hasher,
        keccak256,
    },
    storage::storage_map::*,
    storage::storage_vec::*,
    vm::evm::{
        evm_address::EvmAddress,
    },
};

use std_lib_extended::bytes::*;

//const REPLAY_ID_VALIDATOR_OFFSET: u64 = 0;
const REPLAY_ID_STORAGE_LOCATION_OFFSET: u64 = 20;
//const DOMAIN_HASH_LOCAL_DOMAIN_OFFSET: u64 = 0;
const DOMAIN_HASH_MAILBOX_ID_OFFSET: u64 = 4;
// // The suffix is "HYPERLANE_ANNOUNCEMENT"
const DOMAIN_HASH_SUFFIX_OFFSET: u64 = 36;
const DOMAIN_HASH_SUFFIX_LEN: u64 = 22;
// // The length is DOMAIN_HASH_SUFFIX_OFFSET + DOMAIN_HASH_SUFFIX_LEN
const DOMAIN_HASH_LEN: u64 = 58;

pub fn get_replay_id(validator: EvmAddress, storage_location: Bytes) -> b256 {
    let mut bytes = Bytes::with_capacity(REPLAY_ID_STORAGE_LOCATION_OFFSET + storage_location.len());
    bytes.append(Bytes::from(validator.bits()));
    bytes.append(storage_location);
    keccak256(bytes)
}

pub fn announcement_hash(domain_hash: b256, storage_location: Bytes) -> b256 {
    let mut buffer = Buffer::new();
    buffer = domain_hash.abi_encode(buffer);
    buffer = storage_location.abi_encode(buffer);
    let bytes = Bytes::from(buffer.as_raw_slice());
    keccak256(bytes)
}

pub fn domain_hash(mailbox_id: b256, local_domain: u32) -> b256 {
    let mut buffer = Buffer::new();
    buffer = local_domain.abi_encode(buffer);
    buffer = mailbox_id.abi_encode(buffer);
    buffer = "HYPERLANE_ANNOUNCEMENT".abi_encode(buffer);
    let bytes = Bytes::from(buffer.as_raw_slice());

    let mut hasher = Hasher::new();
    hasher.write(bytes);
    hasher.keccak256()
}

const DIGEST_DOMAIN_HASH_OFFSET: u64 = 0;
const DIGEST_STORAGE_LOCATION_OFFSET: u64 = 32;
pub fn get_announcement_digest(
    mailbox_id: b256,
    local_domain: u32,
    storage_location: Bytes,
) -> b256 {
    let domain_hash_value = domain_hash(mailbox_id, local_domain);

    let len = DIGEST_STORAGE_LOCATION_OFFSET + storage_location.len();
    let mut signed_message_payload = Bytes::with_length(len);
    let _ = signed_message_payload.write_b256(DIGEST_DOMAIN_HASH_OFFSET, domain_hash_value);
    let _ = signed_message_payload.write_bytes(DIGEST_STORAGE_LOCATION_OFFSET, storage_location); // Ensure offset is used
    let signed_message_hash = signed_message_payload.keccak256();

    let ethereum_signed_message_bytes = Bytes::with_ethereum_prefix(signed_message_hash);

    let final_digest = ethereum_signed_message_bytes.keccak256();
    final_digest
}
