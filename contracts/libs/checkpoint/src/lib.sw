library;

use std::bytes::Bytes;
use std_lib_extended::bytes::*;

/// Returns the digest validators are expected to sign when signing checkpoints
///
/// ### Arguments
///
/// * `origin`: [u32] - The origin domain of the checkpoint
/// * `origin_merkle_tree_hook`: [Bytes] - The address of the origin merkle tree hook as bytes with a length of 32
/// * `checkpoint_root`: [Bytes] - The root of the checkpoint
/// * `checkpoint_index`: [u32] - The index of the checkpoint
/// * `message_id`: [b256] - The message ID of the checkpoint
///
/// ### Returns
///
/// * [Bytes] - The digest of the checkpoint
pub fn digest(
    origin: u32,
    origin_merkle_tree_hook: Bytes,
    checkpoint_root: Bytes,
    checkpoint_index: u32,
    message_id: b256,
) -> Bytes {
    let domain_hash = domain_hash(origin, origin_merkle_tree_hook);

    let buffer = Buffer::new();
    let buffer = domain_hash.abi_encode(buffer);
    let mut domain_hash_bytes = Bytes::from(buffer.as_raw_slice());

    let buffer = Buffer::new();
    let buffer = checkpoint_root.abi_encode(buffer);
    let checkpoint_root_bytes = Bytes::from(buffer.as_raw_slice()).split_at(8).1;

    let buffer = Buffer::new();
    let buffer = checkpoint_index.abi_encode(buffer);
    let checkpoint_index_bytes = Bytes::from(buffer.as_raw_slice());

    let buffer = Buffer::new();
    let buffer = message_id.abi_encode(buffer);
    let message_id_bytes = Bytes::from(buffer.as_raw_slice());

    domain_hash_bytes.append(checkpoint_root_bytes);
    domain_hash_bytes.append(checkpoint_index_bytes);
    domain_hash_bytes.append(message_id_bytes);

    let hashed_bytes = domain_hash_bytes.keccak256();

    <Bytes as From<b256>>::from(Bytes::to_eth_signed_message_hash(hashed_bytes))
}

/// Returns the domain hash that validators are expected to use when signing checkpoints.
///
/// ### Arguments
///
/// * `origin`: [u32] - The origin domain of the checkpoint
/// * `origin_merkle_tree_hook`: [Bytes] - The address of the origin merkle tree hook as bytes with a length of 32
///
/// ### Returns
///
/// * [b256] - The domain hash
pub fn domain_hash(origin: u32, origin_merkle_tree_hook: Bytes) -> b256 {
    // Encode origin
    let buffer = Buffer::new();
    let buffer = origin.abi_encode(buffer);
    let mut origin_bytes = Bytes::from(buffer.as_raw_slice());

    // Encode origin_merkle_tree_hook
    let buffer = Buffer::new();
    let buffer = origin_merkle_tree_hook.abi_encode(buffer);
    let hook_bytes_trimmed = Bytes::from(buffer.as_raw_slice()).split_at(8).1;

    // Encode suffix
    let suffix = __to_str_array("HYPERLANE");
    let buffer = Buffer::new();
    let buffer = suffix.abi_encode(buffer);
    let suffix_bytes = Bytes::from(buffer.as_raw_slice());

    // Concatenate all
    origin_bytes.append(hook_bytes_trimmed);
    origin_bytes.append(suffix_bytes);

    // Hash bytes
    origin_bytes.keccak256()
}

// -------------------------
// ---- Sway Unit Tests ----
// -------------------------

struct TestDomainData {
    domain: u32,
    mailbox: b256,
    hash: b256,
}

// from monorepo/vectors/domainHash.json
const TEST_DOMAIN_DATA: [TestDomainData; 3] = [
    TestDomainData {
        domain: 1,
        mailbox: 0x0000000000000000000000002222222222222222222222222222222222222222,
        hash: 0xbbca56eb98960a4637eb40486d9a069550dd70d9c185ed138516e8e33cf3d7e7,
    },
    TestDomainData {
        domain: 2,
        mailbox: 0x0000000000000000000000002222222222222222222222222222222222222222,
        hash: 0xa6a93d86d397028e41995d521ccbc270e6db2a2fc530dcb7f0135254f30c8424,
    },
    TestDomainData {
        domain: 3,
        mailbox: 0x0000000000000000000000002222222222222222222222222222222222222222,
        hash: 0xffb4fbe5142f55e07b5d44b3c7f565c5ef4b016551cbd7c23a92c91621aca06f,
    },
];

#[test]
fn test_domain_hash() {
    let mut index = 0;
    while index < 3 {
        let test_data = TEST_DOMAIN_DATA[index];

        let computed_domain_hash = domain_hash(test_data.domain, Bytes::from(test_data.mailbox));
        assert_eq(computed_domain_hash, test_data.hash);

        index += 1;
    }
}

struct TestDigestData {
    domain: u32,
    index: u32,
    hook: b256,
    root: b256,
    message_id: b256,
    expected_hash: b256,
}

// The `expected_hash` is derived by running the test data through the same function in Solidity
// https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/8e942d3c6bcebcc6c16782f4d48153a1df06c353/solidity/contracts/libs/CheckpointLib.sol#L18
const TEST_DIGEST_DATA: [TestDigestData; 4] = [
    TestDigestData {
        domain: 1000,
        index: 1,
        hook: 0x0000000000000000000000002222222222222222222222222222222222222222,
        root: 0x0202020202020202020202020202020202020202020202020202020202020202,
        message_id: 0x4e3f92dc1bff4057a7c5e6b9f1f6c9c3a573432c2e09b68a9efb86d9904aa96f,
        expected_hash: 0x676170cf14cbe655abf440d6d9c0b846c585269941c3c6d7066cfb7018e6ccd9,
    },
    TestDigestData {
        domain: 1232,
        index: 2,
        hook: 0x0000000000000000000000002222222222222222222222222222222222222222,
        root: 0x0303030303030303030303030303030303030303030303030303030303030303,
        message_id: 0xfd087af1ca133839a8eb21ef8598c2aa006c119f631b21b601949f1a22978c86,
        expected_hash: 0x8ca1704b7319911cc5c5b8646098ae8be23b4f99ba8bd2ff0e2aa6ec612ee94c,
    },
    TestDigestData {
        domain: 567,
        index: 3,
        hook: 0x0000000000000000000000002222222222222222222222222222222222222222,
        root: 0x0404040404040404040404040404040404040404040404040404040404040404,
        message_id: 0x4e3167dc1bff4057a7c5e6b24ff6c9c3a57f712c2e09b68a9efb86af204aa5fa,
        expected_hash: 0x0283771fd0c98a35138244a70d8f663b55aceaaf7e095e9b503c0f7e0f5aca60,
    },
    TestDigestData {
        domain: 1000,
        index: 1,
        hook: 0x1111111111111111111111111111111111111111111111111111111111111111,
        root: 0x2222222222222222222222222222222222222222222222222222222222222222,
        message_id: 0x87aef1eedec41cf03ce02f27f11c802c5931c52c8bd58d2aa194d2183f7c0d55,
        expected_hash: 0x37971c00dbcc46e364e8e97886f48a110b2f3cacf02f24c7df4686395d8d2aa2,
    },
];

#[test]
fn test_digest() {
    let mut index = 0;
    while index < 4 {
        let test_data = TEST_DIGEST_DATA[index];

        let computed_digest = digest(
            test_data
                .domain,
            Bytes::from(test_data.hook),
            Bytes::from(test_data.root),
            test_data
                .index,
            test_data.message_id,
        );

        assert_eq(computed_digest, Bytes::from(test_data.expected_hash));

        index += 1;
    }
}
