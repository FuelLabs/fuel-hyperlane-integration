library;

use std::{
    b512::B512,
    bytes::Bytes,
    bytes_conversions::{
        b256::*,
        u32::*,
    },
    constants::ZERO_B256,
    hash::keccak256,
    vm::evm::evm_address::EvmAddress,
};

use std_lib_extended::bytes::*;

/// See https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/solidity/contracts/libs/isms/MultisigIsmMetadata.sol
/// for the reference implementation.
pub struct MultisigMetadata {
    root: b256,
    index: u32,
    mailbox: b256,
    proof: [b256; 32],
    pub signatures: Vec<B512>,
}

pub fn domain_hash(origin: u32, mailbox: b256) -> b256 {
    let suffix = "SOMETHING";
    let suffix_len = 9;

    // 111111111
    // 111111111

    // let bytes = bytes.split_at(4u64).1;
    // log(bytes);
    const B256_BYTE_COUNT: u64 = 32u64;
    const U32_BYTE_COUNT: u64 = 4u64;
    const LEN_ENCODING: u64 = 8u64;

    // XXX should work
    let buffer = Buffer::new(); // 000000000
    let buffer = origin.abi_encode(buffer); // 000000000000000400000001
    let bytes = Bytes::from(buffer.as_raw_slice());
    log(bytes);
    // log(Bytes::from(buffer.as_raw_wslice()));
    let buffer = mailbox.abi_encode(buffer); // 0000000000000024000000010000000000000000000000002222222222222222222222222222222222222222
    let bytes = Bytes::from(buffer.as_raw_slice());

    log(bytes);

    let buffer = suffix.abi_encode(buffer); //0000000000000035000000010000000000000000000000002222222222222222222222222222222222222222000000000000000948595045524c414e45
    let mut bytes = Bytes::from(buffer.as_raw_slice());
    bytes = bytes.split_at(8).1; // XXX Should cut off the start 
    // let (mut start, mut end_with_len) = bytes.split_at(LEN_ENCODING + U32_BYTE_COUNT + B256_BYTE_COUNT);
    // end_with_len = end_with_len.split_at(LEN_ENCODING).1;
    // start.append(end_with_len);
    // log(start);
    log(bytes);

    // let bytes = bytes.split_at(8).1;
    // log(bytes);
    // bytes.keccak256()
    Bytes::new().keccak256()
    // XXX OLd implementation
    // let mut bytes = Bytes::with_length(U32_BYTE_COUNT + B256_BYTE_COUNT + suffix_len);
    // let mut offset = 0;
    // offset = bytes.write_u32(offset, origin);
    // offset = bytes.write_b256(offset, mailbox);
    // offset = bytes.write_packed_bytes(offset, __addr_of(suffix), suffix_len);

    // bytes.keccak256()

    // XXX encode at once
    // let buffer = Buffer::new();
    // let buffer = (origin, mailbox, suffix).abi_encode(buffer);
}

pub fn checkpoint_hash(origin: u32, mailbox: b256, root: b256, index: u32) -> b256 {
    let domain_hash = domain_hash(origin, mailbox);

    let mut bytes = Bytes::with_length(B256_BYTE_COUNT + B256_BYTE_COUNT + U32_BYTE_COUNT);

    let mut offset = 0;
    offset = bytes.write_b256(offset, domain_hash);
    offset = bytes.write_b256(offset, root);
    offset = bytes.write_u32(offset, index);

    bytes.keccak256()
}

impl MultisigMetadata {
    /// Constructs a new MultisigMetadata instance from packed bytes and a threshold.
    /// Format (bytes):
    /// - root: [0:32] (32 bytes)
    /// - index: [32:36] (4 bytes)
    /// - mailbox: [36:68] (32 bytes)
    /// - proof: [68:1092] (1024 bytes)
    /// - signatures: [1092:...] (64 * threshold bytes)
    ///
    /// The number of signatures is expected to equal the threshold.
    /// Note that signatures are provided as their EIP-2098 64-byte compact
    /// representation.
    pub fn from_bytes(bytes: Bytes, threshold: u64) -> MultisigMetadata {
        let mut offset = 0;

        let root = bytes.read_b256(offset);
        offset += B256_BYTE_COUNT;

        let index = bytes.read_u32(offset);
        offset += U32_BYTE_COUNT;

        let mailbox = bytes.read_b256(offset);
        offset += B256_BYTE_COUNT;

        let mut proof: [b256; 32] = [ZERO_B256; 32];
        let mut proof_index = 0;
        while proof_index < 32 {
            proof[proof_index] = bytes.read_b256(offset);
            offset += B256_BYTE_COUNT;
            proof_index += 1;
        }

        let mut signatures = Vec::with_capacity(threshold);
        let mut signature_index = 0;
        while signature_index < threshold {
            let signature = bytes.read_b512(offset);
            offset += B512_BYTE_COUNT;
            signatures.push(signature);
            signature_index += 1;
        }

        MultisigMetadata {
            root,
            index,
            mailbox,
            proof,
            signatures,
        }
    }

    pub fn checkpoint_digest(self, origin: u32) -> b256 {
        let _checkpoint_hash = checkpoint_hash(origin, self.mailbox, self.root, self.index);
        Bytes::with_ethereum_prefix(_checkpoint_hash).keccak256()
    }
}

// ==================================================
// =====                                        =====
// =====                  Tests                 =====
// =====                                        =====
// ==================================================

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

        let computed_domain_hash = domain_hash(test_data.domain, test_data.mailbox);
        // log(computed_domain_hash);
        // log(test_data.hash);
        assert(computed_domain_hash == test_data.hash);

        index += 1;
    }
}

struct TestCheckpointData {
    domain: u32,
    index: u32,
    mailbox: b256,
    root: b256,
    hash: b256,
}

// from monorepo/vectors/signedCheckpoint.json
const TEST_CHECKPOINT_DATA: [TestCheckpointData; 3] = [
    TestCheckpointData {
        domain: 1000,
        index: 1,
        mailbox: 0x0000000000000000000000002222222222222222222222222222222222222222,
        root: 0x0202020202020202020202020202020202020202020202020202020202020202,
        hash: 0xf5c90415788653e2c8ee94c8f10f7301f52025efb7cac767ce649132ff1384dd,
    },
    TestCheckpointData {
        domain: 1000,
        index: 2,
        mailbox: 0x0000000000000000000000002222222222222222222222222222222222222222,
        root: 0x0303030303030303030303030303030303030303030303030303030303030303,
        hash: 0x0f01ac543ee309d1e511ad7fbaace1ec83f264b8481724b94024f587ac3c2c4e,
    },
    TestCheckpointData {
        domain: 1000,
        index: 3,
        mailbox: 0x0000000000000000000000002222222222222222222222222222222222222222,
        root: 0x0404040404040404040404040404040404040404040404040404040404040404,
        hash: 0x134d65c32fac6ddf3fb9ac312552312d303b24b7b3614a9496f4de33bf412055,
    },
];

// #[test]
// fn test_checkpoint_hash() {
//     let mut index = 0;
//     while index < 3 {
//         let test_data = TEST_CHECKPOINT_DATA[index];

//         let computed_checkpoint_hash = checkpoint_hash(
//             test_data
//                 .domain,
//             test_data
//                 .mailbox,
//             test_data
//                 .root,
//             test_data
//                 .index,
//         );

//         assert(computed_checkpoint_hash == test_data.hash);

//         index += 1;
//     }
// }
