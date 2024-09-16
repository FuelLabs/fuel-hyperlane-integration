library;

use std::bytes::Bytes;
use std_lib_extended::bytes::*;

/// Format of metadata:
/// [   0:  32] Origin merkle tree address
/// [  32:  64] Signed checkpoint root
/// [  64:  68] Signed checkpoint index
/// [  68:????] Validator signatures (length := threshold * 65)
///
const ORIGIN_MERKLE_TREE_OFFSET = 0;
const MERKLE_ROOT_OFFSET = 32;
const MERKLE_INDEX_OFFSET = 64;
const SIGNATURES_OFFSET: u32 = 68;
const SIGNATURE_LENGTH: u32 = 65;

pub struct MessageIdMultisigIsmMetadata {
    bytes: Bytes,
}

impl MessageIdMultisigIsmMetadata {
    /// Creates a new instance of MessageIdMultisigIsmMetadata.
    ///
    /// ### Arguments
    ///
    /// * `bytes`: [Bytes] - The encoded metadata.
    ///
    /// ### Returns
    ///
    /// * [MessageIdMultisigIsmMetadata] - The new instance.
    pub fn new(bytes: Bytes) -> Self {
        Self { bytes }
    }

    /// Returns the origin merkle tree hook of the signed checkpoint as bytes with a length of 32.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - Origin merkle tree hook of the signed checkpoint.
    pub fn origin_merkle_tree_hook(self) -> Bytes {
        let bytes = self.bytes.clone();
        bytes.split_at(ORIGIN_MERKLE_TREE_OFFSET + 32).0
    }

    /// Returns the merkle root of the signed checkpoint.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - Merkle root of the signed checkpoint.
    pub fn root(self) -> Bytes {
        let bytes = self.bytes.clone();
        bytes.split_at(MERKLE_ROOT_OFFSET).1.split_at(32).0
    }

    /// Returns the merkle index of the signed checkpoint
    ///
    /// ### Returns
    ///
    /// * [u32] - Merkle index of the signed checkpoint.
    pub fn index(self) -> u32 {
        let bytes = self.bytes.clone();
        bytes.read_u32(MERKLE_INDEX_OFFSET)
    }

    /// Returns the validator ECDSA signature at the given index.
    ///
    /// ### Arguments
    ///
    /// * `index`: [u32] - The index of the signature.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - The validator ECDSA signature at the given index.
    pub fn signature_at(self, index: u32) -> Bytes {
        let bytes = self.bytes.clone();
        let start = u64::from(SIGNATURES_OFFSET + (index * SIGNATURE_LENGTH));
        bytes.split_at(start).1.split_at(u64::from(SIGNATURE_LENGTH)).0
    }
}

// -------------------------
// ---- Sway Unit Tests ----
// -------------------------

#[test]
fn message_id_multisig_metadata() {
    let hook = 0x1111111111111111111111111111111111111111111111111111111111111111;
    let root = 0x2222222222222222222222222222222222222222222222222222222222222222;
    let index: u32 = 1;

    // Signatures
    let r = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd;
    let s = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd;
    let v: u8 = 1;

    let r_2 = 0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b;
    let s_2 = 0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b;
    let v_2: u8 = 2;

    let buffer = Buffer::new();
    let buffer = r.abi_encode(buffer);
    let buffer = s.abi_encode(buffer);
    let buffer = v.abi_encode(buffer);
    let buffer = r_2.abi_encode(buffer);
    let buffer = s_2.abi_encode(buffer);
    let buffer = v_2.abi_encode(buffer);
    let (sig_1, sig_2) = Bytes::from(buffer.as_raw_slice()).split_at(65);

    let buffer = Buffer::new();
    let buffer = hook.abi_encode(buffer);
    let buffer = root.abi_encode(buffer);
    let buffer = index.abi_encode(buffer);
    let buffer = r.abi_encode(buffer);
    let buffer = s.abi_encode(buffer);
    let buffer = v.abi_encode(buffer);
    let buffer = r_2.abi_encode(buffer);
    let buffer = s_2.abi_encode(buffer);
    let buffer = v_2.abi_encode(buffer);
    let bytes = Bytes::from(buffer.as_raw_slice());

    let metadata = MessageIdMultisigIsmMetadata::new(bytes.clone());

    assert_eq(bytes, metadata.bytes);
    assert_eq(hook, b256::from(metadata.origin_merkle_tree_hook()));
    assert_eq(root, b256::from(metadata.root()));
    assert_eq(index, metadata.index());
    assert_eq(sig_1, metadata.signature_at(0));
    assert_eq(sig_2, metadata.signature_at(1));
}
