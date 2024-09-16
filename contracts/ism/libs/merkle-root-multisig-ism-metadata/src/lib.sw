library;

use std::bytes::Bytes;
use std_lib_extended::bytes::*;

/// Format of metadata:
/// [   0:  32] Origin merkle tree address
/// [  32:  36] Index of message ID in merkle tree
/// [  36:  68] Signed checkpoint message ID
/// [  68:1092] Merkle proof
/// [1092:1096] Signed checkpoint index (computed from proof and index)
/// [1096:????] Validator signatures (length := threshold * 65)
///
const ORIGIN_MERKLE_TREE_OFFSET = 0;
const MESSAGE_INDEX_OFFSET = 32;
const MESSAGE_ID_OFFSET = 36;
const MERKLE_PROOF_OFFSET = 68;
const MERKLE_PROOF_LENGTH = 32 * 32;
const SIGNED_INDEX_OFFSET = 1092;
const SIGNATURES_OFFSET: u32 = 1096;
const SIGNATURE_LENGTH: u32 = 65;

pub struct MerkleRootMultisigIsmMetadata {
    bytes: Bytes,
}

impl MerkleRootMultisigIsmMetadata {
    /// Creates a new instance of MerkleRootMultisigIsmMetadata.
    ///
    /// ### Arguments
    ///
    /// * `bytes`: [Bytes] - The encoded metadata.
    ///
    /// ### Returns
    ///
    /// * [MerkleRootMultisigIsmMetadata] - The new instance.
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

    /// Returns the index of the message being proven.
    ///
    /// ### Returns
    ///
    /// * [u32] - Index of the target message in the merkle tree.
    pub fn message_index(self) -> u32 {
        let bytes = self.bytes.clone();
        bytes.read_u32(MESSAGE_INDEX_OFFSET)
    }

    /// Returns the index of the signed checkpoint
    ///
    /// ### Returns
    ///
    /// * [u32] - Index of the signed checkpoint.
    pub fn signed_index(self) -> u32 {
        let bytes = self.bytes.clone();
        bytes.read_u32(SIGNED_INDEX_OFFSET)
    }

    /// Returns the message ID of the signed checkpoint.
    ///
    /// ### Returns
    ///
    /// * [b256] - Message ID of the signed checkpoint.
    pub fn signed_message_id(self) -> b256 {
        let bytes = self.bytes.clone();
        b256::from(bytes.split_at(MESSAGE_ID_OFFSET).1.split_at(32).0)
    }

    /// Returns the merkle proof branch of the message
    ///
    /// ### Returns
    ///
    /// * [b256; 32] - Merkle proof branch of the message.
    pub fn proof(self) -> [b256; 32] {
        let bytes = self.bytes.clone();
        let bytes = bytes.split_at(MERKLE_PROOF_OFFSET).1.split_at(MERKLE_PROOF_LENGTH).0;
        BufferReader::from_parts(bytes.ptr(), bytes.len()).decode()
    }

    /// Returns the validator ECDSA signature at the given index.
    ///
    /// ### Arguments
    ///
    /// * `index`: [u32] - The index of the signature to return.
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

// ------------------------------
// ------ Sway Unit tests -------
// ------------------------------

#[test]
fn merkle_root_multisig_metadata() {
    let hook = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    let message_index: u32 = 2;
    let signed_message_id = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd;

    // Merkle proof
    let mut proof: [b256; 32] = [b256::zero(); 32];
    let mut index = 0;
    while index < 32 {
        proof[index] = b256::generate(index);
        index += 1;
    }
    let signed_index: u32 = 3;

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
    let buffer = message_index.abi_encode(buffer);
    let buffer = signed_message_id.abi_encode(buffer);
    let buffer = encode_proof(buffer, proof);
    let buffer = signed_index.abi_encode(buffer);
    let buffer = r.abi_encode(buffer);
    let buffer = s.abi_encode(buffer);
    let buffer = v.abi_encode(buffer);
    let buffer = r_2.abi_encode(buffer);
    let buffer = s_2.abi_encode(buffer);
    let buffer = v_2.abi_encode(buffer);
    let bytes = Bytes::from(buffer.as_raw_slice());

    let metadata = MerkleRootMultisigIsmMetadata::new(bytes.clone());

    assert_eq(bytes, metadata.bytes);
    assert_eq(hook, b256::from(metadata.origin_merkle_tree_hook()));
    assert_eq(message_index, metadata.message_index());
    assert_eq(signed_index, metadata.signed_index());
    assert_eq(signed_message_id, metadata.signed_message_id());
    assert_eq(sig_1, metadata.signature_at(0));
    assert_eq(sig_2, metadata.signature_at(1));
    let mut index = 0;
    while index < 32 {
        assert_eq(proof[index], metadata.proof()[index]);
        index += 1;
    }
}

fn encode_proof(buffer: Buffer, proof: [b256; 32]) -> Buffer {
    let mut buffer = buffer;
    let mut index = 0;
    while index < 32 {
        buffer = proof[index].abi_encode(buffer);
        index += 1;
    }
    buffer
}