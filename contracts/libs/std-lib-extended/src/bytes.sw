library;

use std::{
    array_conversions::b256::*,
    b512::B512,
    bytes::Bytes,
    constants::ZERO_B256,
    hash::{
        Hash,
        keccak256,
    },
    vm::evm::evm_address::EvmAddress,
};

/// The number of bytes in a b256.
pub const B256_BYTE_COUNT: u64 = 32u64;

impl b256 {
    /// Returns a pointer to the b256's packed bytes.
    fn packed_bytes(self) -> raw_ptr {
        __addr_of(self)
    }

    /// Gets a b256 from a pointer to packed bytes.
    fn from_packed_bytes(ptr: raw_ptr) -> Self {
        // Return ptr as a b256.
        asm(ptr: ptr) {
            ptr: b256
        }
    }

    pub fn generate(seed: u64) -> Self {
        keccak256(seed)
    }
}

/// The number of bytes in a u32.
pub const U32_BYTE_COUNT: u64 = 4u64;

impl Bytes {
    // ===== b256 ====

    /// Reads a b256 at the specified offset.
    /// Reverts if it violates the bounds of self.
    pub fn read_b256(self, offset: u64) -> b256 {
        let data = self.split_at(offset).1.split_at(B256_BYTE_COUNT).0;
        BufferReader::from_parts(data.ptr(), data.len()).decode()
    }

    // ===== u32 ====

    /// Reads a u32 at the specified offset.
    /// Reverts if it violates the bounds of self.
    pub fn read_u32(self, offset: u64) -> u32 {
        let data = self.split_at(offset).1.split_at(U32_BYTE_COUNT).0;
        BufferReader::from_parts(data.ptr(), data.len()).decode()
    }

    // ===== u8 ====

    /// Reads a u8 at the specified offset.
    /// Reverts if it violates the bounds of self.
    pub fn read_u8(self, offset: u64) -> u8 {
        self.get(offset).unwrap()
    }

    /// Logs all bytes without len encoding.
    pub fn log(self) {
        // See https://fuellabs.github.io/fuel-specs/master/vm/instruction_set.html#logd-log-data-event
        asm(ptr: self.ptr(), bytes: self.len()) {
            logd zero zero ptr bytes;
        };
    }

    /// Transforms a Bytes object into a b256 object.
    ///
    /// ### Returns
    ///
    /// * [b256] - Hash of the Bytes object.
    pub fn keccak256(self) -> b256 {
        keccak256(self)
    }

    /// Eth signatures are 65 bytes long, with the last byte representing the recovery id.
    /// This function converts a 65 byte signature to a 64 byte compact signature.
    ///
    /// ### Returns
    ///
    /// * [B512] - The compact signature.
    pub fn to_compact_signature(self) -> Option<B512> {
        // Ensure the signature is properly formatted
        if self.len() != 65 {
            return None
        }
        let (r, rest) = self.split_at(32);
        let (s, v) = rest.split_at(32);
        let r_bytes: b256 = BufferReader::from_parts(r.ptr(), r.len()).decode();
        let r_bytes: [u8; 32] = r_bytes.to_be_bytes();
        let mut y_parity_and_s_bytes: b256 = BufferReader::from_parts(s.ptr(), s.len()).decode();
        let mut y_parity_and_s_bytes: [u8; 32] = y_parity_and_s_bytes.to_be_bytes();
        let v = v.read_u8(0);
        if v == 28 {
            y_parity_and_s_bytes[0] = __or(y_parity_and_s_bytes[0], 0x80);
        }

        let buffer = Buffer::new();
        let buffer = y_parity_and_s_bytes.abi_encode(buffer);
        let bytes = Bytes::from(buffer.as_raw_slice());
        let y_parity_and_s_bytes = b256::from(bytes);

        let buffer = Buffer::new();
        let buffer = r_bytes.abi_encode(buffer);
        let bytes = Bytes::from(buffer.as_raw_slice());
        let r_bytes = b256::from(bytes);
        Some(B512::from((r_bytes, y_parity_and_s_bytes)))
    }
}

impl Bytes {
    /// Returns the keccak256 digest of an ERC-191 signed data with version `0x45` (`personal_sign` messages).
    ///
    /// The digest is calculated by prefixing a bytes32 `messageHash` with
    /// `"\x19Ethereum Signed Message:\n32"` and hashing the result. It corresponds with the
    /// hash signed when using the https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`] JSON-RPC method.
    ///
    /// NOTE: The `messageHash` parameter is intended to be the result of hashing a raw message with
    /// keccak256, although any bytes32 value can be safely used because the final digest will
    /// be re-hashed.
    ///
    /// ### Arguments
    ///
    /// * `hash`: [b256] - The bytes32 hash of the message to be signed.
    ///
    /// ### Returns
    ///
    /// * [b256] - The keccak256 digest of the signed message hash.
    pub fn to_eth_signed_message_hash(hash: b256) -> b256 {
        // We need the String "\x19Ethereum Signed Message:\n32" to be encoded as bytes
        // but sway does not encode special chars correctly when they are in a string
        // so we need to encode them manually
        let prefix_start = 0x19u8; // '\x19' in utf-8
        let prefix = __to_str_array("Ethereum Signed Message:");
        let escape_char = 0x0au8; // '\n' in utf-8
        // We encode 32 as two separate bytes so we don't need to cut off the str length encoding
        let postprefix1 = 0x33u8; // '3' in utf-8
        let postprefix2 = 0x32u8; // '2' in utf-8

        // Encode full prefix to buffer
        let buffer = Buffer::new();
        let buffer = prefix_start.abi_encode(buffer);
        let buffer = prefix.abi_encode(buffer);
        let buffer = escape_char.abi_encode(buffer);
        let buffer = postprefix1.abi_encode(buffer);
        let buffer = postprefix2.abi_encode(buffer);
        let buffer = hash.abi_encode(buffer);
        let bytes = Bytes::from(buffer.as_raw_slice());
        bytes.keccak256()
    }
}

#[test]
fn eth_prefix_hash() {
    let hash = 0x4e3f92dc1bff4057a7c5e6b9f1f6c9c3a573432c2e09b68a9efb86d9904aa96f;
    // The expected hash derived by running the hash above through the same function in Solidity
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/c1d49a32595bbe095960c43bee34e64a9cfe9f37/contracts/utils/cryptography/MessageHashUtils.sol#L30
    let expected = 0xfd087af1ca133839a8eb21ef8598c2aa006c119f631b21b601949f1a22978c86;

    let eth_prefix_hash = Bytes::to_eth_signed_message_hash(hash);
    assert(expected == eth_prefix_hash);
}