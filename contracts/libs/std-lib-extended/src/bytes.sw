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

use ::mem::*;

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

/// The EVM address will start 12 bytes into the underlying b256.
const EVM_ADDRESS_B256_BYTE_OFFSET: u64 = 12u64;
/// The number of bytes in an EVM address.
pub const EVM_ADDRESS_BYTE_COUNT: u64 = 20u64;

impl EvmAddress {
    /// Returns a pointer to the EvmAddress's packed bytes.
    fn packed_bytes(self) -> raw_ptr {
        __addr_of(self).add_uint_offset(EVM_ADDRESS_B256_BYTE_OFFSET)
    }

    /// Gets an EvmAddress from a pointer to packed bytes.
    fn from_packed_bytes(ptr: raw_ptr) -> Self {
        // The EvmAddress value will be written to this b256.
        let mut value: b256 = ZERO_B256;
        // Point to 12 bytes into the 32 byte b256, where the EVM address
        // contents are expected to start.
        let value_ptr = __addr_of(value).add_uint_offset(EVM_ADDRESS_B256_BYTE_OFFSET);
        // Write the bytes from ptr into value_ptr.
        ptr.copy_bytes_to(value_ptr, EVM_ADDRESS_BYTE_COUNT);
        // Return the value.
        EvmAddress::from(value)
    }
}

/// The number of bytes in a B512.
pub const B512_BYTE_COUNT: u64 = 64u64;

impl B512 {
    /// Returns a pointer to the B512's packed bytes.
    fn packed_bytes(self) -> raw_ptr {
        __addr_of(self.bits())
    }

    /// Gets a B512 from a pointer to packed bytes.
    fn from_packed_bytes(ptr: raw_ptr) -> Self {
        let component_0 = b256::from_packed_bytes(ptr);
        let component_1 = b256::from_packed_bytes(ptr.add_uint_offset(B256_BYTE_COUNT));

        B512::from((component_0, component_1))
    }
}

/// The number of bytes in a u64.
pub const U64_BYTE_COUNT: u64 = 8u64;

impl u64 {
    /// Returns a pointer to the u64's packed bytes.
    fn packed_bytes(self) -> raw_ptr {
        CopyTypeWrapper::ptr_to_value(WrapperType::U64(self), U64_BYTE_COUNT)
    }

    /// Gets a u64 from a pointer to packed bytes.
    fn from_packed_bytes(ptr: raw_ptr) -> Self {
        CopyTypeWrapper::value_from_ptr(ptr, TypeBytes::U64(U64_BYTE_COUNT)).get_value()
    }
}

/// The number of bytes in a u32.
pub const U32_BYTE_COUNT: u64 = 4u64;

impl u32 {
    /// Returns a pointer to the u32's packed bytes.
    fn packed_bytes(self) -> raw_ptr {
        CopyTypeWrapper::ptr_to_value(WrapperType::U32(self), U32_BYTE_COUNT)
    }

    /// Gets a u32 from a pointer to packed bytes.
    fn from_packed_bytes(ptr: raw_ptr) -> Self {
        CopyTypeWrapper::value_from_ptr(ptr, TypeBytes::U32(U32_BYTE_COUNT)).get_value()
    }
}

/// The number of bytes in a u16.
pub const U16_BYTE_COUNT: u64 = 2u64;

impl u16 {
    /// Returns a pointer to the u16's packed bytes.
    fn packed_bytes(self) -> raw_ptr {
        CopyTypeWrapper::ptr_to_value(WrapperType::U16(self), U16_BYTE_COUNT)
    }

    /// Gets a u16 from a pointer to packed bytes.
    fn from_packed_bytes(ptr: raw_ptr) -> Self {
        CopyTypeWrapper::value_from_ptr(ptr, TypeBytes::U16(U16_BYTE_COUNT)).get_value()
    }
}

impl Bytes {
    /// Constructs a new `Bytes` with the specified length and capacity.
    ///
    /// The Bytes will be able to hold exactly `length` bytes without
    /// reallocating.
    /// Pads the Bytes with zeros.
    ///
    /// ### Arguments
    ///
    /// * `length`: [u64] - The length of the Bytes to create.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - The newly created Bytes with the specified length & capacity.
    pub fn with_length(length: u64) -> Self {
        let mut bytes = Bytes::with_capacity(length);
        while bytes.len() < length {
            bytes.push(0u8);
        }
        bytes
    }

    /// Copies `byte_count` bytes from `bytes_ptr` into self at the specified offset.
    /// Reverts if the bounds of self are violated.
    /// Returns the byte index after the last byte written.
    pub fn write_packed_bytes(
        ref mut self,
        offset: u64,
        bytes_ptr: raw_ptr,
        byte_count: u64,
) -> u64 {
        let new_byte_offset = offset + byte_count;
        // Ensure that the written bytes will stay within the correct bounds.
        assert(new_byte_offset <= self.len());
        // Get a pointer to the buffer at the offset.
        let write_ptr = self.ptr().add_uint_offset(offset);
        // Copy from the `bytes_ptr` into `write_ptr`.
        bytes_ptr.copy_bytes_to(write_ptr, byte_count);
        new_byte_offset
    }

    /// Gets a pointer to bytes within self at the specified offset.
    /// Reverts if the `byte_count`, which is the expected number of bytes
    /// to read from the pointer, violates the bounds of self.
    pub fn get_read_ptr(self, offset: u64, byte_count: u64) -> raw_ptr {
        // Ensure that the bytes to read are within the correct bounds.
        assert(offset + byte_count <= self.len());
        // Get a pointer to buffer at the offset.
        self.ptr().add_uint_offset(offset)
    }
}

impl Bytes {
    // ===== b256 ====
    /// Writes a b256 at the specified offset. Reverts if it violates the
    /// bounds of self.
    /// Returns the byte index after the end of the b256.
    pub fn write_b256(ref mut self, offset: u64, value: b256) -> u64 {
        self.write_packed_bytes(offset, value.packed_bytes(), B256_BYTE_COUNT)
    }

    /// Reads a b256 at the specified offset.
    /// Reverts if it violates the bounds of self.
    pub fn read_b256(self, offset: u64) -> b256 {
        let data = self.split_at(offset).1.split_at(B256_BYTE_COUNT).0;
        BufferReader::from_parts(data.ptr(), data.len()).decode()
    }

    // ===== EvmAddress ====
    /// Writes an EvmAddress at the specified offset. Reverts if it violates the
    /// bounds of self.
    /// Returns the byte index after the end of the address.
    pub fn write_evm_address(ref mut self, offset: u64, value: EvmAddress) -> u64 {
        self.write_packed_bytes(offset, value.packed_bytes(), EVM_ADDRESS_BYTE_COUNT)
    }

    /// Reads an EvmAddress at the specified offset.
    pub fn read_evm_address(ref mut self, offset: u64) -> EvmAddress {
        let read_ptr = self.get_read_ptr(offset, EVM_ADDRESS_BYTE_COUNT);

        EvmAddress::from_packed_bytes(read_ptr)
    }

    // ===== B512 ====
    /// Writes a B512 at the specified offset. Reverts if it violates the
    /// bounds of self.
    /// Returns the byte index after the end of the B512.
    pub fn write_b512(ref mut self, offset: u64, value: B512) -> u64 {
        self.write_packed_bytes(offset, value.packed_bytes(), B512_BYTE_COUNT)
    }

    /// Reads a B512 at the specified offset.
    /// Reverts if it violates the bounds of self.
    pub fn read_b512(self, offset: u64) -> B512 {
        let read_ptr = self.get_read_ptr(offset, B256_BYTE_COUNT);

        B512::from_packed_bytes(read_ptr)
    }

    // ===== u64 ====
    /// Writes a u64 at the specified offset. Reverts if it violates the
    /// bounds of self.
    /// Returns the byte index after the end of the u64.
    pub fn write_u64(ref mut self, offset: u64, value: u64) -> u64 {
        self.write_packed_bytes(offset, value.packed_bytes(), U64_BYTE_COUNT)
    }

    /// Reads a u64 at the specified offset.
    /// Reverts if it violates the bounds of self.
    pub fn read_u64(self, offset: u64) -> u64 {
        let read_ptr = self.get_read_ptr(offset, U64_BYTE_COUNT);

        u64::from_packed_bytes(read_ptr)
    }

    // ===== u32 ====
    /// Writes a u32 at the specified offset. Reverts if it violates the
    /// bounds of self.
    /// Returns the byte index after the end of the u32.
    pub fn write_u32(ref mut self, offset: u64, value: u32) -> u64 {
        self.write_packed_bytes(offset, value.packed_bytes(), U32_BYTE_COUNT)
    }

    /// Reads a u32 at the specified offset.
    /// Reverts if it violates the bounds of self.
    pub fn read_u32(self, offset: u64) -> u32 {
        let data = self.split_at(offset).1.split_at(U32_BYTE_COUNT).0;
        BufferReader::from_parts(data.ptr(), data.len()).decode()
    }

    // ===== u16 ====
    /// Writes a u16 at the specified offset. Reverts if it violates the
    /// bounds of self.
    /// Returns the byte index after the end of the u16.
    pub fn write_u16(ref mut self, offset: u64, value: u16) -> u64 {
        self.write_packed_bytes(offset, value.packed_bytes(), U16_BYTE_COUNT)
    }

    /// Reads a u16 at the specified offset.
    /// Reverts if it violates the bounds of self.
    pub fn read_u16(self, offset: u64) -> u16 {
        let read_ptr = self.get_read_ptr(offset, U16_BYTE_COUNT);
        u16::from_packed_bytes(read_ptr)
    }

    // ===== u8 ====
    /// Writes a u8 at the specified offset. Reverts if it violates the
    /// bounds of self.
    /// Returns the byte index after the end of the u8.
    pub fn write_u8(ref mut self, offset: u64, value: u8) -> u64 {
        self.set(offset, value);
        offset + 1
    }

    /// Reads a u8 at the specified offset.
    /// Reverts if it violates the bounds of self.
    pub fn read_u8(self, offset: u64) -> u8 {
        self.get(offset).unwrap()
    }

    // ===== Bytes =====
    /// Writes Bytes at the specified offset. Reverts if it violates the
    /// bounds of self.
    /// Returns the byte index after the end of the bytes written.
    pub fn write_bytes(ref mut self, offset: u64, value: Bytes) -> u64 {
        self.write_packed_bytes(offset, value.ptr(), value.len())
    }


    /// Reads Bytes at the specified offset.
    /// Reverts if it violates the bounds of self.
    /// Does not modify the Bytes object.
    ///
    /// ### Arguments
    ///
    /// * `offset`: [u64] - The offset to read the Bytes from.
    /// * `len`: [u64] - The length of the Bytes to read.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - The Bytes object read from the specified offset.
    pub fn read_bytes(self, offset: u64, len: u64) -> Bytes {
        let read_ptr = self.get_read_ptr(offset, len);

        let mut bytes = Bytes::with_length(len);
        read_ptr.copy_bytes_to(bytes.ptr(), len);
        bytes
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