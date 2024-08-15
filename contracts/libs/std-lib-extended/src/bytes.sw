library;

use std::{
    b512::B512,
    bytes::Bytes,
    constants::ZERO_B256,
    hash::{
        Hash,
        keccak256,
    },
    vm::evm::evm_address::EvmAddress,
    array_conversions::b256::*,
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
    pub fn with_length(length: u64) -> Self {
        // TODO Used to be implemented by changing the len param
        // of the Bytes struct. This is no longer possible.
        // Investigate if there is a better way to implement this.
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
        // let read_ptr = self.get_read_ptr(offset, B256_BYTE_COUNT);
        // b256::from_packed_bytes(read_ptr)
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

        // let read_ptr = self.get_read_ptr(offset, U32_BYTE_COUNT);

        // u32::from_packed_bytes(read_ptr)
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

    // TODO Old implementation, does not work with new Sway version
    // Reads Bytes starting at the specified offset with the `len` number of bytes.
    // Does not copy any bytes, and instead points to the bytes within self.
    // Changing the contents of the returned bytes will affect self, so be cautious
    // of unintented consequences!
    // Reverts if it violates the bounds of self.
    // pub fn read_bytes(self, offset: u64, len: u64) -> Bytes {
    //     let read_ptr = self.get_read_ptr(offset, len);
    //
    //     // Create an empty Bytes
    //     let mut bytes = Bytes::new();
    //     // Manually set the RawBytes ptr to where we want to read from.
    //     bytes.buf.ptr = read_ptr;
    //     // Manually set the RawBytes cap to the number of bytes.
    //     bytes.buf.cap = len;
    //     // Manually set the len to the correct number of bytes.
    //     bytes.len = len;
    //     bytes
    // }

    // TODO Possibly use split_at instead of copying bytes
    pub fn read_bytes(self, offset: u64, len: u64) -> Bytes {
        let read_ptr = self.get_read_ptr(offset, len);

        let mut bytes = Bytes::with_length(len);
        read_ptr.copy_bytes_to(bytes.ptr(), len);
        bytes
    }

    /// Logs all bytes.
    pub fn log(self) {
        // See https://fuellabs.github.io/fuel-specs/master/vm/instruction_set.html#logd-log-data-event
        asm(ptr: self.ptr(), bytes: self.len()) {
            logd zero zero ptr bytes;
        };
    }

    /// Logs all bytes.
    /// `log_id` is a marker value to identify the logged data,
    /// which is set to `rB` in the logd instruction.
    pub fn log_with_id(self, log_id: u64) {
        // See https://fuellabs.github.io/fuel-specs/master/vm/instruction_set.html#logd-log-data-event
        asm(ptr: self.ptr(), bytes: self.len(), log_id: log_id) {
            logd zero log_id ptr bytes;
        };
    }

    pub fn keccak256(self) -> b256 {
        keccak256(self)
    }

    // Eth signatures are 65 bytes long, with the last byte representing the recovery id.
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

<<<<<<< HEAD:contracts/std-lib-extended/src/bytes.sw

=======
>>>>>>> origin:contracts/libs/std-lib-extended/src/bytes.sw
impl Bytes {
    // XXX use `to_eth_signed_message_hash` instead
    // Returns a new Bytes with "/x19Ethereum Signed Message:/n32" prepended to the hash.
    // pub fn with_ethereum_prefix(hash: b256) -> Self {
    //     let prefix = "Ethereum Signed Message:";
    //     // 1 byte for 0x19, 24 bytes for the prefix, 1 byte for \n, 2 bytes for 32
    //     let prefix_len = 1 + 24 + 1 + 2;
    //     let mut _self = Bytes::with_length(prefix_len + B256_BYTE_COUNT);
    //     let mut offset = 0u64;
    //     // Write the 0x19
    //     offset = _self.write_u8(offset, 0x19u8);
    //     // Write the prefix
    //     offset = _self.write_packed_bytes(offset, __addr_of(prefix), 24u64);
    //     // Write \n (0x0a is the utf-8 representation of \n)
    //     offset = _self.write_u8(offset, 0x0au8);
    //     // Write "32" as a string.
    //     let hash_len_str = "32";
    //     offset = _self.write_packed_bytes(offset, __addr_of(hash_len_str), 2);
    //     // Write the hash
    //     offset = _self.write_b256(offset, hash);
    //     //assert(offset == _self.len);
    //     _self
    // }

    /// Returns the keccak256 digest of an ERC-191 signed data with version `0x45` (`personal_sign` messages).
    ///
    /// The digest is calculated by prefixing a bytes32 `messageHash` with
    /// `"\x19Ethereum Signed Message:\n32"` and hashing the result. It corresponds with the
    /// hash signed when using the https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`] JSON-RPC method.
    ///
    /// NOTE: The `messageHash` parameter is intended to be the result of hashing a raw message with
    /// keccak256, although any bytes32 value can be safely used because the final digest will
    /// be re-hashed.
    pub fn to_eth_signed_message_hash(hash: b256) -> b256 {
        // We need the String "\x19Ethereum Signed Message:\n32" to be encoded as bytes
        // but sway does not encode special chars correctly when they are in a string
        // so we need to encode them manually
        let prefix_start = 0x19u8; // '\x19' in utf-8
        let prefix = "Ethereum Signed Message:";
<<<<<<< HEAD
<<<<<<< HEAD:contracts/std-lib-extended/src/bytes.sw
        let prefix_len = 1 + 24 + 1 + 2;
        let mut _self = Bytes::with_length(prefix_len + B256_BYTE_COUNT);

        let mut offset = 0u64;
        offset = _self.write_u8(offset, 0x19u8);
        offset = _self.write_packed_bytes(offset, __addr_of(prefix), 24u64);
        offset = _self.write_u8(offset, 0x0au8);
        let hash_len_str = "32";
        offset = _self.write_packed_bytes(offset, __addr_of(hash_len_str), 2);
        offset = _self.write_b256(offset, hash);
        // log("offset modified");
        // log(offset);

=======
        // 1 byte for 0x19, 24 bytes for the prefix, 1 byte for \n, 2 bytes for 32
        let prefix_len = 1 + 24 + 1 + 2;
        let mut _self = Bytes::with_length(prefix_len + B256_BYTE_COUNT);
        let mut offset = 0u64;
        // Write the 0x19
        offset = _self.write_u8(offset, 0x19u8);
        // Write the prefix
        offset = _self.write_packed_bytes(offset, __addr_of(prefix), 24u64);
        // Write \n (0x0a is the utf-8 representation of \n)
        offset = _self.write_u8(offset, 0x0au8);
        // Write "32" as a string.
        let hash_len_str = "32";
        offset = _self.write_packed_bytes(offset, __addr_of(hash_len_str), 2);
        // Write the hash
        offset = _self.write_b256(offset, hash);
>>>>>>> origin:contracts/libs/std-lib-extended/src/bytes.sw
        //assert(offset == _self.len);
        _self
=======
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

        // Cut off the str length encoding which is 8 bytes
        let prefix_bytes = Bytes::from(buffer.as_raw_slice());
        let (mut data, body_with_len) = prefix_bytes.split_at(1);
        let body = body_with_len.split_at(8).1;
        data.append(body); // Full prefix

        // Encode the hash to buffer 
        let buffer = Buffer::new();
        let buffer = hash.abi_encode(buffer);
        let hash_bytes = Bytes::from(buffer.as_raw_slice());

        data.append(hash_bytes); // Fully encoded data
        data.keccak256()
>>>>>>> feat/ism
    }
}
<<<<<<< HEAD:contracts/std-lib-extended/src/bytes.sw

pub fn bytes_to_str_128(bytes: Bytes) -> str[128] {
    // Create copy that's 128 bytes in length.
    // It's possible for `bytes` to have a length < 128 bytes,
    // so to avoid the str[128] bad memory out of bounds, a copy with the
    // correct length is created.
    let mut copy = Bytes::with_length(128);
    let _ = copy.write_bytes(0u64, bytes);

    let read_ptr = copy.get_read_ptr(0, 128);
    // convert the ptr to a str[128]
    asm(ptr: read_ptr) {
        ptr: str[128]
    }
}
=======
>>>>>>> origin:contracts/libs/std-lib-extended/src/bytes.sw

#[test]
fn eth_prefix_hash() {
    let hash = 0x4e3f92dc1bff4057a7c5e6b9f1f6c9c3a573432c2e09b68a9efb86d9904aa96f;
    // The expected hash derived by running the hash above through the same function in Solidity
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/c1d49a32595bbe095960c43bee34e64a9cfe9f37/contracts/utils/cryptography/MessageHashUtils.sol#L30
    let expected = 0xfd087af1ca133839a8eb21ef8598c2aa006c119f631b21b601949f1a22978c86;

    let eth_prefix_hash = Bytes::to_eth_signed_message_hash(hash);
    assert(expected == eth_prefix_hash);
}


// Bytes::from_vec_u8 requires a mutable Vec<u8> to be passed in.
// Certain situations, like when a Vec is a parameter to a public abi function,
// the Vec cannot be mutable. So instead we provide a non-mutable way to convert
// from Vec<u8> to Bytes.
// TODO check if needed
// impl From<Vec<u8>> for Bytes {
//     fn from(vec: Vec<u8>) -> Self {
//         let vec_len = vec.len();
//         let mut bytes = Bytes::with_length(vec_len);
//         let mut i = 0;
//         while i < vec_len {
//             bytes.set(i, vec.get(i).unwrap());
//             i += 1;
//         }
//         bytes
//     }

//     fn into(self) -> Vec<u8> {
//         require(false, "Bytes -> Vec<u8> not implemented");
//         Vec::new()
//     }
// }

// ==================================================
// =====                                        =====
// =====                  Tests                 =====
// =====                                        =====
// ==================================================

// fn write_and_read_b256(ref mut bytes: Bytes, offset: u64, value: b256) -> b256 {
//     let _ = bytes.write_b256(offset, value);
//     bytes.read_b256(offset)
// }

// #[test()]
// fn test_write_and_read_b256() {
//     let mut bytes = Bytes::with_length(64);

//     let value: b256 = 0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe;
//     // 0 byte offset
//     assert(value == write_and_read_b256(bytes, 0u64, value));

//     // 32 byte offset - tests word-aligned case and writing to the end of the Bytes
//     assert(value == write_and_read_b256(bytes, 32u64, value));

//     // 30 byte offset - tests non-word-aligned case and overwriting existing bytes
//     assert(value == write_and_read_b256(bytes, 30u64, value));
// }

// fn write_and_read_evm_address(ref mut bytes: Bytes, offset: u64, value: EvmAddress) -> EvmAddress {
//     let _ = bytes.write_evm_address(offset, value);
//     bytes.read_evm_address(offset)
// }

// #[test()]
// fn test_write_and_read_evm_address() {
//     let mut bytes = Bytes::with_length(64);

//     let value: EvmAddress = EvmAddress::from(0xdeadeadeadeadeadeadeadeacafecafecafecafecafecafecafecafecafecafe);

//     // Sanity check that an EvmAddress will zero out the first 12 bytes of the b256
//     assert(
//         value == EvmAddress::from(0x000000000000000000000000cafecafecafecafecafecafecafecafecafecafe),
//     );

//     // 0 byte offset
//     assert(value == write_and_read_evm_address(bytes, 0u64, value));

//     // 44 byte offset - tests word-aligned case and writing to the end of the Bytes
//     assert(value == write_and_read_evm_address(bytes, 44u64, value));

//     // 40 byte offset - tests non-word-aligned case and overwriting existing bytes
//     assert(value == write_and_read_evm_address(bytes, 40u64, value));
// }

// fn write_and_read_b512(ref mut bytes: Bytes, offset: u64, value: B512) -> B512 {
//     let _ = bytes.write_b512(offset, value);
//     bytes.read_b512(offset)
// }

// #[test()]
// fn test_write_and_read_b512() {
//     let mut bytes = Bytes::with_length(128);

//     let value: B512 = B512::from((
//         0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe,
//         0xdeadeadeadeadeadeadeadeadeadeadeadeadeadeadeadeadeadeadeadeadead,
//     ));
//     // 0 byte offset
//     assert(value == write_and_read_b512(bytes, 0u64, value));

//     // 64 byte offset - tests word-aligned case and writing to the end of the Bytes
//     assert(value == write_and_read_b512(bytes, 64u64, value));

//     // 50 byte offset - tests non-word-aligned case and overwriting existing bytes
//     assert(value == write_and_read_b512(bytes, 50u64, value));
// }

// fn write_and_read_u64(ref mut bytes: Bytes, offset: u64, value: u64) -> u64 {
//     let _ = bytes.write_u64(offset, value);
//     bytes.read_u64(offset)
// }

// #[test()]
// fn test_write_and_read_u64() {
//     let mut bytes = Bytes::with_length(16);

//     let value: u64 = 0xabcdefabu64;
//     // 0 byte offset
//     assert(value == write_and_read_u64(bytes, 0u64, value));

//     // 8 byte offset - tests word-aligned case and writing to the end of the Bytes
//     assert(value == write_and_read_u64(bytes, 8u64, value));

//     // 6 byte offset - tests non-word-aligned case and overwriting existing bytes
//     assert(value == write_and_read_u64(bytes, 6u64, value));
// }

// fn write_and_read_u32(ref mut bytes: Bytes, offset: u64, value: u32) -> u32 {
//     let _ = bytes.write_u32(offset, value);
//     bytes.read_u32(offset)
// }

// #[test()]
// fn test_write_and_read_u32() {
//     let mut bytes = Bytes::with_length(16);

//     let value: u32 = 0xabcdu32;
//     // 0 byte offset
//     assert(value == write_and_read_u32(bytes, 0u64, value));

//     // 12 byte offset - tests word-aligned case and writing to the end of the Bytes
//     assert(value == write_and_read_u32(bytes, 12u64, value));

//     // 11 byte offset - tests non-word-aligned case and overwriting existing bytes
//     assert(value == write_and_read_u32(bytes, 11u64, value));
// }

// fn write_and_read_u16(ref mut bytes: Bytes, offset: u64, value: u16) -> u16 {
//     let _ = bytes.write_u16(offset, value);
//     bytes.read_u16(offset)
// }

// #[test()]
// fn test_write_and_read_u16() {
//     let mut bytes = Bytes::with_length(16);

//     let value: u16 = 0xabu16;
//     // 0 byte offset
//     assert(value == write_and_read_u16(bytes, 0u64, value));

//     // 14 byte offset - tests word-aligned case and writing to the end of the Bytes
//     assert(value == write_and_read_u16(bytes, 14u64, value));

//     // 13 byte offset - tests non-word-aligned case and overwriting existing bytes
//     assert(value == write_and_read_u16(bytes, 13u64, value));
// }

// fn write_and_read_u8(ref mut bytes: Bytes, offset: u64, value: u8) -> u8 {
//     let _ = bytes.write_u8(offset, value);
//     bytes.read_u8(offset)
// }

// #[test()]
// fn test_write_and_read_u8() {
//     let mut bytes = Bytes::with_length(16);

//     let value: u8 = 0xau8;
//     // 0 byte offset
//     assert(value == write_and_read_u8(bytes, 0u64, value));

//     // 15 byte offset - tests word-aligned case and writing to the end of the Bytes
//     assert(value == write_and_read_u8(bytes, 15u64, value));

//     // 14 byte offset - tests non-word-aligned case
//     assert(value == write_and_read_u8(bytes, 14u64, value));

//     // 14 byte offset - tests overwriting existing byte
//     assert(69u8 == write_and_read_u8(bytes, 14u64, 69u8));
// }

// fn write_and_read_bytes(ref mut bytes: Bytes, offset: u64, value: Bytes) -> Bytes {
//     let _ = bytes.write_bytes(offset, value);
//     bytes.read_bytes(offset, value.len())
// }

// #[test()]
// fn test_write_and_read_bytes() {
//     let mut bytes = Bytes::with_length(64);

//     let mut value = Bytes::with_length(16);
//     let _ = value.write_u64(0u64, 0xabcdefabu64);
//     let _ = value.write_u64(8u64, 0xabcdefabu64);

//     // 0 byte offset
//     assert(value.keccak256() == write_and_read_bytes(bytes, 0u64, value).keccak256());

//     // 48 byte offset - tests word-aligned case and writing to the end of the Bytes
//     assert(value.keccak256() == write_and_read_bytes(bytes, 48u64, value).keccak256());

//     // 43 byte offset - tests word-aligned case and overwriting existing bytes
//     assert(value.keccak256() == write_and_read_bytes(bytes, 43u64, value).keccak256());
// }

// fn write_and_read_str(ref mut bytes: Bytes, offset: u64, value: str[30]) -> str[30] {
//     let _ = bytes.write_packed_bytes(0u64, __addr_of(value), 30);
//     let read_ptr = bytes.get_read_ptr(offset, 30);
//     // convert the ptr to a str[30]
//     asm(ptr: read_ptr) {
//         ptr: str[30]
//     }
// }

// #[test()]
// fn test_write_and_read_str() {
//     let mut bytes = Bytes::with_length(64);

//     let value = "\x19Ethereum Signed Message:\n";
//     let value_len = 30u64;

//     assert(
//         std::hash::sha256(value) == std::hash::sha256(write_and_read_str(bytes, 0u64, value)),
//     );
// }
// }
