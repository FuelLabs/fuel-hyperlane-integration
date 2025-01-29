library;

use std::bytes::Bytes;
use std_lib_extended::bytes::*;

/// Byte layout of StandardHookMetadata:
///   variant:        [0:2]
///   msg_value:      [2:34]
///   gas_limit:      [34:66]
///   refund_address: [66:98]
pub struct StandardHookMetadata {
    /// The metadata variant identifier
    pub variant: u16,
    /// The message value in native tokens
    pub msg_value: u256,
    /// Gas limit for the message
    pub gas_limit: u256,
    /// Refund address for unused gas
    pub refund_address: b256,
}

/// Byte offsets of metadata properties
pub const VARIANT_OFFSET: u64 = 0;
pub const MSG_VALUE_OFFSET: u64 = 2;
pub const GAS_LIMIT_OFFSET: u64 = 34;
pub const REFUND_ADDRESS_OFFSET: u64 = 66;
pub const MIN_METADATA_LENGTH: u64 = 98;
/// Standard variant value
pub const DEFAULT_VARIANT: u16 = 1;

impl StandardHookMetadata {
    /// Gets the variant from metadata bytes.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata bytes to read from.
    ///
    /// ### Returns
    ///
    /// * [u16] - The metadata variant.
    pub fn get_variant(metadata: Bytes) -> u16 {
        if metadata.len() < VARIANT_OFFSET + 2 {
            return 0;
        }
        let data = metadata.split_at(VARIANT_OFFSET).1;
        let data = data.split_at(2).0;
        BufferReader::from_parts(data.ptr(), data.len()).decode()
    }

    /// Gets the msg_value from metadata bytes.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata bytes to read from.
    /// * `default`: [u256] - Default value if metadata is invalid.
    ///
    /// ### Returns
    ///
    /// * [u256] - The message value.
    pub fn get_msg_value(metadata: Bytes, default: u256) -> u256 {
        if metadata.len() < MSG_VALUE_OFFSET + 32 {
            return default;
        }
        let data = metadata.split_at(MSG_VALUE_OFFSET).1;
        let data = data.split_at(32).0;
        BufferReader::from_parts(data.ptr(), data.len()).decode()
    }

    /// Gets the gas_limit from metadata bytes.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata bytes to read from.
    /// * `default`: [u256] - Default value if metadata is invalid.
    ///
    /// ### Returns
    ///
    /// * [u256] - The gas limit.
    pub fn get_gas_limit(metadata: Bytes, default: u256) -> u256 {
        if metadata.len() < GAS_LIMIT_OFFSET + 32 {
            return default;
        }
        let data = metadata.split_at(GAS_LIMIT_OFFSET).1;
        let data = data.split_at(32).0;
        BufferReader::from_parts(data.ptr(), data.len()).decode()
    }

    /// Gets the refund_address from metadata bytes.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata bytes to read from.
    /// * `default`: [b256] - Default address if metadata is invalid.
    ///
    /// ### Returns
    ///
    /// * [b256] - The refund address.
    pub fn get_refund_address(metadata: Bytes, default: b256) -> b256 {
        if metadata.len() < REFUND_ADDRESS_OFFSET + 32 {
            return default;
        }
        metadata.read_b256(REFUND_ADDRESS_OFFSET)
    }

    /// Creates a new StandardHookMetadata from bytes.
    ///
    /// ### Arguments
    ///
    /// * `bytes`: [Bytes] - The bytes to create the metadata from.
    ///
    /// ### Returns
    ///
    /// * [StandardHookMetadata] - The metadata struct.
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self {
            variant: Self::get_variant(bytes),
            msg_value: Self::get_msg_value(bytes, 0),
            gas_limit: Self::get_gas_limit(bytes, 0),
            refund_address: Self::get_refund_address(
                bytes,
                0x0000000000000000000000000000000000000000000000000000000000000000,
            ),
        }
    }

    /// Validates if the metadata is of the correct format and length
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata to validate
    ///
    /// ### Returns
    ///
    /// * [bool] - Whether the metadata is valid or empty
    pub fn is_valid(metadata: Bytes) -> bool {
        // Empty metadata is valid
        if metadata.len() == 0 {
            return true;
        }

        // Check minimum length
        if metadata.len() < MIN_METADATA_LENGTH {
            return false;
        }

        // Check variant
        let variant = Self::get_variant(metadata);
        if variant != DEFAULT_VARIANT {
            return false;
        }

        true
    }

    /// Gets the variant from the struct.
    ///
    /// ### Returns
    ///
    /// * [u16] - The metadata variant.
    pub fn variant(self) -> u16 {
        self.variant
    }

    /// Gets the msg_value from the struct.
    ///
    /// ### Returns
    ///
    /// * [u256] - The message value.
    pub fn msg_value(self) -> u256 {
        self.msg_value
    }

    /// Gets the gas_limit from the struct.
    ///
    /// ### Returns
    ///
    /// * [u256] - The gas limit.
    pub fn gas_limit(self) -> u256 {
        self.gas_limit
    }

    /// Gets the refund_address from the struct.
    ///
    /// ### Returns
    ///
    /// * [b256] - The refund address.
    pub fn refund_address(self) -> b256 {
        self.refund_address
    }

    /// Formats metadata into bytes.
    ///
    /// ### Arguments
    ///
    /// * `msg_value`: [u256] - The message value.
    /// * `gas_limit`: [u256] - The gas limit.
    /// * `refund_address`: [b256] - The refund address.
    /// * `custom_metadata`: [Bytes] - Additional custom metadata.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - The encoded metadata.
    pub fn format_metadata(
        msg_value: u256,
        gas_limit: u256,
        refund_address: b256,
        custom_metadata: Bytes,
    ) -> Bytes {
        let buffer = Buffer::new();
        let buffer = DEFAULT_VARIANT.abi_encode(buffer);
        let buffer = msg_value.abi_encode(buffer);
        let buffer = gas_limit.abi_encode(buffer);
        let buffer = refund_address.abi_encode(buffer);
        let buffer = custom_metadata.abi_encode(buffer);

        Bytes::from(buffer.as_raw_slice())
    }

    /// Gets custom metadata from bytes.
    ///
    /// ### Arguments
    ///
    /// * `bytes`: [Bytes] - The metadata bytes.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - The custom metadata portion.
    pub fn get_custom_metadata(bytes: Bytes) -> Bytes {
        if bytes.len() < MIN_METADATA_LENGTH {
            return Bytes::new();
        }
        bytes.split_at(MIN_METADATA_LENGTH).1
    }

    /// Creates metadata with only msg_value set.
    ///
    /// ### Arguments
    ///
    /// * `msg_value`: [u256] - The message value to set.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - The encoded metadata.
    pub fn override_msg_value(msg_value: u256) -> Bytes {
        Self::format_metadata(msg_value, 0, msg_sender().unwrap().bits(), Bytes::new())
    }

    /// Creates metadata with only gas_limit set.
    ///
    /// ### Arguments
    ///
    /// * `gas_limit`: [u256] - The gas limit to set.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - The encoded metadata.
    pub fn override_gas_limit(gas_limit: u256) -> Bytes {
        Self::format_metadata(0, gas_limit, msg_sender().unwrap().bits(), Bytes::new())
    }

    /// Creates metadata with only refund_address set.
    ///
    /// ### Arguments
    ///
    /// * `refund_address`: [b256] - The refund address to set.
    ///
    /// ### Returns
    ///
    /// * [Bytes] - The encoded metadata.
    pub fn override_refund_address(refund_address: b256) -> Bytes {
        Self::format_metadata(0, 0, refund_address, Bytes::new())
    }
}
