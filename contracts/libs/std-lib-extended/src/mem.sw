library;

use std::convert::TryFrom;

use std::primitive_conversions::{u16::*, u32::*, u64::*,};
use std::revert::revert;

/// The number of bytes in a 64-bit Fuel VM word.
const BYTES_PER_WORD: u64 = 8u64;

pub enum WrapperType {
    U64: u64,
    U32: u32,
    U16: u16,
}

pub enum TypeBytes {
    U64: u64,
    U32: u64,
    U16: u64,
}

pub trait GetValue<T> {
    fn get_value(self) -> T;
}

impl GetValue<u64> for WrapperType {
    fn get_value(self) -> u64 {
        match self {
            WrapperType::U64(value) => value,
            _ => revert(0),
        }
    }
}

impl GetValue<u32> for WrapperType {
    fn get_value(self) -> u32 {
        match self {
            WrapperType::U32(value) => value,
            _ => revert(0),
        }
    }
}

impl GetValue<u16> for WrapperType {
    fn get_value(self) -> u16 {
        match self {
            WrapperType::U16(value) => value,
            _ => revert(0),
        }
    }
}

// impl WrapperType {
//     pub fn get_value(self) -> u64 {
//         match self {
//             WrapperType::U64(value) => value,
//             WrapperType::U32(value) => u64::from(value),
//             WrapperType::U16(value) => u64::from(value),
//         }
//     }
// }


impl TypeBytes {
    pub fn get_value(self) -> u64 {
        match self {
            TypeBytes::U64(value) | TypeBytes::U32(value) | TypeBytes::U16(value) => value,
        }
    }
}

/// Wraps a copy type.
///
/// Types like u64, u32, u16, u8, and bool are copy types,
/// which are ordinarily kept in registers and not in memory.
///
/// Wrapping a copy type in a struct will implicitly result in the
/// type being brought into memory. This struct exists to help write
/// and read copy types to and from memory.
pub struct CopyTypeWrapper {
    value: u64,
}

impl CopyTypeWrapper {
    /// Creates a new CopyTypeWrapper with the value 0.
    fn new() -> Self {
        Self { value: 0u64 }
    }

    /// Creates a new CopyTypeWrapper from `value`.
    /// Note that the value property of the struct is a u64,
    /// so any smaller types will be implicitly upcasted and left-padded
    /// with zeroes to fit within 64 bits.
    fn with_value(value: WrapperType) -> Self {
        match value {
            WrapperType::U64(v) => Self { value: v },
            WrapperType::U32(v) => Self {
                value: u64::from(v),
            },
            WrapperType::U16(v) => Self {
                value: u64::from(v),
            },
        }
    }

    /// Gets a pointer to where a value that is `byte_width`
    /// bytes in length starts.
    /// E.g. if the underlying value is a u16, `byte_width`
    /// should be `2`.
    fn get_ptr(self, byte_width: u64) -> raw_ptr {
        let ptr = __addr_of(self);
        // Account for the potential left-padding of the underlying value
        // to point directly to where the underlying value's contents
        // would start.
        ptr.add_uint_offset(BYTES_PER_WORD - byte_width)
    }

    /// Gets the value, implicitly casting from u64 to the desired type.
    // fn value<T>(self) -> T
    // where
    //     T: TryFrom<u64>,
    // {
    //     T::try_from(self.value).unwrap()
    // }
    fn value(self) -> u64 {
        self.value
    }
}

impl CopyTypeWrapper {
    /// Writes the copy type `value` that is `byte_count` bytes in length to
    /// memory and returns a pointer to where the value starts.
    ///
    /// ### Arguments
    ///
    /// * `value` - The value to write. While this is a u64, any values whose
    ///   original type is smaller may be implicitly upcasted.
    /// * `byte_count` - The number of bytes of the original value. E.g. if the value
    ///   being written is originally a u16, this should be 2 bytes.
    pub fn ptr_to_value(value: WrapperType, byte_count: u64) -> raw_ptr {
        // Use the wrapper struct to get a reference type for a non-reference type.
        let wrapper = Self::with_value(value);
        // Get the pointer to where the value starts within the wrapper struct.
        wrapper.get_ptr(byte_count)
    }

    /// Reads a copy type value that is `byte_count` bytes in length from `ptr`.
    ///
    /// ### Arguments
    /// * `ptr` - A pointer to memory where the value begins. The `byte_count` bytes
    ///   starting at `ptr` are read.
    /// * `byte_count` - The number of bytes of the value's type. E.g. if the value
    ///   being read is a u16, this should be 2 bytes.
    pub fn value_from_ptr(ptr: raw_ptr, byte_count: TypeBytes) -> WrapperType {
        // Create a wrapper struct with a zero value.
        let wrapper = CopyTypeWrapper::new();
        // Get the pointer to where the value should be written to within the wrapper struct.
        let wrapper_ptr = wrapper.get_ptr(byte_count.get_value());
        // Copy the `byte_count` bytes from `ptr` into `wrapper_ptr`.
        ptr.copy_bytes_to(wrapper_ptr, byte_count.get_value());

        match byte_count {
            TypeBytes::U64 => WrapperType::U64(wrapper.value),
            TypeBytes::U32 => WrapperType::U32(u32::try_from(wrapper.value).unwrap()),
            TypeBytes::U16 => WrapperType::U16(u16::try_from(wrapper.value).unwrap()),
        }
    }
}
