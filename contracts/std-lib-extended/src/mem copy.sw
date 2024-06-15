library;

use std::convert::TryInto;
use std::primitive_conversions::u64::*;
// enum WrapperType {
//     U64: u64,
//     U32: u32,
//     U16: u16,
//     U8: u8,
//     Bool: bool,
// }

///
/// The number of bytes in a 64-bit Fuel VM word.
const BYTES_PER_WORD: u64 = 8u64;
///
/// Wraps a copy type.
///
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
    fn with_value<T>(value: T) -> Option<Self>
    where
        T: TryInto<u64>,
    {
        match value.try_into() {
            Some(v) => Some(Self { value: v }),
            None(_) => None,
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
    //     fn value<T>(self) -> T {
    //         self.value

    // }

    fn value<T>(self) -> T
    where
        T: From<u64>,
    {
        T::from(self.value)
    }
    // fn value(self) -> u64 {
    //     self.value
    // }

    // fn value_u32(self) -> u32 {
    //     self.value.try_as_u32().unwrap()
    // }

    // fn value_u16(self) -> u16 {
    //     self.value.try_as_u16().unwrap()
    // }

    // fn value_u8(self) -> u8 {
    //     self.value.try_as_u8().unwrap()
    // }
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
    pub fn ptr_to_value<T>(
        value: T,
        byte_count: u64,
    ) -> raw_ptr
    where
        T: From<u64>,
        T: TryInto<u64>,
    {
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
    pub fn value_from_ptr<T>(ptr: raw_ptr, byte_count: u64) -> T
    where
        T: From<u64>,
    {
        // Create a wrapper struct with a zero value.
        let wrapper = CopyTypeWrapper::new();
        // Get the pointer to where the value should be written to within the wrapper struct.
        let wrapper_ptr = wrapper.get_ptr(byte_count);
        // Copy the `byte_count` bytes from `ptr` into `wrapper_ptr`.
        ptr.copy_bytes_to(wrapper_ptr, byte_count);
        wrapper.value()
    }
}
