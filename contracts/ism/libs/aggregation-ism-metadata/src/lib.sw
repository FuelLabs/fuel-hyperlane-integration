library;

use std::bytes::Bytes;
use std_lib_extended::bytes::*;

/// Format of metadata:
///
/// [????:????] Metadata start/end uint32 ranges, packed as uint64
/// [????:????] ISM metadata, packed encoding
///
const RANGE_SIZE: u8 = 4;

pub struct AggregationIsmMetadata {
    bytes: Bytes,
}

impl AggregationIsmMetadata {
    pub fn new(bytes: Bytes) -> Self {
        Self { bytes }
    }

    pub fn has_metadata(self, index: u8) -> bool {
        let (start, _) = self._metadata_range(index);
        start > 0
    }

    pub fn metadata_at(self, index: u8) -> Bytes {
        let (start, end) = self._metadata_range(index);
        self.bytes.clone().split_at(start.as_u64()).1.split_at(end.as_u64() - start.as_u64()).0
    }

    fn _metadata_range(self, index: u8) -> (u32, u32) {
        let bytes = self.bytes.clone();

        let start = index.as_u64() * RANGE_SIZE.as_u64() * 2;
        let mid = start + RANGE_SIZE.as_u64();

        if bytes.len() < mid + RANGE_SIZE.as_u64() {
            return (0, 0);
        }
        (bytes.read_u32(start), bytes.read_u32(mid))
    }
}
