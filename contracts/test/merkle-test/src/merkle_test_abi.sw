library;

// A contract to test the StorageMerkleTree.
abi TestStorageMerkleTree {
    #[storage(read, write)]
    fn insert(leaf: b256);

    #[storage(read)]
    fn root() -> b256;

    #[storage(read)]
    fn get_count() -> u32;

    fn branch_root(leaf: b256, branch: [b256; 32], index: u64) -> b256;
}
