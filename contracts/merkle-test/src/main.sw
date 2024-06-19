contract;

mod merkle_test_abi;

use merkle::*;
use merkle_test_abi::*;

storage {
    tree: StorageMerkleTree = StorageMerkleTree {},
}

impl TestStorageMerkleTree for Contract {
    #[storage(read, write)]
    fn insert(leaf: b256) {
        storage.tree.insert(leaf);
    }

    #[storage(read)]
    fn root() -> b256 {
        storage.tree.root()
    }

    #[storage(read)]
    fn get_count() -> u64 {
        storage.tree.get_count()
    }

    fn branch_root(leaf: b256, branch: [b256; 32], index: u64) -> b256 {
        StorageMerkleTree::branch_root(leaf, branch, index)
    }
}

#[test]
fn test_success() {
    let test_contract = abi(TestStorageMerkleTree, CONTRACT_ID);
    let result = test_contract.get_count();

    assert_eq(result, 0);
}
