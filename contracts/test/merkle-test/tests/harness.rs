use fuels::{prelude::*, types::Bits256};
use sha3::{Digest, Keccak256};
use test_utils::{get_merkle_test_cases, to_eip_191_payload};

// Load abi from json
abigen!(Contract(
    name = "TestStorageMerkleTree",
    abi = "contracts/test/merkle-test/out/debug/merkle-test-abi.json"
));

async fn get_contract_instance() -> (TestStorageMerkleTree<WalletUnlocked>, ContractId) {
    // Launch a local network and deploy the contract
    let wallets = launch_custom_provider_and_get_wallets(
        WalletsConfig::new(
            Some(1),             /* Single wallet */
            Some(1),             /* Single coin (UTXO) */
            Some(1_000_000_000), /* Amount per coin */
        ),
        None,
        None,
    )
    .await;
    let wallet = wallets.unwrap().pop().unwrap();

    let merkle_id =
        Contract::load_from("./out/debug/merkle-test.bin", LoadConfiguration::default())
            .unwrap()
            .deploy(&wallet, TxPolicies::default())
            .await
            .unwrap();

    let instance = TestStorageMerkleTree::new(merkle_id.clone(), wallet);

    (instance, merkle_id.into())
}

#[tokio::test]
async fn satisfies_test_cases() {
    let test_cases = get_merkle_test_cases("./tests/test_cases.json");

    for case in test_cases.iter() {
        // Deploy a fresh contract for each test case
        let (test_merkle, _) = get_contract_instance().await;

        // Insert all the leaves
        for leaf in case.leaves.iter() {
            let leaf_hash = {
                let mut hasher = Keccak256::new();

                hasher.update(to_eip_191_payload(leaf));
                hasher.finalize()
            };

            // Insert the leaf hash
            test_merkle
                .methods()
                .insert(Bits256(leaf_hash.into()))
                .call()
                .await
                .unwrap();
        }

        // Ensure the count is correct
        let count = test_merkle
            .methods()
            .get_count()
            .simulate(Execution::StateReadOnly)
            .await
            .unwrap();
        assert_eq!(count.value, case.leaves.len() as u32);

        // Ensure it produces the correct root
        let root = test_merkle
            .methods()
            .root()
            .simulate(Execution::StateReadOnly)
            .await
            .unwrap();
        assert_eq!(root.value, case.expected_root);

        // Ensure it can verify each of the leaves' proofs
        for proof in case.proofs.iter() {
            let path: [Bits256; 32] = proof.path.clone().try_into().unwrap();
            let proof_root = test_merkle
                .methods()
                .branch_root(proof.leaf, path, proof.index as u64)
                .simulate(Execution::StateReadOnly)
                .await
                .unwrap();
            assert_eq!(proof_root.value, case.expected_root);
        }
    }
}
