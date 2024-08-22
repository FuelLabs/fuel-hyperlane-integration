use fuels::{prelude::*, types::Bits256};
use sha3::{Digest, Keccak256};
use test_utils::{get_eip_191_prefix_for_hashes, get_merkle_test_cases, to_eip_191_payload};

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

    for (case_index, case) in test_cases.iter().enumerate() {
        // Deploy a fresh contract for each test case
        let (test_merkle, _) = get_contract_instance().await;

        // Insert all the leaves
        for (i, leaf) in case.leaves.iter().enumerate() {
            let leaf_hash = {
                let mut hasher = Keccak256::new();
                // println!("leaf len: {}", leaf.len());
                match case_index {
                    // TODO will never be reached, remove if you wont need to test Merkle Ism
                    1000 => {
                        // The first test case has hashes instead of strings as leaves
                        // {
                        //     "testName": "Actual Message Id leaves test",
                        //     "expectedRoot": "0x226a9ffecc5a45806a149c224681b5b987eaea6c7fafcd52bb53d246b46fd633",
                        //     "leaves": [
                        //       "0x87aef1eedec41cf03ce02f27f11c802c5931c52c8bd58d2aa194d2183f7c0d55",
                        //       "0x5c9aedf8714a9aefbc7f0386628c240ee2bf0e9c9c67821ea686bb9f472bf67d",
                        //       "0x5768ba4738b9bcece99c9b1c99d605f208e592b81999ef3836b7e4f39a41c9fa"
                        //     ],
                        //     "proofs": [
                        //       {
                        //         "leaf": "0xff52e7852bdfc1471d248d6b127efe3859169ce04d129c4782cca68f1578977d",
                        //         "index": 0,
                        //         "path": [
                        //           "0x0000000000000000000000000000000000000000000000000000000000000000",
                        //           "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5",
                        //           "0xb4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30",
                        //           "0x21ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85",
                        //           "0xe58769b32a1beaf1ea27375a44095a0d1fb664ce2dd358e7fcbfb78c26a19344",
                        //           "0x0eb01ebfc9ed27500cd4dfc979272d1f0913cc9f66540d7e8005811109e1cf2d",
                        //           "0x887c22bd8750d34016ac3c66b5ff102dacdd73f6b014e710b51e8022af9a1968",
                        //           "0xffd70157e48063fc33c97a050f7f640233bf646cc98d9524c6b92bcf3ab56f83",
                        //           "0x9867cc5f7f196b93bae1e27e6320742445d290f2263827498b54fec539f756af",
                        //           "0xcefad4e508c098b9a7e1d8feb19955fb02ba9675585078710969d3440f5054e0",
                        //           "0xf9dc3e7fe016e050eff260334f18a5d4fe391d82092319f5964f2e2eb7c1c3a5",
                        //           "0xf8b13a49e282f609c317a833fb8d976d11517c571d1221a265d25af778ecf892",
                        //           "0x3490c6ceeb450aecdc82e28293031d10c7d73bf85e57bf041a97360aa2c5d99c",
                        //           "0xc1df82d9c4b87413eae2ef048f94b4d3554cea73d92b0f7af96e0271c691e2bb",
                        //           "0x5c67add7c6caf302256adedf7ab114da0acfe870d449a3a489f781d659e8becc",
                        //           "0xda7bce9f4e8618b6bd2f4132ce798cdc7a60e7e1460a7299e3c6342a579626d2",
                        //           "0x2733e50f526ec2fa19a22b31e8ed50f23cd1fdf94c9154ed3a7609a2f1ff981f",
                        //           "0xe1d3b5c807b281e4683cc6d6315cf95b9ade8641defcb32372f1c126e398ef7a",
                        //           "0x5a2dce0a8a7f68bb74560f8f71837c2c2ebbcbf7fffb42ae1896f13f7c7479a0",
                        //           "0xb46a28b6f55540f89444f63de0378e3d121be09e06cc9ded1c20e65876d36aa0",
                        //           "0xc65e9645644786b620e2dd2ad648ddfcbf4a7e5b1a3a4ecfe7f64667a3f0b7e2",
                        //           "0xf4418588ed35a2458cffeb39b93d26f18d2ab13bdce6aee58e7b99359ec2dfd9",
                        //           "0x5a9c16dc00d6ef18b7933a6f8dc65ccb55667138776f7dea101070dc8796e377",
                        //           "0x4df84f40ae0c8229d0d6069e5c8f39a7c299677a09d367fc7b05e3bc380ee652",
                        //           "0xcdc72595f74c7b1043d0e1ffbab734648c838dfb0527d971b602bc216c9619ef",
                        //           "0x0abf5ac974a1ed57f4050aa510dd9c74f508277b39d7973bb2dfccc5eeb0618d",
                        //           "0xb8cd74046ff337f0a7bf2c8e03e10f642c1886798d71806ab1e888d9e5ee87d0",
                        //           "0x838c5655cb21c6cb83313b5a631175dff4963772cce9108188b34ac87c81c41e",
                        //           "0x662ee4dd2dd7b2bc707961b1e646c4047669dcb6584f0d8d770daf5d7e7deb2e",
                        //           "0x388ab20e2573d171a88108e79d820e98f26c0b84aa8b2f4aa4968dbb818ea322",
                        //           "0x93237c50ba75ee485f4c22adf2f741400bdf8d6a9cc7df7ecae576221665d735",
                        //           "0x8448818bb4ae4562849e949e17ac16e0be16688e156b5cf15e098c627c0056a9"
                        //         ]
                        //       },
                        //       {
                        //         "leaf": "0x8328ce8e2d3532720ea1d2fec91de5f5541ba1e64c44d4a3dc21d9beff20ea58",
                        //         "index": 1,
                        //         "path": [
                        //           "0x05020eb4f4573ee8af05b50f4b87bf48b448c02fe9842eeae9975b5027b5ab30",
                        //           "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5",
                        //           "0xb4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30",
                        //           "0x21ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85",
                        //           "0xe58769b32a1beaf1ea27375a44095a0d1fb664ce2dd358e7fcbfb78c26a19344",
                        //           "0x0eb01ebfc9ed27500cd4dfc979272d1f0913cc9f66540d7e8005811109e1cf2d",
                        //           "0x887c22bd8750d34016ac3c66b5ff102dacdd73f6b014e710b51e8022af9a1968",
                        //           "0xffd70157e48063fc33c97a050f7f640233bf646cc98d9524c6b92bcf3ab56f83",
                        //           "0x9867cc5f7f196b93bae1e27e6320742445d290f2263827498b54fec539f756af",
                        //           "0xcefad4e508c098b9a7e1d8feb19955fb02ba9675585078710969d3440f5054e0",
                        //           "0xf9dc3e7fe016e050eff260334f18a5d4fe391d82092319f5964f2e2eb7c1c3a5",
                        //           "0xf8b13a49e282f609c317a833fb8d976d11517c571d1221a265d25af778ecf892",
                        //           "0x3490c6ceeb450aecdc82e28293031d10c7d73bf85e57bf041a97360aa2c5d99c",
                        //           "0xc1df82d9c4b87413eae2ef048f94b4d3554cea73d92b0f7af96e0271c691e2bb",
                        //           "0x5c67add7c6caf302256adedf7ab114da0acfe870d449a3a489f781d659e8becc",
                        //           "0xda7bce9f4e8618b6bd2f4132ce798cdc7a60e7e1460a7299e3c6342a579626d2",
                        //           "0x2733e50f526ec2fa19a22b31e8ed50f23cd1fdf94c9154ed3a7609a2f1ff981f",
                        //           "0xe1d3b5c807b281e4683cc6d6315cf95b9ade8641defcb32372f1c126e398ef7a",
                        //           "0x5a2dce0a8a7f68bb74560f8f71837c2c2ebbcbf7fffb42ae1896f13f7c7479a0",
                        //           "0xb46a28b6f55540f89444f63de0378e3d121be09e06cc9ded1c20e65876d36aa0",
                        //           "0xc65e9645644786b620e2dd2ad648ddfcbf4a7e5b1a3a4ecfe7f64667a3f0b7e2",
                        //           "0xf4418588ed35a2458cffeb39b93d26f18d2ab13bdce6aee58e7b99359ec2dfd9",
                        //           "0x5a9c16dc00d6ef18b7933a6f8dc65ccb55667138776f7dea101070dc8796e377",
                        //           "0x4df84f40ae0c8229d0d6069e5c8f39a7c299677a09d367fc7b05e3bc380ee652",
                        //           "0xcdc72595f74c7b1043d0e1ffbab734648c838dfb0527d971b602bc216c9619ef",
                        //           "0x0abf5ac974a1ed57f4050aa510dd9c74f508277b39d7973bb2dfccc5eeb0618d",
                        //           "0xb8cd74046ff337f0a7bf2c8e03e10f642c1886798d71806ab1e888d9e5ee87d0",
                        //           "0x838c5655cb21c6cb83313b5a631175dff4963772cce9108188b34ac87c81c41e",
                        //           "0x662ee4dd2dd7b2bc707961b1e646c4047669dcb6584f0d8d770daf5d7e7deb2e",
                        //           "0x388ab20e2573d171a88108e79d820e98f26c0b84aa8b2f4aa4968dbb818ea322",
                        //           "0x93237c50ba75ee485f4c22adf2f741400bdf8d6a9cc7df7ecae576221665d735",
                        //           "0x8448818bb4ae4562849e949e17ac16e0be16688e156b5cf15e098c627c0056a9"
                        //         ]
                        //       },
                        //       {
                        //         "leaf": "0x05020eb4f4573ee8af05b50f4b87bf48b448c02fe9842eeae9975b5027b5ab30",
                        //         "index": 2,
                        //         "path": [
                        //           "0x0000000000000000000000000000000000000000000000000000000000000000",
                        //           "0x61b43cdc7d79b905a2eae731184f685251d99f55523396ab534dc35e3a861319",
                        //           "0xb4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30",
                        //           "0x21ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85",
                        //           "0xe58769b32a1beaf1ea27375a44095a0d1fb664ce2dd358e7fcbfb78c26a19344",
                        //           "0x0eb01ebfc9ed27500cd4dfc979272d1f0913cc9f66540d7e8005811109e1cf2d",
                        //           "0x887c22bd8750d34016ac3c66b5ff102dacdd73f6b014e710b51e8022af9a1968",
                        //           "0xffd70157e48063fc33c97a050f7f640233bf646cc98d9524c6b92bcf3ab56f83",
                        //           "0x9867cc5f7f196b93bae1e27e6320742445d290f2263827498b54fec539f756af",
                        //           "0xcefad4e508c098b9a7e1d8feb19955fb02ba9675585078710969d3440f5054e0",
                        //           "0xf9dc3e7fe016e050eff260334f18a5d4fe391d82092319f5964f2e2eb7c1c3a5",
                        //           "0xf8b13a49e282f609c317a833fb8d976d11517c571d1221a265d25af778ecf892",
                        //           "0x3490c6ceeb450aecdc82e28293031d10c7d73bf85e57bf041a97360aa2c5d99c",
                        //           "0xc1df82d9c4b87413eae2ef048f94b4d3554cea73d92b0f7af96e0271c691e2bb",
                        //           "0x5c67add7c6caf302256adedf7ab114da0acfe870d449a3a489f781d659e8becc",
                        //           "0xda7bce9f4e8618b6bd2f4132ce798cdc7a60e7e1460a7299e3c6342a579626d2",
                        //           "0x2733e50f526ec2fa19a22b31e8ed50f23cd1fdf94c9154ed3a7609a2f1ff981f",
                        //           "0xe1d3b5c807b281e4683cc6d6315cf95b9ade8641defcb32372f1c126e398ef7a",
                        //           "0x5a2dce0a8a7f68bb74560f8f71837c2c2ebbcbf7fffb42ae1896f13f7c7479a0",
                        //           "0xb46a28b6f55540f89444f63de0378e3d121be09e06cc9ded1c20e65876d36aa0",
                        //           "0xc65e9645644786b620e2dd2ad648ddfcbf4a7e5b1a3a4ecfe7f64667a3f0b7e2",
                        //           "0xf4418588ed35a2458cffeb39b93d26f18d2ab13bdce6aee58e7b99359ec2dfd9",
                        //           "0x5a9c16dc00d6ef18b7933a6f8dc65ccb55667138776f7dea101070dc8796e377",
                        //           "0x4df84f40ae0c8229d0d6069e5c8f39a7c299677a09d367fc7b05e3bc380ee652",
                        //           "0xcdc72595f74c7b1043d0e1ffbab734648c838dfb0527d971b602bc216c9619ef",
                        //           "0x0abf5ac974a1ed57f4050aa510dd9c74f508277b39d7973bb2dfccc5eeb0618d",
                        //           "0xb8cd74046ff337f0a7bf2c8e03e10f642c1886798d71806ab1e888d9e5ee87d0",
                        //           "0x838c5655cb21c6cb83313b5a631175dff4963772cce9108188b34ac87c81c41e",
                        //           "0x662ee4dd2dd7b2bc707961b1e646c4047669dcb6584f0d8d770daf5d7e7deb2e",
                        //           "0x388ab20e2573d171a88108e79d820e98f26c0b84aa8b2f4aa4968dbb818ea322",
                        //           "0x93237c50ba75ee485f4c22adf2f741400bdf8d6a9cc7df7ecae576221665d735",
                        //           "0x8448818bb4ae4562849e949e17ac16e0be16688e156b5cf15e098c627c0056a9"
                        //         ]
                        //       }
                        //     ]
                        //   },
                        // remove the prefix and decode the hex string
                        let formatted_leaf = hex::decode(leaf.split_at(2).1).unwrap();
                        let prefix = hex::decode(get_eip_191_prefix_for_hashes()).unwrap();
                        hasher.update(prefix); // Pass the byte array to hasher.update()
                        hasher.update(formatted_leaf); // Pass the byte array to hasher.update()

                        // hasher.update(get_eip_191_prefix_for_hashes());
                        // hasher.update(0x19457468657265756d205369676e6564204d6573736167653a0a333287aef1eedec41cf03ce02f27f11c802c5931c52c8bd58d2aa194d2183f7c0d55);
                    }
                    _ => hasher.update(to_eip_191_payload(leaf)),
                }
                hasher.finalize()
            };

            // XXX

            let expected_leaf_hash = case.proofs[i].leaf;
            assert_eq!(Bits256(leaf_hash.into()), expected_leaf_hash);

            // XXX

            // Insert the leaf hash
            test_merkle
                .methods()
                .insert(Bits256(leaf_hash.into()))
                .call()
                .await
                .unwrap();
        }

        // Ensure the count is correct
        let count = test_merkle.methods().get_count().simulate().await.unwrap();
        assert_eq!(count.value, case.leaves.len() as u32);

        // Ensure it produces the correct root
        let root = test_merkle.methods().root().simulate().await.unwrap();
        assert_eq!(root.value, case.expected_root);

        // Ensure it can verify each of the leaves' proofs
        for proof in case.proofs.iter() {
            let path: [Bits256; 32] = proof.path.clone().try_into().unwrap();
            let proof_root = test_merkle
                .methods()
                .branch_root(proof.leaf, path, proof.index as u64)
                .simulate()
                .await
                .unwrap();
            assert_eq!(proof_root.value, case.expected_root);
        }
    }
}
