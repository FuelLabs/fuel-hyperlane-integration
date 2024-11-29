use fuels::{
    prelude::*,
    types::{Bits256, ContractId},
};

// Load abi from json
abigen!(Contract(
    name = "MerkeRootMultisigIsm",
    abi = "contracts/ism/multisig/merkle-root-multisig-ism/out/debug/merkle-root-multisig-ism-abi.json"
),
Contract(
    name = "MerkleTest",
    abi = "contracts/test/merkle-test/out/debug/merkle-test-abi.json"
)
);

async fn get_contract_instance() -> (MerkeRootMultisigIsm<WalletUnlocked>, ContractId) {
    // Launch a local network and deploy the contract
    let mut wallets = launch_custom_provider_and_get_wallets(
        WalletsConfig::new(
            Some(1),             /* Single wallet */
            Some(1),             /* Single coin (UTXO) */
            Some(1_000_000_000), /* Amount per coin */
        ),
        None,
        None,
    )
    .await
    .unwrap();
    let wallet = wallets.pop().unwrap();

    let merkle_root_multisig_id = Contract::load_from(
        "./out/debug/merkle-root-multisig-ism.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let merkle_root_multisig = MerkeRootMultisigIsm::new(merkle_root_multisig_id.clone(), wallet);

    (merkle_root_multisig, merkle_root_multisig_id.into())
}

#[tokio::test]
async fn module_type() {
    let (ism, _) = get_contract_instance().await;

    let module_type = ism.methods().module_type().call().await.unwrap().value;

    assert_eq!(module_type, ModuleType::MERKLE_ROOT_MULTISIG);
}

#[tokio::test]
async fn getters_and_setters() {
    let (ism, _) = get_contract_instance().await;

    let message = Bytes(vec![]);

    let (validators, threshold) = ism
        .methods()
        .validators_and_threshold(message.clone())
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(validators, vec![]);
    assert_eq!(threshold, 0);

    ism.methods().set_threshold(1).call().await.unwrap();
    ism.methods()
        .enroll_validator(Bits256::zeroed().into())
        .call()
        .await
        .unwrap();

    let (validators, threshold) = ism
        .methods()
        .validators_and_threshold(message)
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(validators, vec![Bits256::zeroed().into()]);
    assert_eq!(threshold, 1);
}
