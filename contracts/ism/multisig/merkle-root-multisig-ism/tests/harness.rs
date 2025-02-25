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

async fn get_contract_instance() -> (
    MerkeRootMultisigIsm<WalletUnlocked>,
    ContractId,
    WalletUnlocked,
) {
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

    let merkle_root_multisig =
        MerkeRootMultisigIsm::new(merkle_root_multisig_id.clone(), wallet.clone());

    (merkle_root_multisig, merkle_root_multisig_id.into(), wallet)
}

// ============ Module Type ============
#[tokio::test]
async fn module_type() {
    let (ism, _, _) = get_contract_instance().await;

    let module_type = ism.methods().module_type().call().await.unwrap().value;

    assert_eq!(module_type, ModuleType::MERKLE_ROOT_MULTISIG);
}

// ============ Initialization ============
#[tokio::test]
async fn initialization() {
    let (ism, _, wallet) = get_contract_instance().await;

    let message = Bytes(vec![]);

    let (validators, threshold) = ism
        .methods()
        .validators_and_threshold(message.clone())
        .call()
        .await
        .unwrap()
        .value;

    // Deployed with no threshold, cannot be used to verify
    assert_eq!(validators, vec![]);
    assert_eq!(threshold, 0);

    let wallet_bits = Bits256(wallet.address().hash().into());
    let configurables = MerkeRootMultisigIsmConfigurables::default()
        .with_THRESHOLD(1)
        .unwrap()
        .with_EXPECTED_INITIALIZER(wallet_bits)
        .unwrap();

    let id = Contract::load_from(
        "./out/debug/merkle-root-multisig-ism.bin",
        LoadConfiguration::default().with_configurables(configurables),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let ism = MerkeRootMultisigIsm::new(id, wallet.clone());

    let (validators, threshold) = ism
        .methods()
        .validators_and_threshold(message.clone())
        .call()
        .await
        .unwrap()
        .value;

    // Half initialized
    assert_eq!(validators, vec![]);
    assert_eq!(threshold, 1);

    // Initialize validators
    assert!(ism
        .methods()
        .initialize(vec![Bits256::zeroed().into()])
        .call()
        .await
        .is_ok());

    let (validators, threshold) = ism
        .methods()
        .validators_and_threshold(message)
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(validators, vec![Bits256::zeroed().into()]);
    assert_eq!(threshold, 1);

    // Can initialize only once
    assert!(ism
        .methods()
        .initialize(vec![Bits256::zeroed().into()])
        .call()
        .await
        .is_err());
}

// ============ Note ============
// Verification logic tests in the demo
// due to the lack of testing data from
// Hyperlane
