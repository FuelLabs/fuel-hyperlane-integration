use fuels::{
    prelude::*,
    types::{errors::transaction::Reason, Bits256, ContractId},
};
use futures::future::join_all;
use rand::{thread_rng, Rng};

// Load abi from json
abigen!(
    Contract(
        name = "AggregationIsm",
        abi = "contracts/ism/aggregation-ism/out/debug/aggregation-ism-abi.json"
    ),
    Contract(
        name = "TestIsm",
        abi = "contracts/test/ism-test/out/debug/ism-test-abi.json"
    )
);

fn get_deployment_config() -> LoadConfiguration {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    let salt = Salt::new(bytes);

    LoadConfiguration::default().with_salt(salt)
}

async fn deploy_test_ism(wallet: &WalletUnlocked) -> TestIsm<WalletUnlocked> {
    let test_ism_id = Contract::load_from(
        "../../test/ism-test/out/debug/ism-test.bin",
        get_deployment_config(),
    )
    .unwrap()
    .deploy(wallet, TxPolicies::default())
    .await
    .unwrap();

    TestIsm::new(test_ism_id, wallet.clone())
}

/// Generates mock metadata bytes for 3 ISMs
///
/// Used since every ISM requires metadata to be passed in when using an aggregation ISM
fn generate_test_bytes() -> Bytes {
    let mut bytes = Vec::new();

    // Metadata ranges
    let ranges = [
        (8u32, 16u32),  // Index 0
        (16u32, 24u32), // Index 1
        (24u32, 32u32), // Index 2
    ];

    for &(start, end) in &ranges {
        bytes.extend_from_slice(&start.to_be_bytes());
        bytes.extend_from_slice(&end.to_be_bytes());
    }

    // Metadata content (24 bytes of zeros)
    bytes.extend_from_slice(&[0u8; 24]);

    Bytes(bytes)
}

async fn get_contract_instance() -> (AggregationIsm<WalletUnlocked>, Vec<TestIsm<WalletUnlocked>>) {
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

    let aggregation_ism_id = Contract::load_from(
        "./out/debug/aggregation-ism.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let test_isms = vec![
        deploy_test_ism(&wallet).await,
        deploy_test_ism(&wallet).await,
        deploy_test_ism(&wallet).await,
    ];

    let aggregation_ism = AggregationIsm::new(aggregation_ism_id.clone(), wallet.clone());
    let wallet_address = Bits256(Address::from(wallet.address()).into());

    aggregation_ism
        .methods()
        .initialize(wallet_address)
        .call()
        .await
        .unwrap();

    (aggregation_ism, test_isms)
}

#[tokio::test]
async fn module_type() {
    let (ism, _) = get_contract_instance().await;
    let module_type = ism.methods().module_type().call().await.unwrap().value;
    assert_eq!(module_type, ModuleType::AGGREGATION);
}

#[tokio::test]
async fn aggregation_getters_and_setters() {
    let (ism, _) = get_contract_instance().await;

    let bytes = Bytes(vec![0u8]);

    let (modules, threshold) = ism
        .methods()
        .modules_and_threshold(bytes.clone())
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(modules, vec![]);
    assert_eq!(threshold, 0);

    ism.methods().set_threshold(5).call().await.unwrap();
    ism.methods()
        .enroll_module(ContractId::zeroed())
        .call()
        .await
        .unwrap();
    ism.methods()
        .enroll_module(ContractId::zeroed())
        .call()
        .await
        .unwrap();

    let (modules, threshold) = ism
        .methods()
        .modules_and_threshold(bytes)
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(modules.len(), 2);
    assert_eq!(threshold, 5);
}

#[tokio::test]
async fn all_isms_accept() {
    let (ism, test_isms) = get_contract_instance().await;

    let bytes = generate_test_bytes();

    let (modules, threshold) = ism
        .methods()
        .modules_and_threshold(bytes.clone())
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(modules, vec![]);
    assert_eq!(threshold, 0);

    ism.methods().set_threshold(3).call().await.unwrap();

    let mut futures = vec![];
    for test_ism in test_isms {
        futures.push(test_ism.methods().set_accept(true).call());

        ism.methods()
            .enroll_module(test_ism.contract_id())
            .call()
            .await
            .unwrap();
    }
    let _ = join_all(futures).await;
    let (modules, _) = ism
        .methods()
        .modules_and_threshold(bytes.clone())
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(modules.len(), 3);

    let result = ism
        .methods()
        .verify(bytes.clone(), bytes)
        .determine_missing_contracts(Some(3))
        .await
        .unwrap()
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(result, true);
}

#[tokio::test]
async fn invalid_metadata() {
    let (ism, test_isms) = get_contract_instance().await;

    let bytes = Bytes(Vec::new());

    let (modules, threshold) = ism
        .methods()
        .modules_and_threshold(bytes.clone())
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(modules, vec![]);
    assert_eq!(threshold, 0);

    ism.methods().set_threshold(3).call().await.unwrap();

    let mut futures = vec![];
    for test_ism in test_isms {
        futures.push(test_ism.methods().set_accept(true).call());

        ism.methods()
            .enroll_module(test_ism.contract_id())
            .call()
            .await
            .unwrap();
    }
    let _ = join_all(futures).await;
    let (modules, _) = ism
        .methods()
        .modules_and_threshold(bytes.clone())
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(modules.len(), 3);

    let error = ism
        .methods()
        .verify(bytes.clone(), bytes)
        .determine_missing_contracts(Some(3))
        .await
        .unwrap_err();

    if let Error::Transaction(Reason::Reverted { reason, .. }) = error {
        assert_eq!(reason, "DidNotMeetThreshold");
    } else {
        panic!("Unexpected error");
    }
}

#[tokio::test]
async fn one_ism_rejects() {
    let (ism, test_isms) = get_contract_instance().await;

    let bytes = generate_test_bytes();

    let (modules, threshold) = ism
        .methods()
        .modules_and_threshold(bytes.clone())
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(modules, vec![]);
    assert_eq!(threshold, 0);

    ism.methods().set_threshold(3).call().await.unwrap();

    let mut rejected_ism = false;
    for test_ism in test_isms {
        match rejected_ism {
            false => {
                rejected_ism = true;
                test_ism.methods().set_accept(false).call().await.unwrap()
            }
            true => test_ism.methods().set_accept(true).call().await.unwrap(),
        };

        ism.methods()
            .enroll_module(test_ism.contract_id())
            .call()
            .await
            .unwrap();
    }

    let (modules, _) = ism
        .methods()
        .modules_and_threshold(bytes.clone())
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(modules.len(), 3);

    let error = ism
        .methods()
        .verify(bytes.clone(), bytes)
        .determine_missing_contracts(Some(3))
        .await
        .unwrap_err();

    if let Error::Transaction(Reason::Reverted { reason, .. }) = error {
        assert_eq!(reason, "DidNotMeetThreshold");
    } else {
        panic!("Unexpected error");
    }
}
