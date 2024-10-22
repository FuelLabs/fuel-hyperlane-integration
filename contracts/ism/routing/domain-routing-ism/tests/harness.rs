use fuels::{
    prelude::*,
    types::{errors::transaction::Reason, Bits256},
};
use hyperlane_core::{HyperlaneMessage, RawHyperlaneMessage, H256};
use rand::{thread_rng, Rng};

// Load abi from json
abigen!(
    Contract(
        name = "DomainRoutingIsm",
        abi = "contracts/ism/routing/domain-routing-ism/out/debug/domain-routing-ism-abi.json"
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
        "../../../test/ism-test/out/debug/ism-test.bin",
        get_deployment_config(),
    )
    .unwrap()
    .deploy(wallet, TxPolicies::default())
    .await
    .unwrap();

    TestIsm::new(test_ism_id, wallet.clone())
}

fn generate_hyperlane_messages() -> Vec<RawHyperlaneMessage> {
    (1..3)
        .map(|domain| {
            RawHyperlaneMessage::from(&HyperlaneMessage {
                version: 3,
                nonce: 0,
                origin: domain,
                sender: H256::zero(),
                destination: domain,
                recipient: H256::zero(),
                body: vec![],
            })
        })
        .collect()
}

async fn get_contract_instance() -> (
    DomainRoutingIsm<WalletUnlocked>,
    Vec<TestIsm<WalletUnlocked>>,
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

    let id = Contract::load_from(
        "./out/debug/domain-routing-ism.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let domain_routing_ism = DomainRoutingIsm::new(id.clone(), wallet.clone());

    let isms = vec![
        deploy_test_ism(&wallet).await,
        deploy_test_ism(&wallet).await,
        deploy_test_ism(&wallet).await,
    ];

    let wallet_address = Bits256(Address::from(wallet.address()).into());

    domain_routing_ism
        .methods()
        .initialize(wallet_address)
        .call()
        .await
        .unwrap();

    (domain_routing_ism, isms)
}

#[tokio::test]
async fn module_type() {
    let (ism, _) = get_contract_instance().await;
    let module_type = ism.methods().module_type().call().await.unwrap().value;
    assert_eq!(module_type, ModuleType::ROUTING);
}

#[tokio::test]
async fn getters_and_setters() {
    let (domain_routing_ism, test_isms) = get_contract_instance().await;

    let domains = domain_routing_ism
        .methods()
        .domains()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(domains.len(), 0);

    let domain = 1;
    let domain_1_ism = domain_routing_ism
        .methods()
        .module(domain)
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(domain_1_ism, Bits256::zeroed());

    let test_ism = &test_isms[0];
    let test_ism_id = Bits256(ContractId::from(test_ism.id()).into());

    domain_routing_ism
        .methods()
        .set(domain, test_ism_id)
        .call()
        .await
        .unwrap();

    let domains = domain_routing_ism
        .methods()
        .domains()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0], domain);

    let domain_1_ism = domain_routing_ism
        .methods()
        .module(domain)
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(domain_1_ism, test_ism_id);

    domain_routing_ism
        .methods()
        .remove(domain)
        .call()
        .await
        .unwrap();

    let domains = domain_routing_ism
        .methods()
        .domains()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(domains.len(), 0);

    let domain_1_ism = domain_routing_ism
        .methods()
        .module(domain)
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(domain_1_ism, Bits256::zeroed());

    // set it and check again, do for all state chaning funcitons
}

#[tokio::test]
async fn routing() {
    let (domain_routing_ism, test_isms) = get_contract_instance().await;

    for (i, test_ism) in test_isms.iter().enumerate() {
        let test_ism_id = Bits256(ContractId::from(test_ism.id()).into());
        let domain = i as u32 + 1;

        domain_routing_ism
            .methods()
            .set(domain, test_ism_id)
            .call()
            .await
            .unwrap();
    }

    let messages = generate_hyperlane_messages();

    for (i, message) in messages.iter().enumerate() {
        let expected_ism = &test_isms[i];

        let routed_ism = domain_routing_ism
            .methods()
            .route(Bytes(message.clone()))
            .call()
            .await
            .unwrap()
            .value;

        assert_eq!(
            routed_ism,
            Bits256(ContractId::from(expected_ism.id()).into())
        );
    }
}

#[tokio::test]
async fn routing_not_set_domain() {
    let (domain_routing_ism, _) = get_contract_instance().await;

    let message = RawHyperlaneMessage::from(&HyperlaneMessage {
        version: 3,
        nonce: 0,
        origin: 4,
        sender: H256::zero(),
        destination: 4,
        recipient: H256::zero(),
        body: vec![],
    });

    let error = domain_routing_ism
        .methods()
        .route(Bytes(message))
        .call()
        .await
        .unwrap_err();

    if let Error::Transaction(Reason::Reverted { reason, .. }) = error {
        assert_eq!(reason, "DomainNotSet(4)");
    } else {
        panic!("Unexpected error");
    }
}

#[tokio::test]
async fn route_verify_success() {
    let (domain_routing_ism, test_isms) = get_contract_instance().await;

    for (i, test_ism) in test_isms.iter().enumerate() {
        let test_ism_id = Bits256(ContractId::from(test_ism.id()).into());
        let domain = i as u32 + 1;

        domain_routing_ism
            .methods()
            .set(domain, test_ism_id)
            .call()
            .await
            .unwrap();
    }

    let messages = generate_hyperlane_messages();

    for message in messages {
        let message = Bytes(message.clone());
        let metadata = Bytes(vec![]);

        let success = domain_routing_ism
            .methods()
            .verify(metadata, message)
            .determine_missing_contracts(Some(3))
            .await
            .unwrap()
            .call()
            .await
            .unwrap()
            .value;

        assert!(success);
    }
}

#[tokio::test]
async fn route_verify_fail() {
    let (domain_routing_ism, test_isms) = get_contract_instance().await;

    for (i, test_ism) in test_isms.iter().enumerate() {
        test_ism.methods().set_accept(false).call().await.unwrap();

        let test_ism_id = Bits256(ContractId::from(test_ism.id()).into());
        let domain = i as u32 + 1;

        domain_routing_ism
            .methods()
            .set(domain, test_ism_id)
            .call()
            .await
            .unwrap();
    }

    let messages = generate_hyperlane_messages();

    for message in messages {
        let message = Bytes(message.clone());
        let metadata = Bytes(vec![]);

        let success = domain_routing_ism
            .methods()
            .verify(metadata, message)
            .determine_missing_contracts(Some(3))
            .await
            .unwrap()
            .call()
            .await
            .unwrap()
            .value;

        assert!(!success);
    }
}

// Test that the domain routing ISM can route messages to the correct ISM
// use the `route` function to route messages to the correct ISM
// setup the test domain modules and test isms and should be prety straight forward
