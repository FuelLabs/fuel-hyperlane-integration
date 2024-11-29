use fuels::{
    prelude::*,
    types::{Bits256, Identity},
};
use hyperlane_core::{HyperlaneMessage, RawHyperlaneMessage, H256};
use rand::{thread_rng, Rng};

// Load abi from json
abigen!(Contract(
    name = "DefaultFallbackRoutingIsm",
    abi = "contracts/ism/routing/default-fallback-domain-routing-ism/out/debug/default-fallback-domain-routing-ism-abi.json"
),
Contract(
    name = "TestIsm",
    abi = "contracts/test/ism-test/out/debug/ism-test-abi.json"
),
Contract(
    name = "Mailbox",
    abi = "contracts/mailbox/out/debug/mailbox-abi.json"
));

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

fn generate_test_message() -> RawHyperlaneMessage {
    RawHyperlaneMessage::from(&HyperlaneMessage {
        version: 3,
        nonce: 0,
        origin: 4,
        sender: H256::zero(),
        destination: 4,
        recipient: H256::zero(),
        body: vec![],
    })
}

async fn get_contract_instance() -> (
    DefaultFallbackRoutingIsm<WalletUnlocked>,
    Mailbox<WalletUnlocked>,
    Bits256,
    Bits256,
    TestIsm<WalletUnlocked>,
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

    let fallback_routing_ism_id = Contract::load_from(
        "./out/debug/default-fallback-domain-routing-ism.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let mailbox_id = Contract::load_from(
        "../../../mailbox/out/debug/mailbox.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let mailbox = Mailbox::new(mailbox_id, wallet.clone());
    let fallback_routing_ism =
        DefaultFallbackRoutingIsm::new(fallback_routing_ism_id.clone(), wallet.clone());
    let test_ism = deploy_test_ism(&wallet).await;
    let wallet_address = Bits256(Address::from(wallet.address()).into());

    // Setup default mailbox ISM
    let test_ism_id = Bits256(ContractId::from(test_ism.id()).into());
    mailbox
        .methods()
        .initialize(wallet_address, test_ism_id, test_ism_id, test_ism_id)
        .call()
        .await
        .unwrap();

    (
        fallback_routing_ism,
        mailbox,
        wallet_address,
        test_ism_id,
        test_ism,
    )
}

// -----------------------------------------------------------------------------------------------
// This contract is the same as the Domain Routing ISM, but has the functionality to
// fall back to the default ISM set on the mailbox if no domain is found.

// Since the main functionality is the same, we can only test the module fallback functionality
// -----------------------------------------------------------------------------------------------

#[tokio::test]
async fn initialize_with_mailbox() {
    let (fallback_routing_ism, mailbox, wallet_address, _, _) = get_contract_instance().await;

    let mailbox_address = Bits256(ContractId::from(mailbox.id()).into());
    fallback_routing_ism
        .methods()
        .initialize(wallet_address, mailbox_address)
        .call()
        .await
        .unwrap();

    let owner_res = fallback_routing_ism
        .methods()
        .owner()
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(
        owner_res,
        State::Initialized(Identity::Address(Address::from(wallet_address.0)))
    );
}

#[tokio::test]
async fn route_fallback() {
    let (fallback_routing_ism, mailbox, wallet_address, test_ism_id, _) =
        get_contract_instance().await;

    let mailbox_address = Bits256(ContractId::from(mailbox.id()).into());
    fallback_routing_ism
        .methods()
        .initialize(wallet_address, mailbox_address)
        .call()
        .await
        .unwrap();

    let message = generate_test_message();

    let fallback_routed_ism = fallback_routing_ism
        .methods()
        .route(Bytes(message))
        .determine_missing_contracts(Some(3))
        .await
        .unwrap()
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(fallback_routed_ism, test_ism_id);
}

#[tokio::test]
async fn verify_fallback_success() {
    let (fallback_routing_ism, mailbox, wallet_address, _, _) = get_contract_instance().await;

    let mailbox_address = Bits256(ContractId::from(mailbox.id()).into());
    fallback_routing_ism
        .methods()
        .initialize(wallet_address, mailbox_address)
        .call()
        .await
        .unwrap();

    let message = generate_test_message();
    let metadata = Bytes(vec![]);

    let success = fallback_routing_ism
        .methods()
        .verify(metadata, Bytes(message))
        .determine_missing_contracts(Some(3))
        .await
        .unwrap()
        .call()
        .await
        .unwrap()
        .value;

    assert!(success);
}

#[tokio::test]
async fn verify_fallback_fail() {
    let (fallback_routing_ism, mailbox, wallet_address, _, test_ism) =
        get_contract_instance().await;

    let mailbox_address = Bits256(ContractId::from(mailbox.id()).into());
    fallback_routing_ism
        .methods()
        .initialize(wallet_address, mailbox_address)
        .call()
        .await
        .unwrap();

    let message = generate_test_message();
    let metadata = Bytes(vec![]);

    test_ism.methods().set_accept(false).call().await.unwrap();

    let success = fallback_routing_ism
        .methods()
        .verify(metadata, Bytes(message))
        .determine_missing_contracts(Some(3))
        .await
        .unwrap()
        .call()
        .await
        .unwrap()
        .value;

    assert!(!success);
}
