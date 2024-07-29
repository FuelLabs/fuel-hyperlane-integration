use rand::{thread_rng, Rng};
use std::str::FromStr;

use fuels::{
    crypto::SecretKey,
    prelude::*,
    types::{Bits256, ContractId, Salt},
};

// const LOCAL_NODE: &str = "127.0.0.1:4000";
const TESTNET_NODE: &str = "testnet.fuel.network"; // For testnet deployments use fuels 0.55.0 if the latest version of fuels does not work

abigen!(
    Contract(
        name = "Mailbox",
        abi = "contracts/mailbox/out/debug/mailbox-abi.json",
    ),
    Contract(
        name = "PostDispatch",
        abi = "contracts/mocks/mock-post-dispatch/out/debug/mock-post-dispatch-abi.json",
    )
);

#[tokio::main]
async fn main() {
    // Wallet Initialization

    let provider = Provider::connect(TESTNET_NODE).await.unwrap();
    let private_key =
        SecretKey::from_str("0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711")
            .unwrap();
    let wallet = WalletUnlocked::new_from_private_key(private_key, Some(provider));
    println!("Deployer: {}", wallet.address());

    // Mailbox Contract Deployment

    let binary_filepath = "../contracts/mailbox/out/debug/mailbox.bin";

    let config = get_deployment_config();
    let contract = Contract::load_from(binary_filepath, config.clone()).unwrap();

    let mailbox_contract_id = contract
        .deploy(&wallet, TxPolicies::default())
        .await
        .unwrap();

    println!("Mailbox deployed with ID: {}", mailbox_contract_id);

    // Post Dispatch Mock Deployment

    let binary_filepath = "../contracts/mocks/mock-post-dispatch/out/debug/mock-post-dispatch.bin";
    let contract = Contract::load_from(binary_filepath, config.clone()).unwrap();
    let post_dispatch_contract_id = contract
        .deploy(&wallet, TxPolicies::default())
        .await
        .unwrap();

    println!(
        "Post Dispatch Contract deployed with ID: {}",
        post_dispatch_contract_id
    );

    // Recipient deplyment

    let recipient_id = Contract::load_from(
        "../contracts/test/msg-recipient-test/out/debug/msg-recipient-test.bin",
        config,
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    println!("Recipient deployed with ID: {}", recipient_id);

    // Instantiate Contracts

    let post_dispatch = PostDispatch::new(post_dispatch_contract_id.clone(), wallet.clone());
    let mailbox = Mailbox::new(mailbox_contract_id, wallet.clone());

    // Initalize Mailbox Contract

    let wallet_address = Bits256(Address::from(wallet.address()).into());
    let post_dispatch_address = Bits256(ContractId::from(post_dispatch.id()).into());

    let init_res = mailbox
        .methods()
        .initialize(
            wallet_address,
            post_dispatch_address,
            post_dispatch_address,
            post_dispatch_address,
        )
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize Mailbox.");
    println!("Mailbox initialized.");
}

fn get_deployment_config() -> LoadConfiguration {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    let salt = Salt::new(bytes);

    LoadConfiguration::default().with_salt(salt)
}
