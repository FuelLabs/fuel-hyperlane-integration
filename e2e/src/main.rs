use hyperlane_core::{HyperlaneMessage as HyperlaneAgentMessage, H256};

use rand::{thread_rng, Rng};
use std::str::FromStr;

use fuels::{
    crypto::SecretKey,
    prelude::*,
    types::{Bits256, Bytes, ContractId, Salt},
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
        abi = "contracts/mock-post-dispatch/out/debug/mock-post-dispatch-abi.json",
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

    println!("Contract deployed with ID: {}", mailbox_contract_id);

    // Post Dispatch Mock Deployment

    let binary_filepath = "../contracts/mock-post-dispatch/out/debug/mock-post-dispatch.bin";
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
        "../contracts/msg-recipient-test/out/debug/msg-recipient-test.bin",
        config,
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

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

    let paused = mailbox.methods().is_paused().call().await.unwrap();
    println!("Paused: {}", paused.value);

    // Example Dispatch

    let message = test_message(&mailbox, &recipient_id);
    let message_id = message.id();

    let metadata_str = "0x000000000000000000000010000000950000000000000000000000007222b8b24788a79b173a42b2efa2585ed5a76198d06677e4f9f9426baf25bb5869b727d9d762e7ad0e65a0b996c8c26bdec9b4bc000000154fc320ced73551ed55147775d01afd40aa0c487e1d03492285a023a0d2f7696311b4658361ffe3e917b871e8982e0a488921076222eb5805dcd54d628e0c82981c";
    let metadata = Bytes::from_hex_str(metadata_str).unwrap();
    let hook = ContractId::default();

    let dispatch_res = mailbox
        .methods()
        .dispatch(
            message.destination,
            h256_to_bits256(message.recipient),
            Bytes(message.clone().body),
            metadata,
            hook,
        )
        .with_contract_ids(&[post_dispatch_contract_id])
        .call()
        .await;

    if let Err(e) = dispatch_res {
        println!("Error: {}", e);
        return;
    }

    let res = dispatch_res.unwrap();

    let logs: LogResult = res.decode_logs();
    let succeeded = logs.filter_succeeded();
    for log in succeeded {
        println!("Log: {}", log);
    }

    let dispatch_events = res.decode_logs_with_type::<DispatchEvent>().unwrap();
    let dispatch_message: Vec<u8> = dispatch_events
        .first()
        .unwrap()
        .message
        .bytes
        .clone()
        .into();
    let decoded_message = HyperlaneAgentMessage::from(dispatch_message);
    println!("Decoded message id: {:?}", decoded_message.id());
    println!("Decoded message: {:?}", decoded_message);
    println!("Original message: {:?}", message);
    println!("\n\n");

    println!("message sender {:?}", h256_to_bits256(message.sender));
    println!("message recipient {:?}", h256_to_bits256(message.recipient));
    println!("\n\n");
    println!("message id bits {:?}", h256_to_bits256(message_id));
    println!("message built id {:?}", message_id);

    if let Some(tx) = res.tx_id {
        println!("Transaction sent with ID: {}", tx);
    } else {
        println!("Failed to get TX ID.");
    }
}

fn get_deployment_config() -> LoadConfiguration {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    let salt = Salt::new(bytes);

    LoadConfiguration::default().with_salt(salt)
}

fn test_message(
    mailbox: &Mailbox<WalletUnlocked>,
    recipient: &Bech32ContractId,
) -> HyperlaneAgentMessage {
    let hash = mailbox.account().address().hash();
    let sender = hash.as_slice();

    HyperlaneAgentMessage {
        version: 3u8,
        nonce: 0u32,
        origin: 0x6675656cu32,
        sender: H256::from_slice(sender),
        destination: 0x6675656cu32,
        recipient: H256::from_slice(recipient.hash().as_slice()),
        body: vec![10u8; 100],
    }
}

pub fn h256_to_bits256(h: H256) -> Bits256 {
    Bits256(h.0)
}
