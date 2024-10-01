use rand::{thread_rng, Rng};
use std::str::FromStr;

use fuels::{
    client::{PageDirection, PaginationRequest},
    crypto::SecretKey,
    prelude::*,
    types::{Bits256, BlockHeight, ContractId, Salt},
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
    ),
    Contract(
        name = "MerkleTreeHook",
        abi = "contracts/hooks/merkle-tree-hook/out/debug/merkle-tree-hook-abi.json",
    ),
    Contract(
        name = "IGPHook",
        abi = "contracts/hooks/igp/out/debug/igp-hook-abi.json",
    ),
    Contract(
        name = "ValidatorAnnounce",
        abi = "contracts/validator-announce/out/debug/validator-announce-abi.json",
    ),
);

#[tokio::main]
async fn main() {
    // Wallet Initialization

    let provider = Provider::connect(TESTNET_NODE).await.unwrap();
    let private_key =
        SecretKey::from_str("0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711")
            .unwrap();
    let wallet = WalletUnlocked::new_from_private_key(private_key, Some(provider.clone()));
    println!("Deployer: {}", Address::from(wallet.address()));

    // Dispatch test
    if false {
        // Send dispatch
        let mailbox_id = "0x0b5da5eba44aa5473da4defe65194a83e3dc2b0357a006dfbe57771e20ce4d83";
        let mailbox_contract_id = ContractId::from_str(mailbox_id).unwrap();

        let mailbox_instance = Mailbox::new(mailbox_contract_id.clone(), wallet.clone());
        let recipient_address = hex::decode("c2E0b1526E677EA0a856Ec6F50E708502F7fefa9").unwrap();
        let mut address_array = [0u8; 32];
        address_array[12..].copy_from_slice(&recipient_address);

        let body = hex::encode("Hello from Fuel!").into_bytes();
        let res = mailbox_instance
            .methods()
            .dispatch(
                11155111,
                Bits256(address_array),
                Bytes { 0: body },
                Bytes { 0: vec![0] },
                ContractId::zeroed(),
            )
            .determine_missing_contracts(Some(3))
            .await
            .unwrap()
            .call()
            .await;

        if let Err(e) = res {
            println!("Dispatch error: {:?}", e);
        } else {
            println!("Dispatch result: {:?}", res);
        }

        panic!();
    }

    //

    // Pagination test
    if false {
        let blocks_per_req = 10;
        let mut block_req_cursor = Some("11000000".to_owned());
        let mut tx_req_cursor = None;

        loop {
            if block_req_cursor.is_some() && tx_req_cursor.is_none() {
                let block_number: u32 = block_req_cursor
                    .clone()
                    .unwrap()
                    .parse()
                    .expect("Not a valid number");

                let start_block = BlockHeight::from(block_number);
                let block_data = provider
                    .block_by_height(start_block)
                    .await
                    .expect("Failed to get block data")
                    .unwrap();

                let first_transaction = block_data.transactions.first().unwrap();
                let hex_block = hex::encode(block_number.to_be_bytes());
                let hex_tx = hex::encode(first_transaction.to_vec());
                let tx_cursor = Some(format!("{}#0x{}", hex_block, hex_tx));
                let block_cursor = Some(block_number.to_string());

                block_req_cursor = block_cursor;
                tx_req_cursor = tx_cursor;
            }
            println!("block cursor: {:?}", block_req_cursor);
            println!("tx cursor: {:?}", tx_req_cursor);

            // pull blocks
            let req = PaginationRequest {
                cursor: block_req_cursor,
                results: blocks_per_req,
                direction: PageDirection::Forward,
            };

            let blocks = provider.clone().get_blocks(req).await.unwrap();
            println!("retrieved : {:?} blocks", blocks.results.len());
            for block in blocks.results.iter() {
                println!();
                println!("block: {:?}", block);
                println!();
            }
            let tx_ids = blocks
                .results
                .iter()
                .flat_map(|block| block.transactions.iter())
                .collect::<Vec<_>>();

            block_req_cursor = blocks.cursor;
            let tx_amount = blocks
                .results
                .iter()
                .fold(0, |acc: usize, block| acc + block.transactions.len())
                as i32;

            println!("tx amount in blocks: {:?}", tx_amount);

            let req = PaginationRequest {
                cursor: tx_req_cursor,
                results: tx_amount,
                direction: PageDirection::Forward,
            };
            let txs = provider.clone().get_transactions(req).await.unwrap();
            tx_req_cursor = txs.cursor.clone();
            println!("retrieved : {:?} transacitons", txs.results.len());
            assert_eq!(tx_ids.len(), txs.results.len());

            for (tx_id, tx) in tx_ids.iter().zip(txs.results.iter()) {
                let tx_fresh = provider
                    .get_transaction_by_id(tx_id.clone())
                    .await
                    .unwrap()
                    .unwrap();

                println!("------------------------------------");
                println!("tx: {:?}", tx);
                println!("tx fresh: {:?}", tx_fresh);
                println!("------------------------------------");
            }

            panic!();

            println!("cursor for next query: {:?}", txs.cursor);
        }

        let req = PaginationRequest {
            cursor: block_req_cursor,
            results: blocks_per_req,
            direction: PageDirection::Forward,
        };

        let blocks = provider.clone().get_blocks(req).await.unwrap();
        let tx_amount = blocks
            .results
            .iter()
            .fold(0, |acc, block| acc + block.transactions.len());

        println!("tx amount in blocks: {:?}", tx_amount);

        let req = PaginationRequest {
            cursor: None,
            results: i32::try_from(tx_amount).expect("Invalid range"),
            direction: PageDirection::Forward,
        };
        let txs = provider.clone().get_transactions(req).await.unwrap();

        println!("retrieved : {:?} transacitons", txs.results.len());
        println!("cursor for next query: {:?}", txs.cursor);

        panic!();

        println!("block cursor: {:?}", blocks.cursor);

        let latest = blocks.results.get(blocks.results.len() - 1).unwrap();
        let next = BlockHeight::new(latest.header.height).succ().unwrap();

        println!("Latest block from query: {:?}", latest);

        let next_block = provider
            .clone()
            .block_by_height(next)
            .await
            .unwrap()
            .unwrap();

        println!("Next block from query: {:?}", next_block);
        let hex_block = hex::encode(next_block.header.height.to_be_bytes());
        println!("Next block height: {}", hex_block);
        let cursor_tx = hex::encode(next_block.transactions.get(0).unwrap().to_vec());
        println!("Cursor tx: {:?}", cursor_tx);
        let tx_cursor = format!("{}#0x{}", hex_block, cursor_tx);
        println!("Tx cursor: {:?}", tx_cursor);

        let req = PaginationRequest {
            cursor: Some(tx_cursor),
            results: i32::try_from(2010).expect("Invalid range"),
            direction: PageDirection::Backward,
        };
        let tx_q_test = provider.clone().get_transactions(req).await.unwrap();
        println!("Tx query test: {:?}", tx_q_test.cursor);
        println!("Tx query test results: {:?}", tx_q_test.results.len());

        panic!();
    }

    // Mailbox Contract Deployment

    let binary_filepath = "../contracts/mailbox/out/debug/mailbox.bin";

    let config = get_deployment_config();
    let contract = Contract::load_from(binary_filepath, config.clone()).unwrap();

    let mailbox_contract_id = contract
        .deploy(&wallet, TxPolicies::default())
        .await
        .unwrap();

    println!(
        "Mailbox deployed with ID: {}",
        ContractId::from(mailbox_contract_id.clone())
    );

    // Post Dispatch Mock Deployment

    let binary_filepath = "../contracts/mocks/mock-post-dispatch/out/debug/mock-post-dispatch.bin";
    let contract = Contract::load_from(binary_filepath, config.clone()).unwrap();
    let post_dispatch_contract_id = contract
        .deploy(&wallet, TxPolicies::default())
        .await
        .unwrap();

    println!(
        "Post Dispatch Contract deployed with ID: {}",
        ContractId::from(post_dispatch_contract_id.clone())
    );

    // Recipient deplyment

    let recipient_id = Contract::load_from(
        "../contracts/test/msg-recipient-test/out/debug/msg-recipient-test.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "Recipient deployed with ID: {}",
        ContractId::from(recipient_id.clone())
    );

    // Test ISM deployment

    let ism_id = Contract::load_from(
        "../contracts/test/ism-test/out/debug/ism-test.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    println!("ISM deployed with ID: {}", ContractId::from(ism_id.clone()));

    // Merkle Tree hook deployment

    let merkle_tree_id = Contract::load_from(
        "../contracts/hooks/merkle-tree-hook/out/debug/merkle-tree-hook.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "Merkle Tree Hook deployed with ID: {}",
        ContractId::from(merkle_tree_id.clone())
    );

    // IGP deployment

    let igp_id = Contract::load_from(
        "../contracts/igp/gas-paymaster/out/debug/gas-paymaster.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    println!("IGP deployed with ID: {}", ContractId::from(igp_id.clone()));

    // IGP Hook deployment

    let igp_hook_id = Contract::load_from(
        "../contracts/hooks/igp/out/debug/igp-hook.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "IGP Hook deployed with ID: {}",
        ContractId::from(igp_hook_id.clone())
    );

    // Instantiate Contracts

    let post_dispatch = PostDispatch::new(post_dispatch_contract_id.clone(), wallet.clone());
    let mailbox = Mailbox::new(mailbox_contract_id.clone(), wallet.clone());
    let merkle_tree_hook = MerkleTreeHook::new(merkle_tree_id, wallet.clone());
    let igp_hook = IGPHook::new(igp_hook_id.clone(), wallet.clone());

    // Initalize Mailbox Contract

    let wallet_address = Bits256(Address::from(wallet.address()).into());
    let post_dispatch_address = Bits256(ContractId::from(post_dispatch.id()).into());
    let ism_address = Bits256(ContractId::from(ism_id).into());

    let init_res = mailbox
        .methods()
        .initialize(
            wallet_address,
            ism_address,
            post_dispatch_address,
            post_dispatch_address,
        )
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize Mailbox.");
    println!("Mailbox initialized.");

    // VA

    let mailbox_id = ContractId::from(mailbox_contract_id.clone());
    let configurables = ValidatorAnnounceConfigurables::default()
        .with_MAILBOX_ID(mailbox_id)
        .unwrap();

    // Validator announce deployment

    let validator_id = Contract::load_from(
        "../contracts/validator-announce/out/debug/validator-announce.bin",
        config.clone().with_configurables(configurables),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "VA deployed with ID: {}",
        ContractId::from(validator_id.clone())
    );

    // Initalize IGP hoook

    let init_res = igp_hook.methods().initialize(igp_id.clone()).call().await;

    assert!(init_res.is_ok(), "Failed to initialize IGP Hook.");
    println!("IGP Hook initialized.");

    // Initalize Merkle Tree hook

    let init_res = merkle_tree_hook
        .methods()
        .initialize(mailbox.id())
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize Merkle Tree Hook.");
    println!("Merkle Tree Hook initialized.");
}

fn get_deployment_config() -> LoadConfiguration {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    let salt = Salt::new(bytes);

    LoadConfiguration::default().with_salt(salt)
}
