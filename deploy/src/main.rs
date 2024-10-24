use core::panic;
use fuels::types::Identity;
use hyperlane_core::{HyperlaneMessage, RawHyperlaneMessage};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_yaml;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::{env, path::Path};

use fuels::{
    client::{PageDirection, PaginationRequest},
    crypto::SecretKey,
    prelude::*,
    types::{Bits256, BlockHeight, ContractId, Salt},
};

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
    Contract(
        name = "GasOracle",
        abi = "contracts/igp/gas-oracle/out/debug/gas-oracle-abi.json",
    ),
    Contract(
        name = "GasPaymaster",
        abi = "contracts/igp/gas-paymaster/out/debug/gas-paymaster-abi.json",
    ),
    Contract(
        name = "TestRecipient",
        abi = "contracts/test/msg-recipient-test/out/debug/msg-recipient-test-abi.json",
    )
);

struct DeploymentEnv {
    pub rpc_url: &'static str,
    pub secret_key: SecretKey,
    pub dump_path: String,
    pub domain: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ContractAddresses {
    #[serde(rename = "mailbox")]
    mailbox: String,
    #[serde(rename = "postDispatch")]
    post_dispatch: String,
    #[serde(rename = "testRecipient")]
    recipient: String,
    #[serde(rename = "interchainSecurityModule")]
    ism: String,
    #[serde(rename = "merkleTreeHook")]
    merkle_tree_hook: String,
    #[serde(rename = "interchainGasPaymaster")]
    igp: String,
    #[serde(rename = "interchainGasPaymasterHook")]
    igp_hook: String,
    #[serde(rename = "validatorAnnounce")]
    va: String,
}

impl ContractAddresses {
    fn new(
        mailbox: ContractId,
        post_dispatch: ContractId,
        recipient: ContractId,
        ism: ContractId,
        merkle_tree_hook: ContractId,
        igp: ContractId,
        igp_hook: ContractId,
        va: ContractId,
    ) -> Self {
        Self {
            mailbox: format!("0x{}", mailbox.to_string()),
            post_dispatch: format!("0x{}", post_dispatch.to_string()),
            recipient: format!("0x{}", recipient.to_string()),
            ism: format!("0x{}", ism.to_string()),
            merkle_tree_hook: format!("0x{}", merkle_tree_hook.to_string()),
            igp: format!("0x{}", igp.to_string()),
            igp_hook: format!("0x{}", igp_hook.to_string()),
            va: format!("0x{}", va.to_string()),
        }
    }
}

impl DeploymentEnv {
    fn new() -> Self {
        let args: Vec<String> = env::args().collect();

        if args.len() < 2 {
            eprintln!("Error: Please provide deployment location (LOCAL or TESTNET), and optionally a path to dump deployments.");
            std::process::exit(1);
        }
        let env = &args[1];
        let dump_path = match args.get(2) {
            Some(path) => path,
            None => &"./deployments".to_owned(),
        };

        match env.as_str() {
            "LOCAL" => {
                let secret_key = SecretKey::from_str(
                    "0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711",
                )
                .unwrap();
                let local_rpc: &str = "127.0.0.1:4000";
                let dump_path = format!("{}/local", dump_path);
                Self {
                    rpc_url: local_rpc,
                    secret_key,
                    dump_path,
                    domain: 13374,
                }
            }
            "TESTNET" => {
                let secret_key = SecretKey::from_str(
                    "0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711",
                )
                .unwrap();
                let testnet_rpc: &str = "testnet.fuel.network";
                let dump_path = format!("{}/testnet", dump_path);
                Self {
                    rpc_url: testnet_rpc,
                    secret_key,
                    dump_path,
                    domain: 1717982312,
                }
            }
            _ => panic!("Invalid environment string."),
        }
    }
}

#[tokio::main]
async fn main() {
    // Wallet Initialization
    let env = DeploymentEnv::new();
    let provider = Provider::connect(env.rpc_url).await.unwrap();
    let wallet = WalletUnlocked::new_from_private_key(env.secret_key, Some(provider.clone()));
    let block_number = provider.latest_block_height().await.unwrap();
    println!("Deployer: {}", Address::from(wallet.address()));
    println!("Config sync block: {}", block_number);

    /////////////////////////////////
    // Mailbox Contract Deployment //
    /////////////////////////////////

    let binary_filepath = "../contracts/mailbox/out/debug/mailbox.bin";
    let config = get_deployment_config();
    let configurables = MailboxConfigurables::default()
        .with_LOCAL_DOMAIN(env.domain)
        .unwrap();
    let mailbox_contract_id = Contract::load_from(
        binary_filepath,
        config.clone().with_configurables(configurables),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "Mailbox deployed with ID: {}",
        ContractId::from(mailbox_contract_id.clone())
    );

    ///////////////////////////////////
    // Post Dispatch Mock Deployment //
    ///////////////////////////////////

    let binary_filepath = "../contracts/mocks/mock-post-dispatch/out/debug/mock-post-dispatch.bin";
    let contract = Contract::load_from(binary_filepath, config.clone()).unwrap();
    let post_dispatch_mock_id = contract
        .deploy(&wallet, TxPolicies::default())
        .await
        .unwrap();

    println!(
        "Post Dispatch Contract deployed with ID: {}",
        ContractId::from(post_dispatch_mock_id.clone())
    );

    ///////////////////////////////
    // Test Recipient deployment //
    ///////////////////////////////

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

    /////////////////////////
    // Test ISM deployment //
    /////////////////////////

    let ism_id = Contract::load_from(
        "../contracts/test/ism-test/out/debug/ism-test.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    println!("ISM deployed with ID: {}", ContractId::from(ism_id.clone()));

    /////////////////////////////////
    // Merkle Tree hook deployment //
    /////////////////////////////////

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

    /////////////////////////////////////////
    // Gas Paymaster Components Deployment //
    /////////////////////////////////////////

    // Gas Oracle deployment
    let gas_oracle_id = Contract::load_from(
        "../contracts/igp/gas-oracle/out/debug/gas-oracle.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

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

    ///////////////////////////
    // Instantiate Contracts //
    ///////////////////////////

    let post_dispatch_mock = PostDispatch::new(post_dispatch_mock_id.clone(), wallet.clone());
    let mailbox = Mailbox::new(mailbox_contract_id.clone(), wallet.clone());
    let merkle_tree_hook = MerkleTreeHook::new(merkle_tree_id.clone(), wallet.clone());
    let igp_hook = IGPHook::new(igp_hook_id.clone(), wallet.clone());
    let gas_oracle = GasOracle::new(gas_oracle_id.clone(), wallet.clone());
    let igp = GasPaymaster::new(igp_id.clone(), wallet.clone());
    let test_recipient = TestRecipient::new(recipient_id.clone(), wallet.clone());

    /////////////////////////
    // Test Recipiet Setup //
    /////////////////////////

    let set_res = test_recipient
        .methods()
        .set_ism(ism_id.clone())
        .call()
        .await;

    assert!(set_res.is_ok(), "Failed to set ISM in Test Recipient.");

    ////////////////////////////////
    // Initalize Mailbox Contract //
    ////////////////////////////////

    let wallet_address = Bits256(Address::from(wallet.address()).into());
    let post_dispatch_mock_address = Bits256(ContractId::from(post_dispatch_mock.id()).into());
    let ism_address = Bits256(ContractId::from(ism_id.clone()).into());

    let init_res = mailbox
        .methods()
        .initialize(
            wallet_address,
            ism_address,
            post_dispatch_mock_address, // Initially set to mocks
            post_dispatch_mock_address,
        )
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize Mailbox.");
    println!("Mailbox initialized.");

    ///////////////////////////////
    // Initialize IGP Components //
    ///////////////////////////////

    let owner_identity = Identity::Address(Address::from(wallet.address()));

    // Initialize contracts
    let init_res = gas_oracle
        .methods()
        .initialize_ownership(owner_identity)
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize Gas Oracle.");
    let init_res = igp
        .methods()
        .initialize_ownership(owner_identity)
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize IGP.");
    let init_res = igp_hook
        .methods()
        .initialize(igp.contract_id())
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize IGP Hook.");

    // Set contract values //

    // Gas Oracle
    let set_gas_data_res = gas_oracle
        .methods()
        .set_remote_gas_data_configs(vec![RemoteGasDataConfig {
            domain: 11155111,
            remote_gas_data: RemoteGasData {
                // Numbers from BSC and Optimism testnets
                token_exchange_rate: 15000000000,
                gas_price: 37999464941,
                token_decimals: 18,
            },
        }])
        .call()
        .await;
    // IGP
    let set_beneficiary_res = igp.methods().set_beneficiary(owner_identity).call().await;
    let set_gas_oracle_res = igp
        .methods()
        .set_gas_oracle(11155111, Bits256(gas_oracle.contract_id().hash.into()))
        .call()
        .await;

    assert!(set_gas_data_res.is_ok(), "Failed to set gas data.");
    assert!(set_beneficiary_res.is_ok(), "Failed to set beneficiary.");
    assert!(set_gas_oracle_res.is_ok(), "Failed to set gas oracle.");

    ////////////////////////
    // Validator Announce //
    ////////////////////////

    let mailbox_id = ContractId::from(mailbox_contract_id.clone());
    let configurables = ValidatorAnnounceConfigurables::default()
        .with_MAILBOX_ID(mailbox_id)
        .unwrap()
        .with_LOCAL_DOMAIN(env.domain)
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

    /////////////////////////////////////
    // Merkle Tree Hook Initialization //
    /////////////////////////////////////

    let init_res = merkle_tree_hook
        .methods()
        .initialize(mailbox.id())
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize Merkle Tree Hook.");
    println!("Merkle Tree Hook initialized.");

    /////////////////////////////
    // Save contract addresses //
    /////////////////////////////

    let addresses = ContractAddresses::new(
        mailbox_contract_id.into(),
        post_dispatch_mock_id.into(),
        recipient_id.into(),
        ism_id.into(),
        merkle_tree_id.into(),
        igp_id.into(),
        igp_hook_id.into(),
        validator_id.into(),
    );

    let yaml = serde_yaml::to_string(&addresses).unwrap();
    let full_path = format!("{}/contract_addresses.yaml", env.dump_path);
    let path = Path::new(&full_path);

    if let Some(parent) = path.parent() {
        create_dir_all(parent).unwrap();
    }
    let mut file = File::create(full_path.clone()).unwrap();
    file.write_all(yaml.as_bytes()).unwrap();

    println!("Contract addresses dumped to: {}", full_path);
}

fn get_deployment_config() -> LoadConfiguration {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    bytes.reverse();
    let salt = Salt::new(bytes);

    LoadConfiguration::default().with_salt(salt)
}

/// Deploy new VA contract
async fn deploy_new_va(wallet: WalletUnlocked, config: LoadConfiguration) {
    let mailbox_id =
        ContractId::from_str("0x0b5da5eba44aa5473da4defe65194a83e3dc2b0357a006dfbe57771e20ce4d83")
            .unwrap();
    let configurables = ValidatorAnnounceConfigurables::default()
        .with_MAILBOX_ID(mailbox_id)
        .unwrap()
        .with_LOCAL_DOMAIN(1717982312)
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
}

/// Dispatch test
async fn trigger_dispatch() {
    let provider = Provider::connect("testnet.fuel.network").await.unwrap();
    let secret_key =
        SecretKey::from_str("0x5d80cd4fdacb3f5099311a197bb0dc6eb311dfd08e2c8ac3d901ff78629e2e28")
            .unwrap();
    let wallet = WalletUnlocked::new_from_private_key(secret_key, Some(provider.clone()));

    // Send dispatch
    let mailbox_id = "0x2d958d653083f13ea4653c6114473ab97b9ffe40efdedca87930512bd761d0ce";
    let mailbox_contract_id = ContractId::from_str(mailbox_id).unwrap();

    let mailbox_instance = Mailbox::new(mailbox_contract_id.clone(), wallet.clone());
    let recipient_address = hex::decode("c2E0b1526E677EA0a856Ec6F50E708502F7fefa9").unwrap();
    let mut address_array = [0u8; 32];
    address_array[12..].copy_from_slice(&recipient_address);

    let rnd_number = thread_rng().gen_range(0..10000);
    let body_text = format!("Hello from Fuel! {}", rnd_number);
    let body = hex::encode(body_text).into_bytes();
    let metadata = hex::encode("testestubng").into_bytes();
    let res = mailbox_instance
        .methods()
        .dispatch(
            11155111,
            Bits256(address_array),
            Bytes { 0: body },
            Bytes { 0: metadata },
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
}

/// Recipient test
async fn recipient_test() {
    let provider = Provider::connect("testnet.fuel.network").await.unwrap();
    let secret_key =
        SecretKey::from_str("0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711")
            .unwrap();
    let wallet = WalletUnlocked::new_from_private_key(secret_key, Some(provider.clone()));

    // Send dispatch
    let recipient_addr = "0xa347fa1775198aa68fb1a4523a4925f891cca8f4dc79bf18ca71274c49f600c3";
    let mailbox_addr = "0x8a71b28c1f5d869e5b2fefd0c63e84357af42c173c7025da43830df53a32cb58";
    let rec_contract_id = ContractId::from_str(recipient_addr).unwrap();
    let mailbox_contract_id = ContractId::from_str(mailbox_addr).unwrap();

    let rec_instance = TestRecipient::new(rec_contract_id.clone(), wallet.clone());
    let mailbox_instance = Mailbox::new(mailbox_contract_id.clone(), wallet.clone());

    println!(
        "{:?}",
        rec_instance.methods().handled().call().await.unwrap().value
    );

    let contract_id = ContractId::from_str(&recipient_addr).unwrap();

    println!(
        "Recipient formatted: {:?}",
        Bech32ContractId::from(contract_id)
    );

    let res = mailbox_instance
        .methods()
        .recipient_ism(Bech32ContractId::from(contract_id))
        .determine_missing_contracts(Some(3))
        .await
        .unwrap()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap();

    println!("ISM: {:?}", res.value);
}

/// Est gas test
async fn est_gas_test() {
    let provider = Provider::connect("testnet.fuel.network").await.unwrap();
    let secret_key =
        SecretKey::from_str("0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711")
            .unwrap();
    let wallet = WalletUnlocked::new_from_private_key(secret_key, Some(provider.clone()));

    // Send dispatch
    let recipient_addr = "0xa347fa1775198aa68fb1a4523a4925f891cca8f4dc79bf18ca71274c49f600c3";
    let mailbox_addr = "0x8a71b28c1f5d869e5b2fefd0c63e84357af42c173c7025da43830df53a32cb58";
    let rec_contract_id = ContractId::from_str(recipient_addr).unwrap();
    let mailbox_contract_id = ContractId::from_str(mailbox_addr).unwrap();

    let rec_instance = TestRecipient::new(rec_contract_id.clone(), wallet.clone());
    let mailbox_instance = Mailbox::new(mailbox_contract_id.clone(), wallet.clone());

    let message = HyperlaneMessage::default();

    let process_call = mailbox_instance
        .methods()
        .process(Bytes(vec![0]), Bytes(RawHyperlaneMessage::from(&message)));
    let ism_call = rec_instance.methods().interchain_security_module();

    let est = CallHandler::new_multi_call(wallet.clone())
        .add_call(process_call)
        .add_call(ism_call)
        .estimate_transaction_cost(Some(1.0), Some(1))
        .await
        .unwrap();

    println!("Estimate: {:?}", est);
}

/// Check Delivery
async fn check_if_delivered() {
    let provider = Provider::connect("testnet.fuel.network").await.unwrap();
    let secret_key =
        SecretKey::from_str("0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711")
            .unwrap();
    let wallet = WalletUnlocked::new_from_private_key(secret_key, Some(provider.clone()));

    // Send dispatch
    let recipient_addr = "0xa347fa1775198aa68fb1a4523a4925f891cca8f4dc79bf18ca71274c49f600c3";
    let mailbox_addr = "0x8a71b28c1f5d869e5b2fefd0c63e84357af42c173c7025da43830df53a32cb58";
    let rec_contract_id = ContractId::from_str(recipient_addr).unwrap();
    let mailbox_contract_id = ContractId::from_str(mailbox_addr).unwrap();

    let rec_instance = TestRecipient::new(rec_contract_id.clone(), wallet.clone());
    let mailbox_instance = Mailbox::new(mailbox_contract_id.clone(), wallet.clone());

    let message_id =
        Bits256::from_hex_str("0x2d04e7c14bbea23e972766763c92503bccb86058ec536c16c27b103e6a47aca8")
            .unwrap();
    let delivered_res = mailbox_instance
        .methods()
        .delivered(message_id)
        .call()
        .await
        .unwrap();

    println!("Delivered: {:?}", delivered_res.value);
}

/// Pagination test
async fn test_pagination() {
    println!("Pagination test");
    let provider = Provider::connect("testnet.fuel.network").await.unwrap();

    let blocks_per_req: u32 = 10;
    let mut range: RangeInclusive<u32> = 13509410..=13509420;
    // let mut range: RangeInclusive<u32> = 0..=10;

    let mut block_req_cursor = Some("12898721".to_owned());
    let mut tx_req_cursor = None;
    let mut rewind = false;
    let mut i = 0;

    loop {
        if rewind {
            println!("Rewinding");
            range = range.start() - 100..=range.end() - 100;
        }
        println!("Range: {:?}", range);

        let range_start = range.start();
        if *range_start == 0 {
            block_req_cursor = None;
            tx_req_cursor = None;
        } else {
            let start_block = BlockHeight::from(*range_start);
            let block_data = provider
                .block_by_height(start_block)
                .await
                .expect("Failed to get block data")
                .unwrap();
            let first_transaction = block_data.transactions.first().unwrap();

            let hex_block = hex::encode(range_start.to_be_bytes());
            let hex_tx = hex::encode(first_transaction.to_vec());

            tx_req_cursor = Some(format!("{}#0x{}", hex_block, hex_tx));
            block_req_cursor = Some(range_start.to_string());
        }

        println!("block cursor: {:?}", block_req_cursor);
        println!("tx cursor: {:?}", tx_req_cursor);

        // pull blocks
        let result_amount: u32 = range.end() - range.start();
        println!("requesting : {:?} blocks", result_amount);
        let req = PaginationRequest {
            cursor: block_req_cursor,
            results: result_amount as i32,
            direction: PageDirection::Forward,
        };

        let blocks = provider.clone().get_blocks(req).await.unwrap();
        println!("retrieved : {:?} blocks", blocks.results.len());
        for block in blocks.results.iter() {
            println!();
            println!(
                "block id {:?}\n tx_amount: {:?}\n transactions: {:?}",
                block.id, block.header.transactions_count, block.transactions
            );
            println!();
        }
        let tx_ids = blocks
            .results
            .iter()
            .flat_map(|block| block.transactions.iter())
            .collect::<Vec<_>>();

        let tx_amount = blocks
            .results
            .iter()
            .fold(0, |acc: usize, block| acc + block.transactions.len())
            as i32;

        assert_eq!(tx_ids.len(), tx_amount as usize);
        println!("tx amount in blocks: {:?}", tx_amount);

        let req = PaginationRequest {
            cursor: tx_req_cursor,
            results: tx_amount,
            direction: PageDirection::Forward,
        };
        let txs = provider.clone().get_transactions(req).await.unwrap();
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

        if rewind {
            break;
        }

        i += 1;
        if i == 2 {
            rewind = true;
        }
        range = range.start() + blocks_per_req..=range.end() + blocks_per_req;

        println!("tx cursor for next query: {:?}", txs.cursor);
        println!("block cursor for next query: {:?}", blocks.cursor);
    }
}
