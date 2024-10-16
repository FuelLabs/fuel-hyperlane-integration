use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::fs::{self, create_dir_all, File};
use std::io::Write;
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
        name = "WarpRoute",
        abi = "contracts/warp-route/out/debug/warp-route-abi.json",
    ),
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
    #[serde(rename = "warpRoute")]
    warp_route: String,
    #[serde(rename = "warpRouteBridged")]
    warp_route_bridged: String,
    #[serde(rename = "interchainGasPaymasterOracle")]
    gas_oracle: String,
}

#[allow(clippy::too_many_arguments)]
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
        warp_route: ContractId,
        warp_route_bridged: ContractId,
        gas_oracle: ContractId,
    ) -> Self {
        Self {
            mailbox: format!("0x{}", mailbox),
            post_dispatch: format!("0x{}", post_dispatch),
            recipient: format!("0x{}", recipient),
            ism: format!("0x{}", ism),
            merkle_tree_hook: format!("0x{}", merkle_tree_hook),
            igp: format!("0x{}", igp),
            igp_hook: format!("0x{}", igp_hook),
            va: format!("0x{}", va),
            warp_route: format!("0x{}", warp_route),
            warp_route_bridged: format!("0x{}", warp_route_bridged),
            gas_oracle: format!("0x{}", gas_oracle),
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
    println!("Deployer: {}", Address::from(wallet.address()));

    // Mailbox Contract Deployment

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

    println!(
        "Mailbox Bech32 from deploy script {:?}",
        mailbox_contract_id
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

    // Warp Route Deployment -Native
    let warp_route_id = Contract::load_from(
        "../contracts/warp-route/out/debug/warp-route.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    // Deploy bridged warp route with a new salt - otherwise yields ContractIdAlreadyDeployed error
    let new_salt = fuels::types::Salt::new([1u8; 32]);
    let new_config = LoadConfiguration::default().with_salt(new_salt);
    let warp_route_bridged_id = Contract::load_from(
        "../contracts/warp-route/out/debug/warp-route.bin",
        new_config,
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    //Gas Oracle Deployment
    let gas_oracle_id = Contract::load_from(
        "../contracts/igp/gas-oracle/out/debug/gas-oracle.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    // Instantiate Contracts

    let post_dispatch = PostDispatch::new(post_dispatch_contract_id.clone(), wallet.clone());
    let mailbox = Mailbox::new(mailbox_contract_id.clone(), wallet.clone());
    let merkle_tree_hook = MerkleTreeHook::new(merkle_tree_id.clone(), wallet.clone());
    let igp_hook = IGPHook::new(igp_hook_id.clone(), wallet.clone());
    let warp_route = WarpRoute::new(warp_route_id.clone(), wallet.clone());
    let warp_route_bridged = WarpRoute::new(warp_route_bridged_id.clone(), wallet.clone());

    // Initalize Mailbox Contract
    let wallet_address = Bits256(Address::from(wallet.address()).into());
    let post_dispatch_address = Bits256(ContractId::from(post_dispatch.id()).into());
    let ism_address = Bits256(ContractId::from(ism_id.clone()).into());
    let mailbox_address = Bits256(ContractId::from(mailbox_contract_id.clone()).into());
    let igp_hook_address = Bits256(ContractId::from(igp_hook_id.clone()).into());

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

    // Initalize Warp Routes
    let init_res = warp_route
        .methods()
        .initialize(
            wallet_address,
            mailbox_address,
            WarpRouteTokenMode::COLLATERAL,
            igp_hook_address,
            "Ether".to_string(),
            "ETH".to_string(),
            9,
            1_000_000_000,
            Some(
                AssetId::from_str(
                    "0xf8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07",
                )
                .unwrap(),
            ),
        )
        .call()
        .await;

    assert!(init_res.is_ok(), "Failed to initialize Warp Route.");
    println!("Warp Route initialized.");

    // Get bridged token info and deploy bridged warp route
    let yaml_content =
        fs::read_to_string("../infra/configs/deployments/warp_routes/STR/test1-config.yaml")
            .expect("Failed to read YAML file");
    let yaml_data: serde_yaml::Value =
        serde_yaml::from_str(&yaml_content).expect("Failed to parse YAML");

    let token_info = &yaml_data["tokens"][0];
    let name = token_info["name"].as_str().unwrap();
    let symbol = token_info["symbol"].as_str().unwrap();
    let decimals = token_info["decimals"].as_u64().unwrap();

    let bridged_init_res = warp_route_bridged
        .methods()
        .initialize(
            wallet_address,
            mailbox_address,
            WarpRouteTokenMode::BRIDGED,
            igp_hook_address,
            name.to_string(),
            symbol.to_string(),
            decimals as u8,
            1_000_000_000,
            None, // Bridged asset id will be derived by the contract
        )
        .call()
        .await;

    assert!(
        bridged_init_res.is_ok(),
        "Failed to initialize Bridged Warp Route."
    );
    println!("Bridged Warp Route initialized.");

    // Dump contract addresses
    let addresses = ContractAddresses::new(
        mailbox_contract_id.into(),
        post_dispatch_contract_id.into(),
        recipient_id.into(),
        ism_id.into(),
        merkle_tree_id.into(),
        igp_id.into(),
        igp_hook_id.into(),
        validator_id.into(),
        warp_route_id.into(),
        warp_route_bridged_id.into(),
        gas_oracle_id.into(),
    );

    let yaml = serde_yaml::to_string(&addresses).unwrap();
    let full_path = format!("{}/contract_addresses.yaml", env.dump_path);
    let path = Path::new(&full_path);

    // Ensure the directory exists
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
async fn trigger_dispatch(wallet: WalletUnlocked, _mailbox: Mailbox<WalletUnlocked>) {
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
}

/// Pagination test
async fn test_pagination(provider: Provider) {
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
}
