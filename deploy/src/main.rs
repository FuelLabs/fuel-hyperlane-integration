use alloy::signers::{
    k256::{ecdsa::SigningKey, SecretKey as SepoliaPrivateKey},
    local::PrivateKeySigner,
};
use core::panic;
use fuels::types::{EvmAddress, Identity};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_yaml;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::str::FromStr;
use std::{env, path::Path};

use fuels::{
    crypto::SecretKey,
    prelude::*,
    types::{Bits256, ContractId, Salt},
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
    ),
    Contract(
<<<<<<< HEAD
        name = "AggregationISM",
        abi = "contracts/ism/aggregation-ism/out/debug/aggregation-ism-abi.json",
    ),
    Contract(
        name = "DomainRoutingISM",
        abi = "contracts/ism/routing/domain-routing-ism/out/debug/domain-routing-ism-abi.json",
    ),
    Contract(
        name = "FallbackDomainRoutingISM",
        abi = "contracts/ism/routing/default-fallback-domain-routing-ism/out/debug/default-fallback-domain-routing-ism-abi.json",
    ),
    Contract(
        name = "MessageIdMultisigISM",
        abi = "contracts/ism/multisig/message-id-multisig-ism/out/debug/message-id-multisig-ism-abi.json",
    ),
    Contract(
        name = "MerkleRootMultisigISM",
        abi = "contracts/ism/multisig/merkle-root-multisig-ism/out/debug/merkle-root-multisig-ism-abi.json",
    ),
    Contract(
        name = "MessageIdMultisigISMTest",
        abi = "contracts/test/message-id-multisig-ism-test/out/debug/message-id-multisig-ism-test-abi.json",
    ),
    Contract(
        name = "MerkleRootMultisigISMTest",
        abi = "contracts/test/merkle-root-multisig-ism-test/out/debug/merkle-root-multisig-ism-test-abi.json",
    )
=======
        name = "WarpRoute",
        abi = "contracts/warp-route/out/debug/warp-route-abi.json",
    ),
>>>>>>> aca010ac2b0f273da1a137c7d6be4a08654d0d34
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
    #[serde(rename = "gasOracle")]
    gas_oracle: String,
<<<<<<< HEAD
    #[serde(rename = "aggregationISM")]
    aggregation_ism: String,
    #[serde(rename = "domainRoutingISM")]
    domain_routing_ism: String,
    #[serde(rename = "fallbackDomainRoutingISM")]
    fallback_domain_routing_ism: String,
    #[serde(rename = "messageIdMultisigISM")]
    message_id_multisig_ism: String,
    #[serde(rename = "merkleRootMultisigISM")]
    merkle_root_multisig_ism: String,
=======
    #[serde(rename = "warpRoute")]
    warp_route: String,
    #[serde(rename = "warpRouteBridged")]
    warp_route_bridged: String,
>>>>>>> aca010ac2b0f273da1a137c7d6be4a08654d0d34
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
        gas_oracle: ContractId,
<<<<<<< HEAD
        aggregation_ism: ContractId,
        domain_routing_ism: ContractId,
        fallback_domain_routing_ism: ContractId,
        message_id_multisig_ism: ContractId,
        merkle_root_multisig_ism: ContractId,
=======
        warp_route: ContractId,
        warp_route_bridged: ContractId,
>>>>>>> aca010ac2b0f273da1a137c7d6be4a08654d0d34
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
            gas_oracle: format!("0x{}", gas_oracle),
<<<<<<< HEAD
            aggregation_ism: format!("0x{}", aggregation_ism),
            domain_routing_ism: format!("0x{}", domain_routing_ism),
            fallback_domain_routing_ism: format!("0x{}", fallback_domain_routing_ism),
            message_id_multisig_ism: format!("0x{}", message_id_multisig_ism),
            merkle_root_multisig_ism: format!("0x{}", merkle_root_multisig_ism),
=======
            warp_route: format!("0x{}", warp_route),
            warp_route_bridged: format!("0x{}", warp_route_bridged),
>>>>>>> aca010ac2b0f273da1a137c7d6be4a08654d0d34
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
        let fuel_pk = env::var("FUEL_PRIVATE_KEY").expect("FUEL_PRIVATE_KEY must be set");

        match env.as_str() {
            "LOCAL" => {
                let secret_key = SecretKey::from_str(&fuel_pk).unwrap();
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
                let secret_key = SecretKey::from_str(&fuel_pk).unwrap();
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
    dotenv::dotenv().ok();
    // Wallet Initialization
    let env = DeploymentEnv::new();
    let sepolia_pk = SepoliaPrivateKey::from_slice(
        &hex::decode(env::var("SEPOLIA_PRIVATE_KEY").expect("SEPOLIA_PRIVATE_KEY must be set"))
            .unwrap(),
    )
    .unwrap();
    let sepolia_pk = SigningKey::from(sepolia_pk);
    let evm_signer = PrivateKeySigner::from_signing_key(sepolia_pk);

    let fuel_provider = Provider::connect(env.rpc_url).await.unwrap();
    let fuel_wallet =
        WalletUnlocked::new_from_private_key(env.secret_key, Some(fuel_provider.clone()));
    let block_number = fuel_provider.latest_block_height().await.unwrap();
    println!("Deployer: {}", Address::from(fuel_wallet.address()));
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
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "mailbox: 0x{}",
        ContractId::from(mailbox_contract_id.clone())
    );

    ///////////////////////////////////
    // Post Dispatch Mock Deployment //
    ///////////////////////////////////

    let binary_filepath = "../contracts/mocks/mock-post-dispatch/out/debug/mock-post-dispatch.bin";
    let contract = Contract::load_from(binary_filepath, config.clone()).unwrap();
    let post_dispatch_mock_id = contract
        .deploy(&fuel_wallet, TxPolicies::default())
        .await
        .unwrap();

    println!(
        "postDispatch: 0x{}",
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
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!("recipient: 0x{}", ContractId::from(recipient_id.clone()));

    /////////////////////
    // ISMs deployment //
    /////////////////////

    let test_ism_id = Contract::load_from(
        "../contracts/test/ism-test/out/debug/ism-test.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
<<<<<<< HEAD
        "Test ISM deployed with ID: {}",
        ContractId::from(test_ism_id.clone())
    );

    let aggregation_ism_id = Contract::load_from(
        "../contracts/ism/aggregation-ism/out/debug/aggregation-ism.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "Aggregation ISM deployed with ID: {}",
        ContractId::from(aggregation_ism_id.clone())
    );

    let domain_routing_ism_id = Contract::load_from(
        "../contracts/ism/routing/domain-routing-ism/out/debug/domain-routing-ism.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "Domain Routing ISM deployed with ID: {}",
        ContractId::from(domain_routing_ism_id.clone())
    );

    let fallback_domain_routing_ism_id = Contract::load_from(
        "../contracts/ism/routing/default-fallback-domain-routing-ism/out/debug/default-fallback-domain-routing-ism.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "Fallback Domain Routing ISM deployed with ID: {}",
        ContractId::from(fallback_domain_routing_ism_id.clone())
    );

    let message_id_multisig_ism_id = Contract::load_from(
        "../contracts/ism/multisig/message-id-multisig-ism/out/debug/message-id-multisig-ism.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "Message ID Multisig ISM deployed with ID: {}",
        ContractId::from(message_id_multisig_ism_id.clone())
    );

    let merkle_root_multisig_ism_id = Contract::load_from(
        "../contracts/ism/multisig/merkle-root-multisig-ism/out/debug/merkle-root-multisig-ism.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "Merkle Root Multisig ISM deployed with ID: {}",
        ContractId::from(merkle_root_multisig_ism_id.clone())
=======
        "interchainSecurityModule: 0x{}",
        ContractId::from(ism_id.clone())
>>>>>>> aca010ac2b0f273da1a137c7d6be4a08654d0d34
    );

    /////////////////////////////////
    // Merkle Tree hook deployment //
    /////////////////////////////////

    let merkle_tree_id = Contract::load_from(
        "../contracts/hooks/merkle-tree-hook/out/debug/merkle-tree-hook.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "merkleTreeHook: 0x{}",
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
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!("gasOracle: 0x{}", ContractId::from(gas_oracle_id.clone()));

    // IGP deployment
    let igp_id = Contract::load_from(
        "../contracts/igp/gas-paymaster/out/debug/gas-paymaster.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "interchainGasPaymaster: 0x{}",
        ContractId::from(igp_id.clone())
    );

    // IGP Hook deployment
    let igp_hook_id = Contract::load_from(
        "../contracts/hooks/igp/out/debug/igp-hook.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!("igpHook: 0x{}", ContractId::from(igp_hook_id.clone()));

    ///////////////////////////
    // Warp Route Deployment //
    ///////////////////////////

    // Native
    let native_salt = Salt::from(rand::thread_rng().gen::<[u8; 32]>());
    let warp_route_id = Contract::load_from(
        "../contracts/warp-route/out/debug/warp-route.bin",
        config.clone().with_salt(native_salt),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "warpRouteNative: 0x{}",
        ContractId::from(warp_route_id.clone())
    );

    // Bridged
    let bridged_salt = Salt::from(rand::thread_rng().gen::<[u8; 32]>());
    let warp_route_bridged_id = Contract::load_from(
        "../contracts/warp-route/out/debug/warp-route.bin",
        config.clone().with_salt(bridged_salt),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "warpRouteBridged: 0x{}",
        ContractId::from(warp_route_bridged_id.clone())
    );

    ///////////////////////////
    // Instantiate Contracts //
    ///////////////////////////

<<<<<<< HEAD
    let post_dispatch_mock = PostDispatch::new(post_dispatch_mock_id.clone(), fuel_wallet.clone());
    let mailbox = Mailbox::new(mailbox_contract_id.clone(), fuel_wallet.clone());
    let merkle_tree_hook = MerkleTreeHook::new(merkle_tree_id.clone(), fuel_wallet.clone());
    let igp_hook = IGPHook::new(igp_hook_id.clone(), fuel_wallet.clone());
    let gas_oracle = GasOracle::new(gas_oracle_id.clone(), fuel_wallet.clone());
    let igp = GasPaymaster::new(igp_id.clone(), fuel_wallet.clone());
    let test_recipient = TestRecipient::new(recipient_id.clone(), fuel_wallet.clone());
    let aggregation_ism = AggregationISM::new(aggregation_ism_id.clone(), fuel_wallet.clone());
    let domain_routing_ism =
        DomainRoutingISM::new(domain_routing_ism_id.clone(), fuel_wallet.clone());
    let fallback_domain_routing_ism =
        FallbackDomainRoutingISM::new(fallback_domain_routing_ism_id.clone(), fuel_wallet.clone());
    let message_id_multisig_ism =
        MessageIdMultisigISM::new(message_id_multisig_ism_id.clone(), fuel_wallet.clone());
    let merkle_root_multisig_ism =
        MerkleRootMultisigISM::new(merkle_root_multisig_ism_id.clone(), fuel_wallet.clone());

    let wallet_address = Bits256(Address::from(fuel_wallet.address()).into());
    let test_ism_address = Bits256(ContractId::from(test_ism_id.clone()).into());
    let mailbox_address = Bits256(ContractId::from(mailbox_contract_id.clone()).into());

    /////////////////////
    // Initialize ISMs //
    /////////////////////

    // Aggregation ISM
    let init_res = aggregation_ism
        .methods()
        .initialize(wallet_address)
        .call()
        .await;

    let set_res = aggregation_ism.methods().set_threshold(2).call().await;
    assert!(set_res.is_ok(), "Failed to set threshold.");

    for _ in 0..2 {
        let set_res = aggregation_ism
            .methods()
            .enroll_module(test_ism_id.clone())
            .call()
            .await;

        assert!(set_res.is_ok(), "Failed to enroll ISM in Aggregation ISM.");
    }
    assert!(init_res.is_ok(), "Failed to initialize Aggregation ISM.");

    // Domain Routing ISM
    let init_res = domain_routing_ism
        .methods()
        .initialize_with_domains(
            wallet_address,
            vec![11155111, 84532],
            vec![test_ism_address.clone(), test_ism_address.clone()],
        )
        .call()
        .await;

    assert!(init_res.is_ok(), "Failed to initialize Domain Routing ISM.");

    // Fallback Domain Routing ISM
    let init_res = fallback_domain_routing_ism
        .methods()
        .initialize(wallet_address, mailbox_address.clone())
        .call()
        .await;

    assert!(
        init_res.is_ok(),
        "Failed to initialize Fallback Domain Routing ISM."
    );

    // Message ID Multisig ISM
    let set_res = message_id_multisig_ism
        .methods()
        .set_threshold(1)
        .call()
        .await;

    assert!(set_res.is_ok(), "Failed to set threshold.");

    let validator = EvmAddress::from(Bits256(evm_signer.address().into_word().0));
    let set_res = message_id_multisig_ism
        .methods()
        .enroll_validator(validator.clone())
        .call()
        .await;

    assert!(set_res.is_ok(), "Failed to enroll validator.");

    // Merkle Root Multisig ISM
    let set_res = merkle_root_multisig_ism
        .methods()
        .set_threshold(1)
        .call()
        .await;

    assert!(set_res.is_ok(), "Failed to set threshold.");

    let set_res = merkle_root_multisig_ism
        .methods()
        .enroll_validator(validator)
        .call()
        .await;

    assert!(set_res.is_ok(), "Failed to enroll validator.");
=======
    let post_dispatch_mock = PostDispatch::new(post_dispatch_mock_id.clone(), wallet.clone());
    let mailbox = Mailbox::new(mailbox_contract_id.clone(), wallet.clone());
    let merkle_tree_hook = MerkleTreeHook::new(merkle_tree_id.clone(), wallet.clone());
    let igp_hook = IGPHook::new(igp_hook_id.clone(), wallet.clone());
    let gas_oracle = GasOracle::new(gas_oracle_id.clone(), wallet.clone());
    let igp = GasPaymaster::new(igp_id.clone(), wallet.clone());
    let test_recipient = TestRecipient::new(recipient_id.clone(), wallet.clone());
    let warp_route = WarpRoute::new(warp_route_id.clone(), wallet.clone());
    let warp_route_bridged = WarpRoute::new(warp_route_bridged_id.clone(), wallet.clone());
>>>>>>> aca010ac2b0f273da1a137c7d6be4a08654d0d34

    /////////////////////////
    // Test Recipiet Setup //
    /////////////////////////

    let set_res = test_recipient
        .methods()
        .set_ism(test_ism_id.clone())
        .call()
        .await;

    assert!(set_res.is_ok(), "Failed to set ISM in Test Recipient.");

    ////////////////////////////////
    // Initalize Mailbox Contract //
    ////////////////////////////////

    let post_dispatch_mock_address = Bits256(ContractId::from(post_dispatch_mock.id()).into());

    let init_res = mailbox
        .methods()
        .initialize(
            wallet_address,
            test_ism_address,
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

    let owner_identity = Identity::Address(Address::from(fuel_wallet.address()));

    // Initialize contracts
    let init_res = gas_oracle
        .methods()
        .initialize_ownership(owner_identity)
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize Gas Oracle.");

    let init_res = igp
        .methods()
        .initialize(
            wallet_address,
            wallet_address,
            15000000000 * 850000000, // added * 850000000 for requiring less fuel test token
            18,
            5000,
        )
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
                // Numbers from BSC and Optimism testnets - 15000000000
                token_exchange_rate: 15000000000,
                gas_price: 37999464941,
                token_decimals: 18,
            },
        }])
        .call()
        .await;
    assert!(set_gas_data_res.is_ok(), "Failed to set gas data.");

    // IGP
    let set_beneficiary_res = igp.methods().set_beneficiary(owner_identity).call().await;
    assert!(set_beneficiary_res.is_ok(), "Failed to set beneficiary.");

    let set_gas_oracle_res = igp
        .methods()
        .set_gas_oracle(11155111, Bits256(gas_oracle_id.hash().into()))
        .call()
        .await;

    assert!(set_gas_data_res.is_ok(), "Failed to set gas data.");
    assert!(set_beneficiary_res.is_ok(), "Failed to set beneficiary.");
    assert!(set_gas_oracle_res.is_ok(), "Failed to set gas oracle.");

    // let mailbox_set_hook = mailbox
    //     .methods()
    //     .set_required_hook(igp_hook.id())
    //     .call()
    //     .await;

    // assert!(
    //     mailbox_set_hook.is_ok(),
    //     "Failed to set required hook in Mailbox."
    // );

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
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "validatorAnnounce: 0x{}",
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

    ///////////////////////////////
    // Warp Route Initialization //
    /////////////////////////////

    // Initalize Warp Routes
    let init_res = warp_route
        .methods()
        .initialize(
            wallet_address,
            Bits256(mailbox_contract_id.hash().into()),
            WarpRouteTokenMode::COLLATERAL,
            post_dispatch_mock_address,
            "Ether".to_string(),
            "ETH".to_string(),
            18,
            10_000_000,
            Some(
                AssetId::from_str(
                    "0xf8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07",
                )
                .unwrap(),
            ),
        )
        .call()
        .await;

    assert!(init_res.is_ok(), "Failed to initialize Warp Route Native.");

    let bridged_init_res = warp_route_bridged
        .methods()
        .initialize(
            wallet_address,
            Bits256(mailbox_contract_id.hash().into()),
            WarpRouteTokenMode::BRIDGED,
            post_dispatch_mock_address,
            "FuelSepoliaUSDC".to_string(),
            "FST".to_string(),
            18,
            10_000_000,
            None,
        )
        .call()
        .await;

    assert!(
        bridged_init_res.is_ok(),
        "Failed to initialize Warp Route Bridged."
    );

    let set_ism_res = warp_route_bridged
        .methods()
        .set_ism(ism_id.clone())
        .call()
        .await;

    assert!(
        set_ism_res.is_ok(),
        "Failed to set ISM in Warp Route Bridged."
    );

    let set_ism_res = warp_route.methods().set_ism(ism_id.clone()).call().await;
    assert!(
        set_ism_res.is_ok(),
        "Failed to set ISM in Warp Route Collateral"
    );
    /////////////////////////////
    // Save contract addresses //
    /////////////////////////////

    let addresses = ContractAddresses::new(
        mailbox_contract_id.into(),
        post_dispatch_mock_id.into(),
        recipient_id.into(),
        test_ism_id.into(),
        merkle_tree_id.into(),
        igp_id.into(),
        igp_hook_id.into(),
        validator_id.into(),
        gas_oracle_id.into(),
<<<<<<< HEAD
        aggregation_ism_id.into(),
        domain_routing_ism_id.into(),
        fallback_domain_routing_ism_id.into(),
        message_id_multisig_ism_id.into(),
        merkle_root_multisig_ism_id.into(),
=======
        warp_route_id.into(),
        warp_route_bridged_id.into(),
>>>>>>> aca010ac2b0f273da1a137c7d6be4a08654d0d34
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
