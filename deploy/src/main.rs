use alloy::signers::{
    k256::{ecdsa::SigningKey, SecretKey as SepoliaPrivateKey},
    local::PrivateKeySigner,
};
use core::panic;
use fuels::types::{EvmAddress, Identity};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
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
        name = "ValidatorAnnounce",
        abi = "contracts/validator-announce/out/debug/validator-announce-abi.json",
    ),
    Contract(
        name = "GasOracle",
        abi = "contracts/gas-oracle/out/debug/gas-oracle-abi.json",
    ),
    Contract(
        name = "GasPaymaster",
        abi = "contracts/hooks/gas-paymaster/out/debug/gas-paymaster-abi.json",
    ),
    Contract(
        name = "TestRecipient",
        abi = "contracts/test/msg-recipient-test/out/debug/msg-recipient-test-abi.json",
    ),
    Contract(
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
    ),
    Contract(
        name = "WarpRoute",
        abi = "contracts/warp-route/out/debug/warp-route-abi.json",
    ),
    Contract(
        name = "SRC20Test",
        abi = "contracts/test/src20-test/out/debug/src20-test-abi.json",
    ),
    Contract(
        name = "ProtocolFee",
        abi = "contracts/hooks/protocol-fee/out/debug/protocol-fee-abi.json",
    ),
    Contract(
        name = "AggregationHook",
        abi = "contracts/hooks/aggregation/out/debug/aggregation-abi.json",
    ),
    Contract(
      name = "PausableHook",
      abi = "contracts/hooks/pausable-hook/out/debug/pausable-hook-abi.json",
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
    #[serde(rename = "validatorAnnounce")]
    va: String,
    #[serde(rename = "gasOracle")]
    gas_oracle: String,
    #[serde(rename = "aggregationISM")]
    aggregation_ism: String,
    #[serde(rename = "domainRoutingISM")]
    domain_routing_ism: String,
    #[serde(rename = "fallbackDomainRoutingISM")]
    fallback_domain_routing_ism: String,
    #[serde(rename = "messageIdMultisigISM1")]
    message_id_multisig_ism_1: String,
    #[serde(rename = "merkleRootMultisigISM1")]
    merkle_root_multisig_ism_1: String,
    #[serde(rename = "messageIdMultisigISM3")]
    message_id_multisig_ism_3: String,
    #[serde(rename = "merkleRootMultisigISM3")]
    merkle_root_multisig_ism_3: String,
    #[serde(rename = "warpRouteNative")]
    warp_route_native: String,
    #[serde(rename = "warpRouteSynthetic")]
    warp_route_synthetic: String,
    #[serde(rename = "warpRouteCollateral")]
    warp_route_collateral: String,
    #[serde(rename = "collateralTokenContract")]
    collateral_asset_contract_id: String,
    #[serde(rename = "testCollateralAsset")]
    collateral_asset_id: String,
    #[serde(rename = "aggregationHook")]
    aggregation_hook: String,
    #[serde(rename = "pausableHook")]
    pausable_hook: String,
    #[serde(rename = "protocolFee")]
    protocol_fee: String,
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
        va: ContractId,
        gas_oracle: ContractId,
        aggregation_ism: ContractId,
        domain_routing_ism: ContractId,
        fallback_domain_routing_ism: ContractId,
        message_id_multisig_ism_1: ContractId,
        merkle_root_multisig_ism_1: ContractId,
        message_id_multisig_ism_3: ContractId,
        merkle_root_multisig_ism_3: ContractId,
        warp_route_native: ContractId,
        warp_route_synthetic: ContractId,
        warp_route_collateral: ContractId,
        collateral_asset_contract_id: ContractId,
        collateral_asset_id: AssetId,
        aggregation_hook: ContractId,
        pausable_hook: ContractId,
        protocol_fee: ContractId,
    ) -> Self {
        Self {
            mailbox: format!("0x{}", mailbox),
            post_dispatch: format!("0x{}", post_dispatch),
            recipient: format!("0x{}", recipient),
            ism: format!("0x{}", ism),
            merkle_tree_hook: format!("0x{}", merkle_tree_hook),
            igp: format!("0x{}", igp),
            va: format!("0x{}", va),
            gas_oracle: format!("0x{}", gas_oracle),
            aggregation_ism: format!("0x{}", aggregation_ism),
            domain_routing_ism: format!("0x{}", domain_routing_ism),
            fallback_domain_routing_ism: format!("0x{}", fallback_domain_routing_ism),
            message_id_multisig_ism_1: format!("0x{}", message_id_multisig_ism_1),
            merkle_root_multisig_ism_1: format!("0x{}", merkle_root_multisig_ism_1),
            message_id_multisig_ism_3: format!("0x{}", message_id_multisig_ism_3),
            merkle_root_multisig_ism_3: format!("0x{}", merkle_root_multisig_ism_3),
            warp_route_native: format!("0x{}", warp_route_native),
            warp_route_synthetic: format!("0x{}", warp_route_synthetic),
            warp_route_collateral: format!("0x{}", warp_route_collateral),
            collateral_asset_id: format!("0x{}", collateral_asset_id),
            collateral_asset_contract_id: format!("0x{}", collateral_asset_contract_id),
            aggregation_hook: format!("0x{}", aggregation_hook),
            pausable_hook: format!("0x{}", pausable_hook),
            protocol_fee: format!("0x{}", protocol_fee),
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
        "interchainSecurityModule: 0x{}",
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
        "AggregationISM: 0x{}",
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
        "DomainRoutingISM: 0x{}",
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
        "FallbackDomainRoutingISM: 0x{}",
        ContractId::from(fallback_domain_routing_ism_id.clone())
    );

    let configurables = MessageIdMultisigISMConfigurables::default()
        .with_THRESHOLD(1)
        .unwrap();

    let message_id_multisig_ism_id_1 = Contract::load_from(
        "../contracts/ism/multisig/message-id-multisig-ism/out/debug/message-id-multisig-ism.bin",
        config.clone().with_configurables(configurables),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "MessageIdMultisigISM 1/x: 0x{}",
        ContractId::from(message_id_multisig_ism_id_1.clone())
    );

    let configurables = MessageIdMultisigISMConfigurables::default()
        .with_THRESHOLD(3)
        .unwrap();

    let message_id_multisig_ism_id_3 = Contract::load_from(
        "../contracts/ism/multisig/message-id-multisig-ism/out/debug/message-id-multisig-ism.bin",
        config.clone().with_configurables(configurables),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "MessageIdMultisigISM 3/x: 0x{}",
        ContractId::from(message_id_multisig_ism_id_3.clone())
    );

    let configurables = MerkleRootMultisigISMConfigurables::default()
        .with_THRESHOLD(1)
        .unwrap();

    let merkle_root_multisig_ism_id_1 = Contract::load_from(
        "../contracts/ism/multisig/merkle-root-multisig-ism/out/debug/merkle-root-multisig-ism.bin",
        config.clone().with_configurables(configurables),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "MerkleRootMultisigISM 1/x: 0x{}",
        ContractId::from(merkle_root_multisig_ism_id_1.clone())
    );

    let configurables = MerkleRootMultisigISMConfigurables::default()
        .with_THRESHOLD(3)
        .unwrap();

    let merkle_root_multisig_ism_id_3 = Contract::load_from(
        "../contracts/ism/multisig/merkle-root-multisig-ism/out/debug/merkle-root-multisig-ism.bin",
        config.clone().with_configurables(configurables),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "MerkleRootMultisigISM 3/x: 0x{}",
        ContractId::from(merkle_root_multisig_ism_id_3.clone())
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

    /////////////////////////////////
    // Aggregation Hook Deployment //
    /////////////////////////////////

    let aggregation_hook_id = Contract::load_from(
        "../contracts/hooks/aggregation/out/debug/aggregation.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "aggregationHook: 0x{}",
        ContractId::from(aggregation_hook_id.clone())
    );

    ///////////////////////////////
    // Pausable Hook Deployment //
    //////////////////////////////

    let pausable_hook_id = Contract::load_from(
        "../contracts/hooks/pausable-hook/out/debug/pausable-hook.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "pausableHook: 0x{}",
        ContractId::from(pausable_hook_id.clone())
    );

    //////////////////////////////////
    // Protocol Fee Hook Deployment //
    //////////////////////////////////

    const MAX_PROTOCOL_FEE: u64 = 10;

    let protocol_fee_configurables = ProtocolFeeConfigurables::default()
        .with_MAX_PROTOCOL_FEE(MAX_PROTOCOL_FEE)
        .unwrap();

    let protocol_fee_hook_id = Contract::load_from(
        "../contracts/hooks/protocol-fee/out/debug/protocol-fee.bin",
        config
            .clone()
            .with_configurables(protocol_fee_configurables),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "protocolFee: 0x{}",
        ContractId::from(protocol_fee_hook_id.clone())
    );

    /////////////////////////////////////////
    // Gas Paymaster Components Deployment //
    /////////////////////////////////////////

    // Gas Oracle deployment
    let gas_oracle_id = Contract::load_from(
        "../contracts/gas-oracle/out/debug/gas-oracle.bin",
        config.clone(),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "storageGasOracle: 0x{}",
        ContractId::from(gas_oracle_id.clone())
    );

    let igp_configurables = GasPaymasterConfigurables::default()
        .with_TOKEN_EXCHANGE_RATE_SCALE(15_000_000_000_000)
        .unwrap()
        .with_DEFAULT_GAS_AMOUNT(5000)
        .unwrap();

    // IGP deployment
    let igp_id = Contract::load_from(
        "../contracts/hooks/gas-paymaster/out/debug/gas-paymaster.bin",
        config.clone().with_configurables(igp_configurables),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "interchainGasPaymaster: 0x{}",
        ContractId::from(igp_id.clone())
    );

    ///////////////////////////
    // Warp Route Deployment //
    ///////////////////////////

    //Collateral Token
    let collateral_token_salt = Salt::from(rand::thread_rng().gen::<[u8; 32]>());
    let collateral_asset_contract_id = Contract::load_from(
        "../contracts/test/src20-test/out/debug/src20-test.bin",
        config.clone().with_salt(collateral_token_salt),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    let collateral_token_contract =
        SRC20Test::new(collateral_asset_contract_id.clone(), fuel_wallet.clone());

    let _ = collateral_token_contract
        .methods()
        .mint(
            Identity::Address(fuel_wallet.address().into()),
            Some(Bits256::zeroed()),
            2 * 10_u64.pow(18),
        )
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .call()
        .await
        .unwrap();

    println!(
        "collateralTokenContractId: {}",
        collateral_token_contract.contract_id()
    );

    let collateral_asset_id = collateral_asset_contract_id.asset_id(&Bits256::zeroed());
    println!("collateralAssetId: 0x{}", collateral_asset_id.clone());

    //Collateral WR
    let collateral_salt = Salt::from(rand::thread_rng().gen::<[u8; 32]>());
    let warp_route_collateral_id = Contract::load_from(
        "../contracts/warp-route/out/debug/warp-route.bin",
        config.clone().with_salt(collateral_salt),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "warpRouteCollateral: 0x{}",
        ContractId::from(warp_route_collateral_id.clone())
    );

    // Native WR
    let native_salt = Salt::from(rand::thread_rng().gen::<[u8; 32]>());
    let warp_route_native_id = Contract::load_from(
        "../contracts/warp-route/out/debug/warp-route.bin",
        config.clone().with_salt(native_salt),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "warpRouteNative: 0x{}",
        ContractId::from(warp_route_native_id.clone())
    );

    // Synthetic WR
    let synthetic_salt = Salt::from(rand::thread_rng().gen::<[u8; 32]>());
    let warp_route_synthetic_id = Contract::load_from(
        "../contracts/warp-route/out/debug/warp-route.bin",
        config.clone().with_salt(synthetic_salt),
    )
    .unwrap()
    .deploy(&fuel_wallet, TxPolicies::default())
    .await
    .unwrap();

    println!(
        "warpRouteSynthetic: 0x{}",
        ContractId::from(warp_route_synthetic_id.clone())
    );

    ///////////////////////////
    // Instantiate Contracts //
    ///////////////////////////

    let post_dispatch_mock = PostDispatch::new(post_dispatch_mock_id.clone(), fuel_wallet.clone());
    let mailbox = Mailbox::new(mailbox_contract_id.clone(), fuel_wallet.clone());
    let merkle_tree_hook = MerkleTreeHook::new(merkle_tree_id.clone(), fuel_wallet.clone());
    let aggregation_hook = AggregationHook::new(aggregation_hook_id.clone(), fuel_wallet.clone());
    let pausable_hook = PausableHook::new(pausable_hook_id.clone(), fuel_wallet.clone());
    let protocol_fee_hook = ProtocolFee::new(protocol_fee_hook_id.clone(), fuel_wallet.clone());
    let gas_oracle = GasOracle::new(gas_oracle_id.clone(), fuel_wallet.clone());
    let igp = GasPaymaster::new(igp_id.clone(), fuel_wallet.clone());
    let test_recipient = TestRecipient::new(recipient_id.clone(), fuel_wallet.clone());
    let aggregation_ism = AggregationISM::new(aggregation_ism_id.clone(), fuel_wallet.clone());
    let domain_routing_ism =
        DomainRoutingISM::new(domain_routing_ism_id.clone(), fuel_wallet.clone());
    let fallback_domain_routing_ism =
        FallbackDomainRoutingISM::new(fallback_domain_routing_ism_id.clone(), fuel_wallet.clone());
    let message_id_multisig_ism_1 =
        MessageIdMultisigISM::new(message_id_multisig_ism_id_1.clone(), fuel_wallet.clone());
    let merkle_root_multisig_ism_1 =
        MerkleRootMultisigISM::new(merkle_root_multisig_ism_id_1.clone(), fuel_wallet.clone());
    let message_id_multisig_ism_3 =
        MessageIdMultisigISM::new(message_id_multisig_ism_id_3.clone(), fuel_wallet.clone());
    let merkle_root_multisig_ism_3 =
        MerkleRootMultisigISM::new(merkle_root_multisig_ism_id_3.clone(), fuel_wallet.clone());
    let warp_route_native = WarpRoute::new(warp_route_native_id.clone(), fuel_wallet.clone());
    let warp_route_synthetic = WarpRoute::new(warp_route_synthetic_id.clone(), fuel_wallet.clone());
    let warp_route_collateral =
        WarpRoute::new(warp_route_collateral_id.clone(), fuel_wallet.clone());

    let wallet_identity = Identity::from(fuel_wallet.address());
    let test_ism_address = Bits256(ContractId::from(test_ism_id.clone()).into());
    let mailbox_address = Bits256(ContractId::from(mailbox_contract_id.clone()).into());

    /////////////////////
    // Initialize ISMs //
    /////////////////////

    // Aggregation ISM
    let aggregation_ism_threshold = 2;
    let test_isms_to_aggregate = vec![
        ContractId::from(test_ism_id.clone()),
        ContractId::from(test_ism_id.clone()),
    ];
    let init_res = aggregation_ism
        .methods()
        .initialize(
            wallet_identity,
            test_isms_to_aggregate,
            aggregation_ism_threshold,
        )
        .call()
        .await;

    assert!(init_res.is_ok(), "Failed to initialize Aggregation ISM.");

    // Domain Routing ISM
    let init_res = domain_routing_ism
        .methods()
        .initialize_with_domains(
            wallet_identity,
            vec![11155111, 84532],
            vec![test_ism_address, test_ism_address],
        )
        .call()
        .await;

    assert!(init_res.is_ok(), "Failed to initialize Domain Routing ISM.");

    // Fallback Domain Routing ISM
    let init_res = fallback_domain_routing_ism
        .methods()
        .initialize(wallet_identity, mailbox_address)
        .call()
        .await;

    assert!(
        init_res.is_ok(),
        "Failed to initialize Fallback Domain Routing ISM."
    );

    // Multisig ISMs validator setup
    // (Threshold is set during contract deployment)

    let evm_pk_vars = vec![
        "SEPOLIA_PRIVATE_KEY_1",
        "SEPOLIA_PRIVATE_KEY_2",
        "SEPOLIA_PRIVATE_KEY_3",
    ];

    let validators_to_enroll = evm_pk_vars
        .iter()
        .map(|pk| {
            let secret_key = SepoliaPrivateKey::from_slice(
                &hex::decode(env::var(pk).unwrap_or_else(|_| panic!("{:?} must be set", pk)))
                    .unwrap(),
            )
            .unwrap();
            let signing_key = SigningKey::from(secret_key);
            let signer = PrivateKeySigner::from_signing_key(signing_key);
            EvmAddress::from(Bits256(signer.address().into_word().0))
        })
        .collect::<Vec<_>>();

    // Message ID Multisig ISM, threshold 1
    let init_res = message_id_multisig_ism_1
        .methods()
        .initialize(validators_to_enroll.clone())
        .call()
        .await;
    assert!(
        init_res.is_ok(),
        "Failed to initailize Message ID Multisig ISM, threshold 1."
    );

    // Message ID Multisig ISM, threshold 3
    let init_res = message_id_multisig_ism_3
        .methods()
        .initialize(validators_to_enroll.clone())
        .call()
        .await;
    assert!(
        init_res.is_ok(),
        "Failed to initailize Message ID Multisig ISM, threshold 3."
    );

    // Merkle Root Multisig ISM, threshold 1
    let init_res = merkle_root_multisig_ism_1
        .methods()
        .initialize(validators_to_enroll.clone())
        .call()
        .await;
    assert!(
        init_res.is_ok(),
        "Failed to initailize Merkle Root Multisig ISM, threshold 1."
    );

    // Merkle Root Multisig ISM, threshold 3
    let init_res = merkle_root_multisig_ism_3
        .methods()
        .initialize(validators_to_enroll.clone())
        .call()
        .await;
    assert!(
        init_res.is_ok(),
        "Failed to initailize Merkle Root Multisig ISM, threshold 3."
    );

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
            wallet_identity,
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
        .initialize(wallet_identity, wallet_identity)
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize IGP.");

    // Gas Oracle
    let set_gas_data_res = gas_oracle
        .methods()
        .set_remote_gas_data_configs(vec![RemoteGasDataConfig {
            domain: 84532,
            remote_gas_data: RemoteGasData {
                domain: 84532,
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
        .set_gas_oracle(84532, Bits256(gas_oracle_id.hash().into()))
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
    // Pausable Hook Initialization //
    ///////////////////////////////
    let init_res = pausable_hook
        .methods()
        .initialize_ownership(owner_identity)
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize Pausable Hook.");
    println!("Pausable Hook initialized.");

    //////////////////////////////////////
    // Protocol Fee Hook Initialization //
    //////////////////////////////////////

    let protocol_fee = 1;

    let init_res = protocol_fee_hook
        .methods()
        .initialize(protocol_fee, owner_identity, owner_identity)
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize Protocol Fee Hook.");
    println!("Protocol Fee Hook initialized.");

    //////////////////////////////////////
    // Aggregation Hook Initialization //
    //////////////////////////////////////

    let hooks = vec![post_dispatch_mock_id.clone().into(), igp_id.clone().into()];

    let init_res = aggregation_hook
        .methods()
        .initialize(wallet_identity, hooks)
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize Aggregation Hook.");
    println!("Aggregation Hook initialized.");

    ///////////////////////////////
    // Warp Route Initialization //
    ///////////////////////////////

    // Initalize Warp Routes
    let native_init_res = warp_route_native
        .methods()
        .initialize(
            wallet_identity,
            Bits256(mailbox_contract_id.hash().into()),
            WarpRouteTokenMode::NATIVE,
            post_dispatch_mock_address,
            test_ism_address,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .call()
        .await;

    assert!(
        native_init_res.is_ok(),
        "Failed to initialize Warp Route Native."
    );

    let synthetic_init_res = warp_route_synthetic
        .methods()
        .initialize(
            wallet_identity,
            Bits256(mailbox_contract_id.hash().into()),
            WarpRouteTokenMode::SYNTHETIC,
            post_dispatch_mock_address,
            test_ism_address,
            Some("FuelSepoliaUSDC".to_string()),
            Some("FST".to_string()),
            Some(6),
            Some(10_000_000),
            None,
            None,
        )
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .call()
        .await;

    assert!(
        synthetic_init_res.is_ok(),
        "Failed to initialize Warp Route Synthetic."
    );

    let collateral_init_res = warp_route_collateral
        .methods()
        .initialize(
            wallet_identity,
            Bits256(mailbox_contract_id.hash().into()),
            WarpRouteTokenMode::COLLATERAL,
            post_dispatch_mock_address,
            test_ism_address,
            None,
            None,
            None,
            None,
            Some(collateral_asset_id),
            Some(Bits256(collateral_asset_contract_id.hash().into())),
        )
        .with_contract_ids(&[collateral_asset_contract_id.clone()])
        .call()
        .await;

    assert!(
        collateral_init_res.is_ok(),
        "Failed to initialize Warp Route Collateral."
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
        validator_id.into(),
        gas_oracle_id.into(),
        aggregation_ism_id.into(),
        domain_routing_ism_id.into(),
        fallback_domain_routing_ism_id.into(),
        message_id_multisig_ism_id_1.into(),
        merkle_root_multisig_ism_id_1.into(),
        message_id_multisig_ism_id_3.into(),
        merkle_root_multisig_ism_id_3.into(),
        warp_route_native_id.into(),
        warp_route_synthetic_id.into(),
        warp_route_collateral_id.into(),
        collateral_asset_contract_id.into(),
        collateral_asset_id,
        aggregation_hook_id.into(),
        pausable_hook_id.into(),
        protocol_fee_hook_id.into(),
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
