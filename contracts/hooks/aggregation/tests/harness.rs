use fuels::{
    prelude::*,
    types::{Bits256, Identity, Salt},
};
use rand::Rng;

use hyperlane_core::HyperlaneMessage;
use std::str::FromStr;
use test_utils::get_revert_reason;

// Load abi from json
abigen!(
    Contract(
        name = "GasPaymaster",
        abi = "contracts/hooks/gas-paymaster/out/debug/gas-paymaster-abi.json"
    ),
    Contract(
        name = "GasOracle",
        abi = "contracts/gas-oracle/out/debug/gas-oracle-abi.json"
    ),
    Contract(
        name = "AggregationHook",
        abi = "contracts/hooks/aggregation/out/debug/aggregation-abi.json"
    ),
    Contract(
        name = "MerkleTreeHook",
        abi = "contracts/hooks/merkle-tree-hook/out/debug/merkle-tree-hook-abi.json"
    ),
    Contract(
        name = "PostDispatchHook",
        abi = "contracts/mocks/mock-post-dispatch/src/out/debug/mock-post-dispatch-abi.json"
    )
);

const TEST_REFUND_ADDRESS: &str =
    "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";

const TEST_DESTINATION_DOMAIN: u32 = 11111;
const TOKEN_EXCHANGE_RATE_SCALE: u128 = 1e19 as u128;
const BASE_ASSET_DECIMALS: u8 = 9;
const TEST_GAS_AMOUNT: u64 = 300000;
const MIN_METADATA_LENGTH: u64 = 98;

fn get_base_asset() -> AssetId {
    AssetId::BASE
}

fn create_mock_message() -> Bytes {
    let msg = HyperlaneMessage {
        version: 1,
        nonce: 1,
        origin: 1,
        sender: hyperlane_core::H256::from_str(TEST_REFUND_ADDRESS).unwrap(),
        destination: TEST_DESTINATION_DOMAIN,
        recipient: hyperlane_core::H256([0u8; 32]),
        body: vec![1, 2, 3, 4],
    };

    Bytes(hyperlane_core::Encode::to_vec(&msg))
}

// variant:        [0:2]     // Set to 1
// msg_value:      [2:34]    // Left as 0
// gas_limit:      [34:66]   // Left as 0
// refund_address: [66:98]   // Set to TEST_REFUND_ADDRESS
fn create_mock_metadata() -> Bytes {
    let mut metadata = vec![0u8; MIN_METADATA_LENGTH as usize];

    metadata[0] = 0;
    metadata[1] = 1;

    let mut gas_limit_bytes = [0u8; 32];

    gas_limit_bytes[24..32].copy_from_slice(&TEST_GAS_AMOUNT.to_be_bytes());
    metadata[34..66].copy_from_slice(&gas_limit_bytes);

    let refund_address = Address::from_str(TEST_REFUND_ADDRESS).unwrap();
    let refund_address_bytes: [u8; 32] = refund_address.into();
    metadata[66..98].copy_from_slice(&refund_address_bytes);

    Bytes(metadata)
}

async fn get_contract_instances() -> (
    AggregationHook<WalletUnlocked>,
    PostDispatchHook<WalletUnlocked>,
    PostDispatchHook<WalletUnlocked>,
    GasPaymaster<WalletUnlocked>,
    GasOracle<WalletUnlocked>,
) {
    let base_asset_id = get_base_asset();

    // Launch a local network and deploy the contract
    let mut wallets = launch_custom_provider_and_get_wallets(
        WalletsConfig::new_multiple_assets(
            1,
            vec![AssetConfig {
                id: base_asset_id,
                num_coins: 1,                 /* Single coin (UTXO) */
                coin_amount: 100_000_000_000, /* Amount per coin */
            }],
        ),
        None,
        None,
    )
    .await
    .unwrap();

    let wallet = wallets.pop().unwrap();

    let igp_id = Contract::load_from(
        "../gas-paymaster/out/debug/gas-paymaster.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    // Deploy aggregation hook
    let aggregation_id =
        Contract::load_from("./out/debug/aggregation.bin", LoadConfiguration::default())
            .unwrap()
            .deploy(&wallet, TxPolicies::default())
            .await
            .unwrap();

    // Deploy two mock hooks for testing
    let mock_hook1_id = Contract::load_from(
        "../../mocks/mock-post-dispatch/src/out/debug/mock-post-dispatch.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let salt = Salt::from(rand::thread_rng().gen::<[u8; 32]>());

    let mock_hook2_id = Contract::load_from(
        "../../mocks/mock-post-dispatch/src/out/debug/mock-post-dispatch.bin",
        LoadConfiguration::default().with_salt(salt),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let storage_gas_oracle_id = Contract::load_from(
        "../../gas-oracle/out/debug/gas-oracle.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let aggregation = AggregationHook::new(aggregation_id, wallet.clone());
    let mock_hook1 = PostDispatchHook::new(mock_hook1_id, wallet.clone());
    let mock_hook2 = PostDispatchHook::new(mock_hook2_id, wallet.clone());
    let storage_gas_oracle = GasOracle::new(storage_gas_oracle_id.clone(), wallet.clone());
    let igp = GasPaymaster::new(igp_id, wallet.clone());

    let owner_identity = Identity::Address(wallet.address().into());
    let owner_b256 = Bits256(Address::from(wallet.address()).into());

    igp.methods()
        .initialize(owner_b256, owner_b256)
        .call()
        .await
        .unwrap();

    storage_gas_oracle
        .methods()
        .initialize_ownership(owner_identity)
        .call()
        .await
        .unwrap();

    igp.methods()
        .set_gas_oracle(
            TEST_DESTINATION_DOMAIN,
            Bits256(storage_gas_oracle_id.hash().into()),
        )
        .call()
        .await
        .unwrap();

    let remote_gas_data_config = RemoteGasDataConfig {
        domain: TEST_DESTINATION_DOMAIN,
        remote_gas_data: RemoteGasData {
            domain: TEST_DESTINATION_DOMAIN,
            token_exchange_rate: TOKEN_EXCHANGE_RATE_SCALE, // 1.0 exchange rate (remote token has exact same value as local)
            gas_price: 1u64.into(),                         // 1 wei gas price
            token_decimals: BASE_ASSET_DECIMALS,            // same decimals as local
        },
    };
    storage_gas_oracle
        .methods()
        .set_remote_gas_data_configs(vec![remote_gas_data_config])
        .call()
        .await
        .unwrap();

    let hooks = vec![mock_hook1.contract_id().into(), igp.contract_id().into()];

    aggregation
        .methods()
        .initialize(owner_b256, hooks)
        .call()
        .await
        .unwrap();

    (aggregation, mock_hook1, mock_hook2, igp, storage_gas_oracle)
}

// ============ Initialization Test ============

#[tokio::test]
async fn test_initialization_reverts_if_already_initialized() {
    let (aggregation, mock_hook1, _, _, _) = get_contract_instances().await;
    let wallet = aggregation.account();

    let hooks = vec![mock_hook1.contract_id().into()];
    let owner_b256 = Bits256(Address::from(wallet.address()).into());

    // Second initialization should fail
    let result = aggregation
        .methods()
        .initialize(owner_b256, hooks)
        .call()
        .await;

    assert!(result.is_err());
    assert_eq!(
        get_revert_reason(result.err().unwrap()),
        "ContractAlreadyInitialized"
    );
}

// ============ Add Hook Tests ============
#[tokio::test]
async fn test_add_hook() {
    let (aggregation, _, mock_hook2, _, _) = get_contract_instances().await;

    let new_hook = mock_hook2.contract_id().into();
    aggregation
        .methods()
        .add_hook(new_hook)
        .call()
        .await
        .unwrap();

    let stored_hooks = aggregation
        .methods()
        .get_hooks()
        .call()
        .await
        .unwrap()
        .value;
    assert_eq!(stored_hooks.len(), 3);
    assert!(stored_hooks.contains(&new_hook));
}

// ============ Add Duplicate Hook Tests ============
#[tokio::test]
async fn test_add_hook_reverts_if_duplicate() {
    let (aggregation, mock_hook1, _, _, _) = get_contract_instances().await;

    let hook: ContractId = mock_hook1.contract_id().into();
    let result = aggregation.methods().add_hook(hook).call().await;

    assert!(result.is_err());
    assert_eq!(
        get_revert_reason(result.err().unwrap()),
        "HookAlreadyExists"
    );
}

// ============ Remove Hook Tests ============
#[tokio::test]
async fn test_remove_hook() {
    let (aggregation, mock_hook1, _, _, _) = get_contract_instances().await;

    // Remove first hook
    let hook_to_remove = mock_hook1.contract_id().into();
    aggregation
        .methods()
        .remove_hook(hook_to_remove)
        .call()
        .await
        .unwrap();

    let stored_hooks = aggregation
        .methods()
        .get_hooks()
        .call()
        .await
        .unwrap()
        .value;
    assert_eq!(stored_hooks.len(), 1);
    assert!(!stored_hooks.contains(&hook_to_remove));
}

// ============ Remove Hook Test with Non-Existent Hook ============
#[tokio::test]
async fn test_remove_hook_reverts_if_not_found() {
    let (aggregation, _, mock_hook2, _, _) = get_contract_instances().await;

    // Try to remove second hook that wasn't added
    let result = aggregation
        .methods()
        .remove_hook(mock_hook2.contract_id())
        .call()
        .await;

    assert!(result.is_err());
    assert_eq!(get_revert_reason(result.err().unwrap()), "HookNotFound");
}

// ============ Hook Type Tests ============
#[tokio::test]
async fn test_hook_type() {
    let (aggregation, _, _, _, _) = get_contract_instances().await;

    let hook_type = aggregation
        .methods()
        .hook_type()
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(hook_type, PostDispatchHookType::AGGREGATION);
}

// ============ Quote Dispatch Calculation Tests ============
#[tokio::test]
async fn test_quote_dispatch_calculation() {
    let (aggregation, mock_hook1, mock_hook2, igp, oracle) = get_contract_instances().await;
    let metadata = create_mock_metadata();
    let message = create_mock_message();

    let total_quote = aggregation
        .methods()
        .quote_dispatch(metadata, message)
        .with_contract_ids(&[
            igp.contract_id().clone(),
            oracle.contract_id().clone(),
            mock_hook1.contract_id().clone(),
            mock_hook2.contract_id().clone(),
        ])
        .call()
        .await
        .unwrap()
        .value;

    // Verify quote is non-zero (from IGP)
    assert!(total_quote > 0);
}

// ============ Post Dispatch Insufficient Payment Tests ============
#[tokio::test]
async fn test_post_dispatch_insufficient_payment() {
    let (aggregation, mock_hook1, mock_hook2, igp, oracle) = get_contract_instances().await;

    let metadata = create_mock_metadata();
    let message = create_mock_message();

    let result = aggregation
        .methods()
        .post_dispatch(metadata, message)
        .with_contract_ids(&[
            igp.contract_id().clone(),
            oracle.contract_id().clone(),
            mock_hook1.contract_id().clone(),
            mock_hook2.contract_id().clone(),
        ])
        .call_params(CallParameters::new(0, get_base_asset(), 1_000_000))
        .unwrap()
        .call()
        .await;

    assert!(result.is_err());
    assert_eq!(
        get_revert_reason(result.err().unwrap()),
        "IncorrectTotalHookPayment"
    );
}

// ============ Post Dispatch Test with Payment ============
#[tokio::test]
async fn test_post_dispatch_with_payment() {
    let (aggregation, mock_hook1, mock_hook2, igp, oracle) = get_contract_instances().await;
    let wallet = aggregation.account();
    let provider = wallet.provider().unwrap();

    let metadata = create_mock_metadata();
    let message = create_mock_message();

    let wallet_balance_before = provider
        .get_asset_balance(wallet.address(), get_base_asset())
        .await
        .unwrap();
    let igp_balance_before = provider
        .get_contract_asset_balance(igp.contract_id(), get_base_asset())
        .await
        .unwrap();

    let total_quote = aggregation
        .methods()
        .quote_dispatch(metadata.clone(), message.clone())
        .with_contract_ids(&[
            igp.contract_id().clone(),
            oracle.contract_id().clone(),
            mock_hook1.contract_id().clone(),
            mock_hook2.contract_id().clone(),
        ])
        .call()
        .await
        .unwrap()
        .value;

    aggregation
        .methods()
        .post_dispatch(metadata, message)
        .with_contract_ids(&[
            igp.contract_id().clone(),
            oracle.contract_id().clone(),
            mock_hook1.contract_id().clone(),
            mock_hook2.contract_id().clone(),
        ])
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .call_params(CallParameters::new(
            total_quote,
            get_base_asset(),
            1_000_000,
        ))
        .unwrap()
        .call()
        .await
        .unwrap();

    // Check final balances
    let wallet_balance_after = provider
        .get_asset_balance(wallet.address(), get_base_asset())
        .await
        .unwrap();
    let igp_balance_after = provider
        .get_contract_asset_balance(igp.contract_id(), get_base_asset())
        .await
        .unwrap();

    assert!(wallet_balance_before - wallet_balance_after >= total_quote);
    assert_eq!(igp_balance_after - igp_balance_before, total_quote);
}

// ============ Post Dispatch Test with Overpayment ============
#[tokio::test]
async fn test_post_dispatch_with_overpayment_should_fail() {
    let (aggregation, mock_hook1, mock_hook2, igp, oracle) = get_contract_instances().await;

    let metadata = create_mock_metadata();
    let message = create_mock_message();

    let total_quote = aggregation
        .methods()
        .quote_dispatch(metadata.clone(), message.clone())
        .with_contract_ids(&[
            igp.contract_id().clone(),
            oracle.contract_id().clone(),
            mock_hook1.contract_id().clone(),
            mock_hook2.contract_id().clone(),
        ])
        .call()
        .await
        .unwrap()
        .value;

    let overpayment = 10_000;
    let total_payment = total_quote + overpayment;

    let overpayment_result = aggregation
        .methods()
        .post_dispatch(metadata, message)
        .with_contract_ids(&[
            igp.contract_id().clone(),
            oracle.contract_id().clone(),
            mock_hook1.contract_id().clone(),
            mock_hook2.contract_id().clone(),
        ])
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .call_params(CallParameters::new(
            total_payment,
            get_base_asset(),
            1_000_000,
        ))
        .unwrap()
        .call()
        .await;

    assert!(overpayment_result.is_err());
    assert_eq!(
        get_revert_reason(overpayment_result.err().unwrap()),
        "IncorrectTotalHookPayment"
    );
}
