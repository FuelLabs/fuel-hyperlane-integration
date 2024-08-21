use fuels::{
    prelude::*,
    types::{Bits256, Identity},
};
use hyperlane_core::HyperlaneMessage;
use test_utils::get_revert_reason;

// Load abi from json
abigen!(
    Contract(
        name = "IGPHook",
        abi = "contracts/hooks/igp/out/debug/igp-hook-abi.json"
    ),
    Contract(
        name = "GasPaymaster",
        abi = "contracts/igp/gas-paymaster/out/debug/gas-paymaster-abi.json"
    ),
    Contract(
        name = "GasOracle",
        abi = "contracts/igp/gas-oracle/out/debug/gas-oracle-abi.json"
    )
);

const DESTINATION: u32 = 22;

async fn set_remote_gas_data(
    oracle: &GasOracle<WalletUnlocked>,
    remote_gas_data_config: RemoteGasDataConfig,
) -> Result<()> {
    oracle
        .methods()
        .set_remote_gas_data_configs(vec![remote_gas_data_config])
        .call()
        .await?;
    Ok(())
}

async fn get_balance(
    provider: &Provider,
    address: &Bech32Address,
) -> std::result::Result<u64, Error> {
    provider.get_asset_balance(address, AssetId::BASE).await
}

async fn get_contract_instance() -> (
    GasPaymaster<WalletUnlocked>,
    IGPHook<WalletUnlocked>,
    GasOracle<WalletUnlocked>,
) {
    let mut wallets = launch_custom_provider_and_get_wallets(
        WalletsConfig::new_multiple_assets(
            1,
            vec![AssetConfig {
                id: AssetId::default(),
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
        "../../igp/gas-paymaster/out/debug/gas-paymaster.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let hook_id = Contract::load_from("./out/debug/igp-hook.bin", LoadConfiguration::default())
        .unwrap()
        .deploy(&wallet, TxPolicies::default())
        .await
        .unwrap();

    let igp = GasPaymaster::new(igp_id.clone(), wallet.clone());
    let hook = IGPHook::new(hook_id.clone(), wallet.clone());

    let gas_oracle_id = Contract::load_from(
        "../../igp/gas-oracle/out/debug/gas-oracle.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let gas_oracle = GasOracle::new(gas_oracle_id.clone(), wallet.clone());
    let owner_identity = Identity::Address(wallet.address().into());

    igp.methods()
        .initialize_ownership(owner_identity)
        .call()
        .await
        .unwrap();

    gas_oracle
        .methods()
        .initialize_ownership(owner_identity)
        .call()
        .await
        .unwrap();

    igp.methods()
        .set_gas_oracle(DESTINATION, Bits256(gas_oracle_id.hash().into()))
        .call()
        .await
        .unwrap();

    hook.methods()
        .initialize(igp_id.clone())
        .call()
        .await
        .unwrap();

    (igp, hook, gas_oracle)
}

fn create_mock_message() -> HyperlaneMessage {
    HyperlaneMessage {
        version: 1,
        nonce: 1,
        origin: 1,
        sender: hyperlane_core::H256([0u8; 32]),
        destination: DESTINATION,
        recipient: hyperlane_core::H256([0u8; 32]),
        body: vec![1, 2, 3, 4],
    }
}

#[tokio::test]
async fn test_module_type() {
    let (_, hook, _) = get_contract_instance().await;

    let hook_type = hook.methods().hook_type().call().await.unwrap().value;
    assert_eq!(hook_type, PostDispatchHookType::INTERCHAIN_GAS_PAYMASTER);
}
#[tokio::test]
async fn test_supports_metadata() {
    let (_, hook, _) = get_contract_instance().await;

    let metadata = Bytes(vec![0]);
    let supports = hook
        .methods()
        .supports_metadata(metadata)
        .call()
        .await
        .unwrap()
        .value;

    assert!(!supports);
}

#[tokio::test]
async fn test_quote_dispatch() {
    let (igp, hook, oracle) = get_contract_instance().await;
    let mock_message = create_mock_message();
    let empty_metadata = Bytes(vec![]);

    let message_bytes = hyperlane_core::Encode::to_vec(&mock_message);

    let quote = hook
        .methods()
        .quote_dispatch(empty_metadata, Bytes(message_bytes))
        .with_contract_ids(&[
            hook.contract_id().clone(),
            igp.contract_id().clone(),
            oracle.contract_id().clone().clone(),
        ])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(quote, 0);
}

#[tokio::test]
async fn test_post_dispatch() {
    let (igp, hook, oracle) = get_contract_instance().await;
    let mock_message = create_mock_message();
    let metadata = Bytes(vec![0]);

    let wallet = igp.account();
    let provider = wallet.provider().unwrap();
    let wallet_address_balance_before = get_balance(provider, wallet.address()).await.unwrap();
    println!("{}", wallet_address_balance_before);

    let message_bytes = hyperlane_core::Encode::to_vec(&mock_message);

    hook.methods()
        .post_dispatch(metadata, Bytes(message_bytes))
        .with_contract_ids(&[
            hook.contract_id().clone(),
            igp.contract_id().clone(),
            oracle.contract_id().clone(),
        ])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap();

    let wallet_address_balance_after = get_balance(provider, wallet.address()).await.unwrap();
    let diff = wallet_address_balance_before - wallet_address_balance_after;
    assert_eq!(diff, 0);
}

#[tokio::test]
async fn test_post_dispatch_with_insufficient_payment() {
    let (igp, hook, oracle) = get_contract_instance().await;
    let mock_message = create_mock_message();
    let metadata = Bytes(vec![0]);

    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: DESTINATION,
            remote_gas_data: RemoteGasData {
                token_exchange_rate: 1e19 as u128, // 1.0 exchange rate (remote token has exact same value as local)
                gas_price: 1u64.into(),            // 1 wei gas price
                token_decimals: 9,                 // same decimals as local
            },
        },
    )
    .await
    .unwrap();

    let message_bytes = hyperlane_core::Encode::to_vec(&mock_message);

    let quote = hook
        .methods()
        .quote_dispatch(metadata.clone(), Bytes(message_bytes.clone()))
        .with_contract_ids(&[
            hook.contract_id().clone(),
            igp.contract_id().clone(),
            oracle.contract_id().clone(),
        ])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    // Set the call parameters with insufficient payment
    let call_params = CallParameters::new(quote - 1, AssetId::default(), 1_000_000);

    let result = hook
        .methods()
        .post_dispatch(metadata, Bytes(message_bytes))
        .call_params(call_params)
        .unwrap()
        .with_contracts(&[&hook, &igp, &oracle])
        .call()
        .await;

    assert!(result.is_err());
    assert_eq!(
        get_revert_reason(result.err().unwrap()),
        "InsufficientGasPayment"
    );
}

#[tokio::test]
async fn test_quote_dispatch_error_propagation() {
    let (igp, hook, _) = get_contract_instance().await;
    let metadata = Bytes(vec![0]);
    let mock_message = create_mock_message();
    let message_bytes = hyperlane_core::Encode::to_vec(&mock_message);

    let call = hook
        .methods()
        .quote_dispatch(metadata, Bytes(message_bytes))
        .with_contract_ids(&[igp.contract_id().clone()]) //oracle contract is required when igp is called, but not provided
        .simulate(Execution::StateReadOnly)
        .await;

    assert_eq!(
        get_revert_reason(call.err().unwrap()),
        "ContractNotInInputs"
    )
}
