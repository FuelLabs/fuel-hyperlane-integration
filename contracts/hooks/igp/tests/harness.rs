use fuels::{
    prelude::*,
    types::{Bits256, Identity},
};
use hyperlane_core::HyperlaneMessage;

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

    // Initialize the gas oracle
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
        .simulate()
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

    // Ensure the IGP contract is correctly handling the dispatch
    hook.methods()
        .post_dispatch(metadata, Bytes(message_bytes))
        .with_contract_ids(&[
            hook.contract_id().clone(),
            igp.contract_id().clone(),
            oracle.contract_id().clone(),
        ])
        .simulate()
        .await
        .unwrap();

    let wallet_address_balance_after = get_balance(provider, wallet.address()).await.unwrap();
    let diff = wallet_address_balance_before - wallet_address_balance_after;
    assert_eq!(diff, 0);
}
