use abigen_bindings::gas_oracle_mod::interfaces::gas_oracle::RemoteGasData;
use fuels::{
    prelude::*,
    types::{Bits256, Identity},
};
use hyperlane_core::HyperlaneMessage;
use std::str::FromStr;
use test_utils::{funded_wallet_with_private_key, get_revert_reason};

// Load abi from json
abigen!(
    Contract(
        name = "GasPaymaster",
        abi = "contracts/hooks/gas-paymaster/out/debug/gas-paymaster-abi.json"
    ),
    Contract(
        name = "GasOracle",
        abi = "contracts/gas-oracle/out/debug/gas-oracle-abi.json"
    )
);

const NON_OWNER_PRIVATE_KEY: &str =
    "0xde97d8624a438121b86a1956544bd72ed68cd69f2c99555b08b1e8c51ffd511c";

const TEST_REFUND_ADDRESS: &str =
    "0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";

const TEST_DESTINATION_DOMAIN: u32 = 11111;
const TOKEN_EXCHANGE_RATE_SCALE: u128 = 1e19 as u128;
const BASE_ASSET_DECIMALS: u8 = 9;
const TEST_GAS_AMOUNT: u64 = 300000;
const MIN_METADATA_LENGTH: u64 = 98;

fn get_base_asset() -> AssetId {
    AssetId::BASE
}

fn get_non_base_asset() -> AssetId {
    AssetId::new([1u8; 32])
}

fn create_mock_message() -> HyperlaneMessage {
    HyperlaneMessage {
        version: 1,
        nonce: 1,
        origin: 1,
        sender: hyperlane_core::H256::from_str(TEST_REFUND_ADDRESS).unwrap(),
        destination: TEST_DESTINATION_DOMAIN,
        recipient: hyperlane_core::H256([0u8; 32]),
        body: vec![1, 2, 3, 4],
    }
}

// variant:        [0:2]     // Set to 1
// msg_value:      [2:34]    // Left as 0
// gas_limit:      [34:66]   // Left as 0
// refund_address: [66:98]   // Set to wallet address
fn create_mock_metadata(wallet: &WalletUnlocked) -> Bytes {
    let mut metadata = vec![0u8; MIN_METADATA_LENGTH as usize];

    metadata[0] = 0;
    metadata[1] = 1;

    let mut gas_limit_bytes = [0u8; 32];

    gas_limit_bytes[24..32].copy_from_slice(&TEST_GAS_AMOUNT.to_be_bytes());
    metadata[34..66].copy_from_slice(&gas_limit_bytes);

    let wallet_bytes: [u8; 32] = wallet.address().hash().into();
    metadata[66..98].copy_from_slice(&wallet_bytes);

    Bytes(metadata)
}

async fn get_contract_instances() -> (GasPaymaster<WalletUnlocked>, GasOracle<WalletUnlocked>) {
    let non_base_asset_id = get_non_base_asset();
    let base_asset_id = get_base_asset();

    // Launch a local network and deploy the contract
    let mut wallets = launch_custom_provider_and_get_wallets(
        WalletsConfig::new_multiple_assets(
            1,
            vec![
                AssetConfig {
                    id: base_asset_id,
                    num_coins: 1,                 /* Single coin (UTXO) */
                    coin_amount: 100_000_000_000, /* Amount per coin */
                },
                AssetConfig {
                    id: non_base_asset_id,
                    num_coins: 1,               /* Single coin (UTXO) */
                    coin_amount: 1_000_000_000, /* Amount per coin */
                },
            ],
        ),
        None,
        None,
    )
    .await
    .unwrap();

    let wallet = wallets.pop().unwrap();

    let igp_id = Contract::load_from(
        "./out/debug/gas-paymaster.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let igp = GasPaymaster::new(igp_id, wallet.clone());

    let owner_identity = Identity::Address(wallet.address().into());

    igp.methods()
        .initialize(
            Bits256(Address::from(wallet.address()).into()),
            Bits256(Address::from(wallet.address()).into()),
        )
        .call()
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
    let storage_gas_oracle = GasOracle::new(storage_gas_oracle_id.clone(), wallet);

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

    (igp, storage_gas_oracle)
}

// ============ claim ============

#[tokio::test]
async fn test_claim() {
    let (igp, _) = get_contract_instances().await;

    let amount = 12345677u64;
    let base_asset_id = get_base_asset();

    let wallet = igp.account();

    let (_, _) = wallet
        .force_transfer_to_contract(
            igp.contract_id(),
            amount,
            base_asset_id,
            TxPolicies::default(),
        )
        .await
        .unwrap();

    let provider = wallet.provider().unwrap();

    let beneficiary_balance_before = get_balance(provider, &wallet.address().into())
        .await
        .unwrap();
    let igp_balance_before = get_contract_balance(provider, igp.contract_id())
        .await
        .unwrap();

    // Claim the tokens
    let call = igp
        .methods()
        .claim(Some(get_base_asset()))
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .call()
        .await
        .unwrap();

    let events = call.decode_logs_with_type::<ClaimEvent>().unwrap();
    assert_eq!(
        events,
        vec![ClaimEvent {
            beneficiary: Identity::Address(Address::from(wallet.address())),
            amount,
        }]
    );

    let beneficiary_balance_after = get_balance(provider, &wallet.address().into())
        .await
        .unwrap();
    let igp_balance_after = get_contract_balance(provider, igp.contract_id())
        .await
        .unwrap();

    assert_eq!(igp_balance_before - igp_balance_after, amount);
    assert_eq!(
        beneficiary_balance_after - beneficiary_balance_before + 1,
        amount
    );
}

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

async fn get_contract_balance(
    provider: &Provider,
    contract_id: &Bech32ContractId,
) -> std::result::Result<u64, Error> {
    provider
        .get_contract_asset_balance(contract_id, AssetId::BASE)
        .await
}

// ============ Initial Beneficiary ============
#[tokio::test]
async fn test_initial_beneficiary() {
    let (igp, _) = get_contract_instances().await;

    let wallet = igp.account();
    let expected_beneficiary: Identity = Identity::Address(wallet.address().into());

    let beneficiary = igp
        .methods()
        .beneficiary()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(beneficiary, expected_beneficiary);
}

// ============ pay_for_gas ============
#[tokio::test]
async fn test_pay_for_gas() {
    let (igp, oracle) = get_contract_instances().await;

    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: RemoteGasData {
                domain: TEST_DESTINATION_DOMAIN,
                token_exchange_rate: TOKEN_EXCHANGE_RATE_SCALE, // 1.0 exchange rate (remote token has exact same value as local)
                gas_price: 1u64.into(),                         // 1 wei gas price
                token_decimals: BASE_ASSET_DECIMALS,            // same decimals as local
            },
        },
    )
    .await
    .unwrap();

    let wallet = igp.account();
    let provider = wallet.provider().unwrap();

    let refund_address = Address::from_str(TEST_REFUND_ADDRESS).unwrap();

    let igp_balance_before = get_contract_balance(provider, igp.contract_id())
        .await
        .unwrap();
    let refund_address_balance_before =
        get_balance(provider, &refund_address.into()).await.unwrap();

    let quote = igp
        .methods()
        .quote_gas_payment(TEST_DESTINATION_DOMAIN, TEST_GAS_AMOUNT)
        .with_contract_ids(&[oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    let overpayment: u64 = 54321u64;

    let base_asset_id = get_base_asset();
    let call_params = CallParameters::new(quote + overpayment, base_asset_id, 1_000_000);
    let mock_message = create_mock_message();
    let message_id = mock_message.id();
    let destination_domain = mock_message.destination;

    let call = igp
        .methods()
        .pay_for_gas(
            Bits256(message_id.into()),
            destination_domain,
            TEST_GAS_AMOUNT,
            Identity::Address(refund_address),
        )
        .call_params(call_params)
        .unwrap()
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .determine_missing_contracts(Some(2))
        .await
        .unwrap()
        .call()
        .await
        .unwrap();

    // Ensure balances are what's expected
    let igp_balance_after = get_contract_balance(provider, igp.contract_id())
        .await
        .unwrap();
    let refund_address_balance_after = get_balance(provider, &refund_address.into()).await.unwrap();

    assert_eq!(igp_balance_after - igp_balance_before, quote);
    assert_eq!(
        refund_address_balance_after - refund_address_balance_before,
        overpayment,
    );

    //And that the transaction logged the GasPaymentEvent
    let events = call.decode_logs_with_type::<GasPaymentEvent>().unwrap();
    assert_eq!(
        events,
        vec![GasPaymentEvent {
            message_id: Bits256(message_id.into()),
            destination_domain,
            gas_amount: TEST_GAS_AMOUNT,
            payment: quote,
        }]
    );
}

// ============ Pay For Gas Reverts If Insufficient Payment ============
#[tokio::test]
async fn test_pay_for_gas_reverts_if_insufficient_payment() {
    let (igp, oracle) = get_contract_instances().await;

    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: RemoteGasData {
                domain: TEST_DESTINATION_DOMAIN,
                token_exchange_rate: TOKEN_EXCHANGE_RATE_SCALE, // 1.0 exchange rate (remote token has exact same value as local)
                gas_price: 1u64.into(),                         // 1 wei gas price
                token_decimals: BASE_ASSET_DECIMALS,            // same decimals as local
            },
        },
    )
    .await
    .unwrap();

    let refund_address = Address::from_str(TEST_REFUND_ADDRESS).unwrap();

    let quote = igp
        .methods()
        .quote_gas_payment(TEST_DESTINATION_DOMAIN, TEST_GAS_AMOUNT)
        .with_contract_ids(&[oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    let base_asset_id = get_base_asset();
    let call_params = CallParameters::new(quote - 1, base_asset_id, 1_000_000);

    let mock_message = create_mock_message();
    let message_id = mock_message.id();
    let destination_domain = mock_message.destination;

    let call = igp
        .methods()
        .pay_for_gas(
            Bits256(message_id.into()),
            destination_domain,
            TEST_GAS_AMOUNT,
            Identity::Address(refund_address),
        )
        .call_params(call_params)
        .unwrap()
        .determine_missing_contracts(Some(1))
        .await;

    assert!(call.is_err());
    assert_eq!(
        get_revert_reason(call.err().unwrap()),
        "InsufficientGasPayment"
    );
}

// ============ Pay For Gas Reverts If Not Base Asset ============
#[tokio::test]
async fn test_pay_for_gas_reverts_if_not_base_asset() {
    let (igp, oracle) = get_contract_instances().await;

    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: RemoteGasData {
                domain: TEST_DESTINATION_DOMAIN,
                token_exchange_rate: TOKEN_EXCHANGE_RATE_SCALE, // 1.0 exchange rate (remote token has exact same value as local)
                gas_price: 1u64.into(),                         // 1 wei gas price
                token_decimals: BASE_ASSET_DECIMALS,            // same decimals as local
            },
        },
    )
    .await
    .unwrap();

    let refund_address = Address::from_str(TEST_REFUND_ADDRESS).unwrap();

    let quote = igp
        .methods()
        .quote_gas_payment(TEST_DESTINATION_DOMAIN, TEST_GAS_AMOUNT)
        .with_contract_ids(&[oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    let non_base_asset_id = get_non_base_asset();
    let call_params = CallParameters::new(quote - 1, non_base_asset_id, 1_000_000);

    let mock_message = create_mock_message();
    let message_id = mock_message.id();
    let destination_domain = mock_message.destination;

    let call = igp
        .methods()
        .pay_for_gas(
            Bits256(message_id.into()),
            destination_domain,
            TEST_GAS_AMOUNT,
            Identity::Address(refund_address),
        )
        .call_params(call_params)
        .unwrap()
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .determine_missing_contracts(Some(1))
        .await;

    assert!(call.is_err());
    assert_eq!(
        get_revert_reason(call.err().unwrap()),
        "InterchainGasPaymentInBaseAsset"
    );
}

// ============ quote_gas_payment ============

#[tokio::test]
async fn test_quote_gas_payment() {
    let (igp, oracle) = get_contract_instances().await;

    // Testing when exchange rates are relatively close.
    // The base asset has 9 decimals, there's a 1:1 exchange rate,
    // and the remote asset also has 9 decimals.
    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: RemoteGasData {
                domain: TEST_DESTINATION_DOMAIN,
                // 0.2 exchange rate (remote token less valuable)
                token_exchange_rate: (TOKEN_EXCHANGE_RATE_SCALE / 5),
                gas_price: 150u64.into(),            // 150 gas price
                token_decimals: BASE_ASSET_DECIMALS, // same decimals as local
            },
        },
    )
    .await
    .unwrap();

    let quote = igp
        .methods()
        .quote_gas_payment(TEST_DESTINATION_DOMAIN, TEST_GAS_AMOUNT)
        .with_contract_ids(&[oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    // 300,000 destination gas
    // 150 gas price
    // 300,000 * 150 = 45000000 (0.045 remote tokens w/ 9 decimals)
    // Using the 0.2 token exchange rate, meaning the local native token
    // is 5x more valuable than the remote token:
    // 45000000 * 0.2 = 9000000 (0.009 local tokens w/ 9 decimals)
    assert_eq!(quote, 9000000u64);

    // Testing when the remote token is much more valuable, has higher decimals, & there's a super high gas price
    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: RemoteGasData {
                domain: TEST_DESTINATION_DOMAIN,
                // remote token 5000x more valuable
                token_exchange_rate: (5000 * TOKEN_EXCHANGE_RATE_SCALE),
                gas_price: 1500000000000u64.into(), // 150 gwei gas price
                token_decimals: 18,                 // remote has 18 decimals
            },
        },
    )
    .await
    .unwrap();

    let quote = igp
        .methods()
        .quote_gas_payment(TEST_DESTINATION_DOMAIN, TEST_GAS_AMOUNT)
        .with_contract_ids(&[oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    // 300,000 destination gas
    // 1500 gwei = 1500000000000 wei
    // 300,000 * 1500000000000 = 450000000000000000 (0.45 remote tokens w/ 18 decimals)
    // Using the 5000 * 1e19 token exchange rate, meaning the remote native token
    // is 5000x more valuable than the local token, and adjusting for decimals:
    // 450000000000000000 * 5000 * 1e-9 = 2250000000000 (2250 local tokens w/ 9 decimals)
    assert_eq!(quote, 2250000000000u64);

    // Testing when the remote token is much less valuable & there's a low gas price, but has 18 decimals
    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: RemoteGasData {
                domain: TEST_DESTINATION_DOMAIN,
                // remote token 0.04x the price
                token_exchange_rate: (4 * TOKEN_EXCHANGE_RATE_SCALE / 100),
                gas_price: 100000000u64.into(), // 0.1 gwei gas price
                token_decimals: 18,             // remote has 18 decimals
            },
        },
    )
    .await
    .unwrap();

    let quote = igp
        .methods()
        .quote_gas_payment(TEST_DESTINATION_DOMAIN, TEST_GAS_AMOUNT)
        .with_contract_ids(&[oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    // 300,000 destination gas
    // 0.1 gwei = 100000000 wei
    // 300,000 * 100000000 = 30000000000000 (0.00003 remote tokens w/ 18 decimals)
    // Using the 0.04 * 1e19 token exchange rate, meaning the remote native token
    // is 0.04x the price of the local token, and adjusting for decimals:
    // 30000000000000 * 0.04 * 1e-9 = 1200 (0.0000012 local tokens w/ 9 decimals)
    assert_eq!(quote, 1200u64);

    // Testing when the remote token is much less valuable & there's a low gas price, but has 4 decimals
    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: RemoteGasData {
                domain: TEST_DESTINATION_DOMAIN,
                // remote token 10x the price
                token_exchange_rate: (10 * TOKEN_EXCHANGE_RATE_SCALE),
                gas_price: 10u64.into(), // 10 gas price
                token_decimals: 4u8,     // remote has 4 decimals
            },
        },
    )
    .await
    .unwrap();

    let quote = igp
        .methods()
        .quote_gas_payment(TEST_DESTINATION_DOMAIN, TEST_GAS_AMOUNT)
        .with_contract_ids(&[oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    // 300,000 destination gas
    // 10 gas price
    // 300,000 * 10 = 3000000 (300.0000 remote tokens w/ 4 decimals)
    // Using the 10 * 1e19 token exchange rate, meaning the remote native token
    // is 10x the price of the local token, and adjusting for decimals:
    // 3000000 * 10 * 1e5 = 3000000000000 (3000 local tokens w/ 9 decimals)
    assert_eq!(quote, 3000000000000u64);
}

#[tokio::test]
async fn test_quote_gas_payment_reverts_if_no_gas_oracle_set() {
    let (igp, _) = get_contract_instances().await;

    let quote = igp
        .methods()
        .quote_gas_payment(TEST_DESTINATION_DOMAIN + 1, TEST_GAS_AMOUNT)
        .simulate(Execution::StateReadOnly)
        .await;

    assert!(quote.is_err());
}

// ============ set_gas_oracle ============

#[tokio::test]
async fn test_set_gas_oracle() {
    let (igp, oracle) = get_contract_instances().await;

    let remote_domain = TEST_DESTINATION_DOMAIN + 1;
    let oracle_contract_id_bits256 = Bits256(oracle.contract_id().hash().into());

    // Before it's been set, it should return None
    let gas_oracle = igp
        .methods()
        .gas_oracle(remote_domain)
        .call()
        .await
        .unwrap()
        .value;
    assert_eq!(gas_oracle, None);

    // Now set the gas oracle
    let call = igp
        .methods()
        .set_gas_oracle(remote_domain, oracle_contract_id_bits256)
        .call()
        .await
        .unwrap();
    let events = call.decode_logs_with_type::<GasOracleSetEvent>().unwrap();
    assert_eq!(
        events,
        vec![GasOracleSetEvent {
            domain: remote_domain,
            gas_oracle: oracle_contract_id_bits256,
        }]
    );

    // Ensure it's actually been set
    let gas_oracle = igp
        .methods()
        .gas_oracle(remote_domain)
        .call()
        .await
        .unwrap()
        .value;
    assert_eq!(gas_oracle, Some(oracle_contract_id_bits256));
}

#[tokio::test]
async fn test_set_gas_oracle_reverts_if_not_owner() {
    let (igp, oracle) = get_contract_instances().await;

    let remote_domain = TEST_DESTINATION_DOMAIN + 1;
    let oracle_contract_id_bits256 = Bits256(oracle.contract_id().hash().into());

    let non_owner_wallet =
        funded_wallet_with_private_key(&oracle.account(), NON_OWNER_PRIVATE_KEY).await;

    let call = igp
        .with_account(non_owner_wallet)
        .methods()
        .set_gas_oracle(remote_domain, oracle_contract_id_bits256)
        .call()
        .await;

    assert!(call.is_err());
    assert_eq!(get_revert_reason(call.err().unwrap()), "NotOwner");
}

// ============ set_beneficiary ============

#[tokio::test]
async fn test_set_beneficiary() {
    let (igp, _) = get_contract_instances().await;

    let new_beneficiary = Identity::Address(Address::from_str(TEST_REFUND_ADDRESS).unwrap());

    let call = igp
        .methods()
        .set_beneficiary(new_beneficiary)
        .call()
        .await
        .unwrap();

    let events = call.decode_logs_with_type::<BeneficiarySetEvent>().unwrap();
    assert_eq!(
        events,
        vec![BeneficiarySetEvent {
            beneficiary: Identity::Address(Address::from_str(TEST_REFUND_ADDRESS).unwrap()),
        }]
    );

    // Before it's been set, it should return None
    let beneficiary = igp.methods().beneficiary().call().await.unwrap().value;
    assert_eq!(beneficiary, new_beneficiary);
}

#[tokio::test]
async fn test_set_beneficiary_reverts_if_not_owner() {
    let (igp, _) = get_contract_instances().await;
    let non_owner_wallet =
        funded_wallet_with_private_key(&igp.account(), NON_OWNER_PRIVATE_KEY).await;

    let new_beneficiary = Identity::Address(Address::from_str(TEST_REFUND_ADDRESS).unwrap());

    let call = igp
        .with_account(non_owner_wallet)
        .methods()
        .set_beneficiary(new_beneficiary)
        .call()
        .await;

    assert!(call.is_err());
    assert_eq!(get_revert_reason(call.err().unwrap()), "NotOwner");
}

// ============ get_remote_gas_data ============

#[tokio::test]
async fn test_get_remote_gas_data() {
    let (_, oracle) = get_contract_instances().await;

    let remote_gas_data_config = RemoteGasDataConfig {
        domain: TEST_DESTINATION_DOMAIN,
        remote_gas_data: RemoteGasData {
            domain: TEST_DESTINATION_DOMAIN,
            token_exchange_rate: TOKEN_EXCHANGE_RATE_SCALE, // 1.0 exchange rate (remote token has exact same value as local)
            gas_price: 1u64.into(),                         // 1 wei gas price
            token_decimals: BASE_ASSET_DECIMALS,            // same decimals as local
        },
    };

    set_remote_gas_data(&oracle, remote_gas_data_config.clone())
        .await
        .unwrap();

    let RemoteGasData {
        domain: _,
        token_exchange_rate,
        gas_price,
        token_decimals,
    } = oracle
        .methods()
        .get_remote_gas_data(TEST_DESTINATION_DOMAIN)
        .with_contract_ids(&[oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(
        token_exchange_rate,
        remote_gas_data_config.remote_gas_data.token_exchange_rate
    );
    assert_eq!(gas_price, remote_gas_data_config.remote_gas_data.gas_price);
    assert_eq!(
        token_decimals,
        remote_gas_data_config.remote_gas_data.token_decimals
    );
}

// ============ get_remote_gas_data_reverts_if_no_gas_oracle_set ============

#[tokio::test]
async fn test_get_remote_gas_data_reverts_if_no_gas_oracle_set() {
    let (igp, _) = get_contract_instances().await;

    let res = igp
        .methods()
        .gas_oracle(TEST_DESTINATION_DOMAIN + 10)
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(res, None);
}

// ============ Post Dispatch Hook - Module Type ============

#[tokio::test]
async fn test_module_type() {
    let (igp, _) = get_contract_instances().await;

    let hook_type = igp.methods().hook_type().call().await.unwrap().value;
    assert_eq!(hook_type, PostDispatchHookType::INTERCHAIN_GAS_PAYMASTER);
}

// ============ Supports Metadata ============

#[tokio::test]
async fn test_supports_metadata() {
    let (igp, _) = get_contract_instances().await;

    let supports = igp
        .methods()
        .supports_metadata(Bytes(vec![0]))
        .call()
        .await
        .unwrap()
        .value;

    assert!(!supports);
}

// ============ Quote Dispatch ============
#[tokio::test]
async fn test_quote_dispatch() {
    let (igp, oracle) = get_contract_instances().await;
    let mock_message = create_mock_message();

    let message_bytes = hyperlane_core::Encode::to_vec(&mock_message);

    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: RemoteGasData {
                domain: TEST_DESTINATION_DOMAIN,
                // 0.2 exchange rate (remote token less valuable)
                token_exchange_rate: (TOKEN_EXCHANGE_RATE_SCALE / 5),
                gas_price: 150u64.into(),            // 150 gas price
                token_decimals: BASE_ASSET_DECIMALS, // same decimals as local
            },
        },
    )
    .await
    .unwrap();

    let metadata = create_mock_metadata(&igp.account());

    let quote = igp
        .methods()
        .quote_dispatch(metadata, Bytes(message_bytes))
        .with_contract_ids(&[igp.contract_id().clone(), oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(quote, 9000000u64);
}

// ============ Post Dispatch ============
#[tokio::test]
async fn test_post_dispatch() {
    let (igp, oracle) = get_contract_instances().await;
    let mock_message = create_mock_message();

    let wallet = igp.account();
    let provider = wallet.provider().unwrap();
    let wallet_address_balance_before = get_balance(provider, wallet.address()).await.unwrap();

    let message_bytes = hyperlane_core::Encode::to_vec(&mock_message);

    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: RemoteGasData {
                domain: TEST_DESTINATION_DOMAIN,
                // 0.2 exchange rate (remote token less valuable)
                token_exchange_rate: (TOKEN_EXCHANGE_RATE_SCALE / 5),
                gas_price: 150u64.into(),            // 150 gas price
                token_decimals: BASE_ASSET_DECIMALS, // same decimals as local
            },
        },
    )
    .await
    .unwrap();

    let metadata = create_mock_metadata(&igp.account());

    let quote = igp
        .methods()
        .quote_dispatch(metadata.clone(), Bytes(message_bytes.clone()))
        .with_contract_ids(&[igp.contract_id().clone(), oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    let call_params = CallParameters::new(quote, get_base_asset(), 1_000_000);

    igp.methods()
        .post_dispatch(metadata, Bytes(message_bytes.clone()))
        .call_params(call_params)
        .unwrap()
        .with_contract_ids(&[igp.contract_id().clone(), oracle.contract_id().clone()])
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .call()
        .await
        .unwrap();

    let wallet_address_balance_after = get_balance(provider, wallet.address()).await.unwrap();

    assert_eq!(
        wallet_address_balance_before - wallet_address_balance_after,
        quote + 2 // 1 gas for quote + 1 gas for post dispatch
    );
}

// ============ Post Dispatch With Metadata Validation ============
#[tokio::test]
async fn test_supports_metadata_validation() {
    let (igp, _) = get_contract_instances().await;

    // Metadata too short
    let short_metadata = Bytes(vec![1; MIN_METADATA_LENGTH as usize - 1]);
    let supports = igp
        .methods()
        .supports_metadata(short_metadata)
        .call()
        .await
        .unwrap()
        .value;
    assert!(!supports, "Should reject metadata that's too short");

    // Wrong variant
    let mut wrong_variant_metadata = vec![0; MIN_METADATA_LENGTH as usize];
    wrong_variant_metadata[0] = 2; // Set variant to 2 instead of 1
    let supports = igp
        .methods()
        .supports_metadata(Bytes(wrong_variant_metadata))
        .call()
        .await
        .unwrap()
        .value;
    assert!(!supports, "Should reject metadata with wrong variant");
}

// ============ Post Dispatch With Invalid Metadata ============
#[tokio::test]
async fn test_post_dispatch_with_invalid_metadata() {
    let (igp, oracle) = get_contract_instances().await;
    let mock_message = create_mock_message();
    let message_bytes = hyperlane_core::Encode::to_vec(&mock_message);

    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: RemoteGasData {
                domain: TEST_DESTINATION_DOMAIN,
                token_exchange_rate: (TOKEN_EXCHANGE_RATE_SCALE / 5),
                gas_price: 150u64.into(),
                token_decimals: BASE_ASSET_DECIMALS,
            },
        },
    )
    .await
    .unwrap();

    // Test with invalid metadata
    let mut invalid_metadata = vec![0; MIN_METADATA_LENGTH as usize];
    invalid_metadata[0] = 2; // Wrong variant

    let quote = igp
        .methods()
        .quote_dispatch(
            Bytes(invalid_metadata.clone()),
            Bytes(message_bytes.clone()),
        )
        .with_contract_ids(&[igp.contract_id().clone(), oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await;

    assert!(quote.is_err(), "Quote should fail with invalid metadata");

    let call_params = CallParameters::new(1000000, get_base_asset(), 1_000_000);
    let result = igp
        .methods()
        .post_dispatch(Bytes(invalid_metadata), Bytes(message_bytes))
        .call_params(call_params)
        .unwrap()
        .with_contract_ids(&[igp.contract_id().clone(), oracle.contract_id().clone()])
        .call()
        .await;

    assert!(
        result.is_err(),
        "Post dispatch should fail with invalid metadata"
    );
    assert_eq!(
        get_revert_reason(result.err().unwrap()),
        "UnsupportedMetadataFormat"
    );
}

// ============ Post Dispatch With Empty Metadata ============
#[tokio::test]
async fn test_post_dispatch_with_empty_metadata() {
    let (igp, oracle) = get_contract_instances().await;
    let mock_message = create_mock_message();
    let message_bytes = hyperlane_core::Encode::to_vec(&mock_message);

    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: RemoteGasData {
                domain: TEST_DESTINATION_DOMAIN,
                token_exchange_rate: (TOKEN_EXCHANGE_RATE_SCALE / 5),
                gas_price: 150u64.into(),
                token_decimals: BASE_ASSET_DECIMALS,
            },
        },
    )
    .await
    .unwrap();

    let wallet = igp.account();
    let provider = wallet.provider().unwrap();
    let wallet_address_balance_before = get_balance(provider, wallet.address()).await.unwrap();

    let refund_identity = Address::from_str(TEST_REFUND_ADDRESS).unwrap();
    let refunded_address_balance_before = get_balance(provider, &refund_identity.into())
        .await
        .unwrap();

    let quote = igp
        .methods()
        .quote_dispatch(Bytes(vec![]), Bytes(message_bytes.clone()))
        .with_contract_ids(&[igp.contract_id().clone(), oracle.contract_id().clone()])
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    let overpayment_amount = 10000;
    let total_payment = quote + overpayment_amount;

    let call_params = CallParameters::new(total_payment, get_base_asset(), 1_000_000);

    igp.methods()
        .post_dispatch(Bytes(vec![]), Bytes(message_bytes))
        .call_params(call_params)
        .unwrap()
        .with_contract_ids(&[igp.contract_id().clone(), oracle.contract_id().clone()])
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .call()
        .await
        .unwrap();

    let wallet_address_balance_after = get_balance(provider, wallet.address()).await.unwrap();
    let total_spent = wallet_address_balance_before - wallet_address_balance_after;

    let refunded_address_balance_after = get_balance(provider, &refund_identity.into())
        .await
        .unwrap();

    assert_eq!(
        total_spent,
        total_payment + 1 // 1 gas for post dispatch
    );

    assert_eq!(
        refunded_address_balance_after - refunded_address_balance_before,
        total_payment - quote
    );
}

// ============ Get Domain Gas Config ============
#[tokio::test]
async fn test_get_domain_gas_config() {
    let (igp, oracle) = get_contract_instances().await;

    let oracle_address = Bits256(oracle.contract_id().hash().into());
    let test_overhead = 50000u64;

    let domains = vec![TEST_DESTINATION_DOMAIN];
    let configs = vec![DomainGasConfig {
        gas_overhead: test_overhead,
        gas_oracle: oracle_address,
    }];

    igp.methods()
        .set_destination_gas_config(domains, configs)
        .call()
        .await
        .unwrap();

    let updated_config = igp
        .methods()
        .get_domain_gas_config(TEST_DESTINATION_DOMAIN)
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(updated_config.gas_overhead, test_overhead);
    assert_eq!(updated_config.gas_oracle, oracle_address);
}

// ============ Set Destination Gas Config ============
#[tokio::test]
async fn test_set_destination_gas_config() {
    let (igp, oracle) = get_contract_instances().await;
    let oracle_address = Bits256(oracle.contract_id().hash().into());

    let domains = vec![TEST_DESTINATION_DOMAIN, TEST_DESTINATION_DOMAIN + 1];
    let configs = vec![
        DomainGasConfig {
            gas_overhead: 50000u64,
            gas_oracle: oracle_address,
        },
        DomainGasConfig {
            gas_overhead: 75000u64,
            gas_oracle: oracle_address,
        },
    ];

    let call = igp
        .methods()
        .set_destination_gas_config(domains.clone(), configs.clone())
        .call()
        .await
        .unwrap();

    let events = call
        .decode_logs_with_type::<DestinationGasConfigSetEvent>()
        .unwrap();
    assert_eq!(events.len(), 2);

    assert_eq!(events[0].domain, domains[0]);
    assert_eq!(events[0].oracle, configs[0].gas_oracle);
    assert_eq!(events[0].overhead, configs[0].gas_overhead);

    assert_eq!(events[1].domain, domains[1]);
    assert_eq!(events[1].oracle, configs[1].gas_oracle);
    assert_eq!(events[1].overhead, configs[1].gas_overhead);

    for i in 0..domains.len() {
        let config = igp
            .methods()
            .get_domain_gas_config(domains[i])
            .call()
            .await
            .unwrap()
            .value;

        assert_eq!(config.gas_overhead, configs[i].gas_overhead);
        assert_eq!(config.gas_oracle, configs[i].gas_oracle);
    }
}

// ============ Set Destination Gas Config Reverts If Not Owner ============
#[tokio::test]
async fn test_set_destination_gas_config_reverts_if_not_owner() {
    let (igp, oracle) = get_contract_instances().await;
    let non_owner_wallet =
        funded_wallet_with_private_key(&igp.account(), NON_OWNER_PRIVATE_KEY).await;
    let oracle_address = Bits256(oracle.contract_id().hash().into());

    let domains = vec![TEST_DESTINATION_DOMAIN];
    let configs = vec![DomainGasConfig {
        gas_overhead: 50000u64,
        gas_oracle: oracle_address,
    }];

    let call = igp
        .with_account(non_owner_wallet)
        .methods()
        .set_destination_gas_config(domains, configs)
        .call()
        .await;

    assert!(call.is_err());
    assert_eq!(get_revert_reason(call.err().unwrap()), "NotOwner");
}

// ============ Set Destination Gas Config Reverts If Lengths Mismatch ============
#[tokio::test]
async fn test_set_destination_gas_config_reverts_if_lengths_mismatch() {
    let (igp, oracle) = get_contract_instances().await;
    let oracle_address = Bits256(oracle.contract_id().hash().into());

    let domains = vec![TEST_DESTINATION_DOMAIN];
    let configs = vec![
        DomainGasConfig {
            gas_overhead: 50000u64,
            gas_oracle: oracle_address,
        },
        DomainGasConfig {
            gas_overhead: 75000u64,
            gas_oracle: oracle_address,
        },
    ];

    let call = igp
        .methods()
        .set_destination_gas_config(domains, configs)
        .call()
        .await;

    assert!(call.is_err());
    assert_eq!(
        get_revert_reason(call.err().unwrap()),
        "InvalidDomainConfigLength"
    );
}
