use fuels::{
    prelude::*,
    types::{Bits256, Identity},
};
use gas_oracle::{GasOracle, RemoteGasDataConfig};
use std::str::FromStr;
use test_utils::{funded_wallet_with_private_key, get_revert_reason};

// Load abi from json
abigen!(Contract(
    name = "GasPaymaster",
    abi = "contracts/igp/gas-paymaster/out/debug/gas-paymaster-abi.json"
));

mod gas_oracle {
    use fuels::prelude::abigen;

    // Load abi from json
    abigen!(Contract(
        name = "GasOracle",
        abi = "contracts/igp/gas-oracle/out/debug/gas-oracle-abi.json"
    ));
}

const NON_OWNER_PRIVATE_KEY: &str =
    "0xde97d8624a438121b86a1956544bd72ed68cd69f2c99555b08b1e8c51ffd511c";

const TEST_DESTINATION_DOMAIN: u32 = 11111;
const TEST_GAS_AMOUNT: u64 = 300000;
const TEST_MESSAGE_ID: &str = "0x6ae9a99190641b9ed0c07143340612dde0e9cb7deaa5fe07597858ae9ba5fd7f";
const TEST_REFUND_ADDRESS: &str =
    "0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";
const TEST_NON_BASE_ASSET_ID: [u8; 32] = [1u8; 32];

const TOKEN_EXCHANGE_RATE_SCALE: u128 = 1e19 as u128;
const BASE_ASSET_DECIMALS: u8 = 9;

fn get_base_asset() -> AssetId {
    AssetId::BASE
}

fn get_non_base_asset() -> AssetId {
    AssetId::new(TEST_NON_BASE_ASSET_ID)
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
            TOKEN_EXCHANGE_RATE_SCALE as u64,
            TEST_GAS_AMOUNT,
        )
        .call()
        .await
        .unwrap();

    let storage_gas_oracle_id = Contract::load_from(
        "../gas-oracle/out/debug/gas-oracle.bin",
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
        .claim(get_base_asset())
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .call()
        .await
        .unwrap();

    let events = call.decode_logs_with_type::<ClaimEvent>().unwrap();
    assert_eq!(
        events,
        vec![ClaimEvent {
            beneficiary: Bits256(Address::from(wallet.address()).into()),
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
            remote_gas_data: gas_oracle::RemoteGasData {
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

    let call = igp
        .methods()
        .pay_for_gas(
            Bits256::from_hex_str(TEST_MESSAGE_ID).unwrap(),
            TEST_DESTINATION_DOMAIN,
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
            message_id: Bits256::from_hex_str(TEST_MESSAGE_ID).unwrap(),
            destination_domain: TEST_DESTINATION_DOMAIN,
            gas_amount: TEST_GAS_AMOUNT,
            payment: quote,
        }]
    );
}

#[tokio::test]
async fn test_pay_for_gas_reverts_if_insufficient_payment() {
    let (igp, oracle) = get_contract_instances().await;

    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: gas_oracle::RemoteGasData {
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

    let call = igp
        .methods()
        .pay_for_gas(
            Bits256::from_hex_str(TEST_MESSAGE_ID).unwrap(),
            TEST_DESTINATION_DOMAIN,
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

#[tokio::test]
async fn test_pay_for_gas_reverts_if_not_base_asset() {
    let (igp, oracle) = get_contract_instances().await;

    set_remote_gas_data(
        &oracle,
        RemoteGasDataConfig {
            domain: TEST_DESTINATION_DOMAIN,
            remote_gas_data: gas_oracle::RemoteGasData {
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

    let call = igp
        .methods()
        .pay_for_gas(
            Bits256::from_hex_str(TEST_MESSAGE_ID).unwrap(),
            TEST_DESTINATION_DOMAIN,
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
            remote_gas_data: gas_oracle::RemoteGasData {
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
            remote_gas_data: gas_oracle::RemoteGasData {
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
            remote_gas_data: gas_oracle::RemoteGasData {
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
            remote_gas_data: gas_oracle::RemoteGasData {
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
            beneficiary: Bits256::from_hex_str(TEST_REFUND_ADDRESS).unwrap(),
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
        remote_gas_data: gas_oracle::RemoteGasData {
            token_exchange_rate: TOKEN_EXCHANGE_RATE_SCALE, // 1.0 exchange rate (remote token has exact same value as local)
            gas_price: 1u64.into(),                         // 1 wei gas price
            token_decimals: BASE_ASSET_DECIMALS,            // same decimals as local
        },
    };

    set_remote_gas_data(&oracle, remote_gas_data_config.clone())
        .await
        .unwrap();

    let gas_oracle::RemoteGasData {
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
