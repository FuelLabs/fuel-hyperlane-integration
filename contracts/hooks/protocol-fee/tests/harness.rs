use fuels::{prelude::*, types::Identity};
use std::str::FromStr;
use test_utils::get_revert_reason;

// Load abi from json
abigen!(Contract(
    name = "ProtocolFee",
    abi = "contracts/hooks/protocol-fee/out/debug/protocol-fee-abi.json"
));

const PROTOCOL_FEE: u64 = 1;
const MAX_PROTOCOL_FEE: u64 = 10;
const TEST_REFUND_ADDRESS: &str =
    "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";

fn get_base_asset() -> AssetId {
    AssetId::BASE
}

fn create_mock_metadata() -> Bytes {
    Bytes(vec![])
}

async fn get_contract_instance() -> (ProtocolFee<WalletUnlocked>, WalletUnlocked) {
    let base_asset_id = get_base_asset();

    // Launch a local network and deploy the contract
    let mut wallets = launch_custom_provider_and_get_wallets(
        WalletsConfig::new_multiple_assets(
            1,
            vec![AssetConfig {
                id: base_asset_id,
                num_coins: 1,
                coin_amount: 100_000_000_000,
            }],
        ),
        None,
        None,
    )
    .await
    .unwrap();

    let wallet = wallets.pop().unwrap();

    let protocol_fee_configurables = ProtocolFeeConfigurables::default()
        .with_MAX_PROTOCOL_FEE(MAX_PROTOCOL_FEE)
        .unwrap();

    let id = Contract::load_from(
        "./out/debug/protocol-fee.bin",
        LoadConfiguration::default().with_configurables(protocol_fee_configurables),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let instance = ProtocolFee::new(id, wallet.clone());
    let owner_identity = Identity::Address(wallet.address().into());

    instance
        .methods()
        .initialize(PROTOCOL_FEE, owner_identity, owner_identity)
        .call()
        .await
        .unwrap();

    (instance, wallet)
}

// ============ Initialization Test ============
#[tokio::test]
async fn test_initialization_reverts_if_already_initialized() {
    let (instance, wallet) = get_contract_instance().await;
    let owner = Identity::Address(wallet.address().into());

    let result = instance
        .methods()
        .initialize(PROTOCOL_FEE, owner, owner)
        .call()
        .await;

    assert!(result.is_err());
    assert_eq!(
        get_revert_reason(result.err().unwrap()),
        "CannotReinitialized"
    );
}

// ============ Protocol Fee Tests ============
#[tokio::test]
async fn test_set_protocol_fee() {
    let (instance, _wallet) = get_contract_instance().await;

    let new_fee = 2;
    instance
        .methods()
        .set_protocol_fee(new_fee)
        .call()
        .await
        .unwrap();

    let current_fee = instance
        .methods()
        .protocol_fee()
        .call()
        .await
        .unwrap()
        .value;
    assert_eq!(current_fee, new_fee);
}

// ... (previous code remains the same)

// ============ Protocol Fee Validation Tests ============
#[tokio::test]
async fn test_set_protocol_fee_exceeds_max() {
    let (instance, _wallet) = get_contract_instance().await;

    let result = instance
        .methods()
        .set_protocol_fee(MAX_PROTOCOL_FEE + 1)
        .call()
        .await;

    assert!(result.is_err());
    assert_eq!(
        get_revert_reason(result.err().unwrap()),
        "ExceedsMaxProtocolFee"
    );
}

// ============ Beneficiary Management Tests ============
#[tokio::test]
async fn test_set_beneficiary() {
    let (instance, _wallet) = get_contract_instance().await;

    let new_beneficiary = Identity::Address(Address::from_str(TEST_REFUND_ADDRESS).unwrap());
    instance
        .methods()
        .set_beneficiary(new_beneficiary)
        .call()
        .await
        .unwrap();

    let current_beneficiary = instance.methods().beneficiary().call().await.unwrap().value;
    assert_eq!(current_beneficiary, new_beneficiary);
}

// ============ Set Beneficiary Zero Address ============
#[tokio::test]
async fn test_set_beneficiary_zero_address() {
    let (instance, _wallet) = get_contract_instance().await;

    let zero_beneficiary = Identity::Address(Address::from([0u8; 32]));
    let result = instance
        .methods()
        .set_beneficiary(zero_beneficiary)
        .call()
        .await;

    assert!(result.is_err());
    assert_eq!(
        get_revert_reason(result.err().unwrap()),
        "InvalidBeneficiary"
    );
}

// ============ Post Dispatch Tests ============
#[tokio::test]
async fn test_post_dispatch_with_payment() {
    let (instance, wallet) = get_contract_instance().await;
    let provider = wallet.provider().unwrap();

    let metadata = create_mock_metadata();
    let message = Bytes(vec![1, 2, 3, 4]);

    let wallet_balance_before = provider
        .get_asset_balance(wallet.address(), get_base_asset())
        .await
        .unwrap();

    let fee = instance
        .methods()
        .protocol_fee()
        .call()
        .await
        .unwrap()
        .value;
    let overpayment = 50;
    let total_payment = fee + overpayment;

    instance
        .methods()
        .post_dispatch(metadata, message)
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .call_params(CallParameters::new(
            total_payment,
            get_base_asset(),
            1_000_000,
        ))
        .unwrap()
        .call()
        .await
        .unwrap();

    let wallet_balance_after = provider
        .get_asset_balance(wallet.address(), get_base_asset())
        .await
        .unwrap();

    assert!(wallet_balance_before - wallet_balance_after >= fee);
}

// ============ Post Dispatch Insufficient Payment ============
#[tokio::test]
async fn test_post_dispatch_insufficient_payment() {
    let (instance, _wallet) = get_contract_instance().await;

    let metadata = create_mock_metadata();
    let message = Bytes(vec![1, 2, 3, 4]);
    let fee = instance
        .methods()
        .protocol_fee()
        .call()
        .await
        .unwrap()
        .value;

    let result = instance
        .methods()
        .post_dispatch(metadata, message)
        .call_params(CallParameters::new(fee - 1, get_base_asset(), 1_000_000))
        .unwrap()
        .call()
        .await;

    assert!(result.is_err());
    assert_eq!(
        get_revert_reason(result.err().unwrap()),
        "InsufficientProtocolFee"
    );
}

// ============ Quote Dispatch ============
#[tokio::test]
async fn test_quote_dispatch() {
    let (instance, _wallet) = get_contract_instance().await;

    let metadata = create_mock_metadata();
    let message = Bytes(vec![1, 2, 3, 4]);

    let quote = instance
        .methods()
        .quote_dispatch(metadata, message)
        .call()
        .await
        .unwrap()
        .value;

    let fee = instance
        .methods()
        .protocol_fee()
        .call()
        .await
        .unwrap()
        .value;
    assert_eq!(quote, fee);
}

// ============ Fee Collection ============
#[tokio::test]
async fn test_collect_protocol_fees() {
    let (instance, wallet) = get_contract_instance().await;
    let provider = wallet.provider().unwrap();

    let metadata = create_mock_metadata();
    let message = Bytes(vec![1, 2, 3, 4]);
    let fee = instance
        .methods()
        .protocol_fee()
        .call()
        .await
        .unwrap()
        .value;

    instance
        .methods()
        .post_dispatch(metadata, message)
        .call_params(CallParameters::new(fee, get_base_asset(), 1_000_000))
        .unwrap()
        .call()
        .await
        .unwrap();

    let contract_balance_before = provider
        .get_contract_asset_balance(instance.contract_id(), get_base_asset())
        .await
        .unwrap();

    instance
        .methods()
        .collect_protocol_fees()
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .call()
        .await
        .unwrap();

    let contract_balance_after = provider
        .get_contract_asset_balance(instance.contract_id(), get_base_asset())
        .await
        .unwrap();

    assert!(contract_balance_before > contract_balance_after);
}

// ============ Metadata Support Tests ============
#[tokio::test]
async fn test_supports_metadata() {
    let (instance, _wallet) = get_contract_instance().await;

    let valid_metadata = create_mock_metadata();
    let result = instance
        .methods()
        .supports_metadata(valid_metadata)
        .call()
        .await
        .unwrap()
        .value;

    assert!(result);
}

// ============ Post Dispatch Overpayment Tests ============
#[tokio::test]
async fn test_post_dispatch_with_overpayment() {
    let (instance, wallet) = get_contract_instance().await;
    let provider = wallet.provider().unwrap();

    let metadata = create_mock_metadata();
    let message = Bytes(vec![1, 2, 3, 4]);

    let fee = instance
        .methods()
        .protocol_fee()
        .call()
        .await
        .unwrap()
        .value;
    let overpayment = 50;

    let total_payment = fee + overpayment;
    let refund_balance_before = provider
        .get_asset_balance(&wallet.address().into(), get_base_asset())
        .await
        .unwrap();

    instance
        .methods()
        .post_dispatch(metadata, message)
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .call_params(CallParameters::new(
            total_payment,
            get_base_asset(),
            1_000_000,
        ))
        .unwrap()
        .call()
        .await
        .unwrap();

    let refund_balance_after = provider
        .get_asset_balance(&wallet.address().into(), get_base_asset())
        .await
        .unwrap();

    assert_eq!(refund_balance_before - refund_balance_after, fee + 1);
}
