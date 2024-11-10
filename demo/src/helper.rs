use fuels::{
    accounts::{provider::Provider, wallet::WalletUnlocked, Account},
    types::{bech32::Bech32ContractId, transaction::TxPolicies, Address, AssetId, ContractId},
};
use serde_json::Value;
use std::{fs, str::FromStr};

pub const TEST_RECIPIENT_IN_FUEL: &str =
    "45eef0a12f9bd3590ca07f81f32bc6e15e6b5e6c2440451c8b4af2126adf718b";
pub const TEST_RECIPIENT_IN_SEPOLIA: &str = "c2E0b1526E677EA0a856Ec6F50E708502F7fefa9";

pub fn get_native_asset() -> AssetId {
    AssetId::from_str("0xf8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07").unwrap()
}

pub fn load_json_addresses() -> Value {
    let path = "../infra/configs/agent-config.json";
    let data = fs::read_to_string(path).expect("Unable to read JSON config file");
    serde_json::from_str(&data).expect("JSON format error")
}

pub fn get_value_from_json(chain_name: &str, path: &[&str]) -> Value {
    let json_addresses = load_json_addresses();

    let mut current_value = &json_addresses["chains"][chain_name];

    for &key in path {
        current_value = &current_value[key];
    }

    current_value.clone()
}

pub fn get_contract_id_from_json(chain_name: &str, path: &[&str]) -> ContractId {
    let value = get_value_from_json(chain_name, path);
    stip_address_prefix(value)
}

pub fn stip_address_prefix(value: Value) -> ContractId {
    let value_str = value.as_str().unwrap_or_default();
    let value_str_stripped = value_str.strip_prefix("0x").unwrap();
    ContractId::from_str(value_str_stripped).unwrap()
}

pub async fn get_native_balance(provider: &Provider) -> u64 {
    let asset = get_native_asset();
    let address = Address::from_str(TEST_RECIPIENT_IN_FUEL).unwrap();
    provider
        .get_asset_balance(&address.into(), asset)
        .await
        .unwrap()
}

pub async fn get_bridged_balance(provider: &Provider, asset_id: AssetId) -> u64 {
    let address = Address::from_str(TEST_RECIPIENT_IN_FUEL).unwrap();

    provider
        .get_asset_balance(&address.into(), asset_id)
        .await
        .unwrap()
}

// pub async fn get_contract_balance(provider: &Provider, contract_id: ContractId) -> u64 {
//     let asset = get_native_asset();

//     provider
//         .get_contract_asset_balance(&Bech32ContractId::from(contract_id), asset)
//         .await
//         .unwrap()
// }

pub async fn send_token_to_contract(from: WalletUnlocked, to: &Bech32ContractId, amount: u64) {
    let _ = from
        .force_transfer_to_contract(to, amount, get_native_asset(), TxPolicies::default())
        .await;
}
