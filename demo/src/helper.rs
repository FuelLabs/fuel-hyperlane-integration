use fuels::{
    accounts::provider::Provider,
    types::{
        bech32::{Bech32Address, Bech32ContractId},
        Address, AssetId, ContractId,
    },
};
use serde_json::Value;
use std::{fs, str::FromStr};

pub fn get_native_asset() -> AssetId {
    AssetId::from_str("0xf8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07").unwrap()
}

pub fn get_bridged_asset() -> AssetId {
    AssetId::from_str("5e2d6d5f8832e11cd8c00053ea56acd7ed2f5256b87b39d47c651a2e6f9abdab").unwrap()
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

pub async fn get_native_balance(provider: &Provider, address: &Bech32Address) -> u64 {
    let asset = get_native_asset();
    provider.get_asset_balance(address, asset).await.unwrap()
}

pub async fn get_bridged_balance_of_recipient(provider: &Provider) -> u64 {
    let asset = get_bridged_asset();
    let address = "a347fa1775198aa68fb1a4523a4925f891cca8f4dc79bf18ca71274c49f600c3";

    let recipient_address = Address::from_str(address).unwrap();

    provider
        .get_asset_balance(&recipient_address.into(), asset)
        .await
        .unwrap()
}

pub async fn get_contract_balance(provider: &Provider, contract_id: ContractId) -> u64 {
    let asset = get_native_asset();

    provider
        .get_contract_asset_balance(&Bech32ContractId::from(contract_id), asset)
        .await
        .unwrap()
}
