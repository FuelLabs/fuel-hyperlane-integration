use fuels::{
    accounts::provider::Provider,
    types::{bech32::Bech32Address, AssetId, ContractId},
};
use serde_json::Value;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use std::{fs, str::FromStr};

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

pub async fn get_native_balance(provider: &Provider, address: &Bech32Address) -> u64 {
    let asset = get_native_asset();
    provider.get_asset_balance(address, asset).await.unwrap()
}

pub fn write_demo_run_to_file(entires: Vec<String>) {
    let full_path = format!("./demo-run.log");
    let path = Path::new(&full_path);

    if let Some(parent) = path.parent() {
        create_dir_all(parent).unwrap();
    }
    let mut file = File::create(full_path.clone()).unwrap();
    for entry in entires {
        writeln!(file, "{}", entry).unwrap();
    }
}
