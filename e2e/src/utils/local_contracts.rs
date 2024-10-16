use fuels::prelude::*;
use serde_json::Value as JsonValue;
use std::{collections::HashMap, fs, str::FromStr};

fn load_json_addresses() -> JsonValue {
    let path = "../infra/configs/agent-config-local.json";
    let data = fs::read_to_string(path).expect("Unable to read JSON config file");
    serde_json::from_str(&data).expect("JSON format error")
}

pub fn load_yaml_addresses() -> HashMap<String, String> {
    let path = "../infra/output/contracts/local/contract_addresses.yaml";
    let data = fs::read_to_string(path).expect("Unable to read YAML addresses file");
    let values: HashMap<String, String> = serde_yaml::from_str(&data).expect("YAML format error");
    values
}

pub fn get_value_from_agent_config_json(chain_name: &str, key: &str) -> Option<JsonValue> {
    let json_addresses = load_json_addresses();
    let res = json_addresses["chains"][chain_name][key].clone();
    if res.is_null() {
        None
    } else {
        Some(res)
    }
}
pub fn get_contract_address_from_yaml(contract_name: &str) -> ContractId {
    let yaml_addresses = load_yaml_addresses();
    let res = yaml_addresses
        .get(contract_name)
        .expect("Key not found in YAML");
    ContractId::from_str(res).unwrap()
}

pub fn get_contract_address_from_json(chain_name: &str, contract_name: &str) -> ContractId {
    let json_addresses = load_json_addresses();

    let address = json_addresses["chains"][chain_name][contract_name]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "Key not found in JSON for {} chain {}",
                chain_name, contract_name
            )
        });

    ContractId::from_str(address).unwrap()
}
