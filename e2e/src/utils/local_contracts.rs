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

// pub fn get_bech32_contract_address(address: &str) -> Bech32ContractId {
//     let address_bytes =
//         hex::decode(address.trim_start_matches("0x")).expect("Failed to decode hex string");

//     let contract_id = if address_bytes.len() == 20 {
//         // Ethereum address (20 bytes) - TODO: look for a better way to handle this
//         let mut padded = [0u8; 32];
//         padded[12..].copy_from_slice(&address_bytes);
//         ContractId::new(padded)
//     } else if address_bytes.len() == 32 {
//         // Fuel contract ID (32 bytes)
//         ContractId::new(address_bytes.try_into().unwrap())
//     } else {
//         panic!("Invalid address length: expected 20 or 32 bytes");
//     };

//     let address_bech32 = Bech32ContractId::from(contract_id);
//     println!(
//         "Successfully created Bech32ContractId: {:?}",
//         address_bech32
//     );

//     address_bech32
// }

// pub async fn get_mailbox_from_chains() -> Mailbox<WalletUnlocked> {
//     let wallet = get_loaded_wallet().await;

//     let mailbox_address = get_contract_address_from_json("test1", "mailbox");
//     println!("mailbox address from json {:?}", mailbox_address);
//     let mailbox_bech32 = get_bech32_contract_address(&mailbox_address);
//     println!("mailbox bech32 from json {:?}", mailbox_bech32);

//     let mailbox = Mailbox::new(mailbox_bech32, wallet.clone());
//     println!("----------------------------");
//     println!("{:?}", mailbox);
//     println!("----------------------------");
//     println!("Mailbox address from setup: {:?}", mailbox.contract_id());

//     let domain_res = mailbox
//         .methods()
//         .local_domain()
//         .with_contracts(&[&mailbox])
//         .with_contract_ids(&[mailbox.contract_id().clone()])
//         .call()
//         .await;
//     println!("{:?}", domain_res);

//     mailbox
// }
