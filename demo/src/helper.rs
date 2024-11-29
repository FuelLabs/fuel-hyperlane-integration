use fuels::{
    accounts::{provider::Provider, wallet::WalletUnlocked, Account},
    types::{bech32::Bech32ContractId, transaction::TxPolicies, Address, AssetId, ContractId},
};
use serde::Deserialize;
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

#[derive(Debug, Deserialize)]
pub struct YamlConfig {
    #[serde(rename = "testRecipient")]
    test_recipient: String,
    #[serde(rename = "aggregationISM")]
    aggregation_ism: String,
    #[serde(rename = "domainRoutingISM")]
    domain_routing_ism: String,
    #[serde(rename = "fallbackDomainRoutingISM")]
    fallback_domain_routing_ism: String,
    #[serde(rename = "messageIdMultisigISM")]
    message_id_multisig_ism: String,
    #[serde(rename = "merkleRootMultisigISM")]
    merkle_root_multisig_ism: String,
    #[serde(rename = "interchainSecurityModule")]
    test_ism: String,
}

pub struct ParsedYamlConfig {
    pub test_recipient: ContractId,
    pub aggregation_ism: ContractId,
    pub domain_routing_ism: ContractId,
    pub fallback_domain_routing_ism: ContractId,
    pub message_id_multisig_ism: ContractId,
    pub merkle_root_multisig_ism: ContractId,
    pub test_ism: ContractId,
}

impl From<YamlConfig> for ParsedYamlConfig {
    fn from(config: YamlConfig) -> Self {
        ParsedYamlConfig {
            test_ism: ContractId::from_str(config.test_ism.as_str().strip_prefix("0x").unwrap())
                .unwrap(),
            test_recipient: ContractId::from_str(
                config.test_recipient.as_str().strip_prefix("0x").unwrap(),
            )
            .unwrap(),
            aggregation_ism: ContractId::from_str(
                config.aggregation_ism.as_str().strip_prefix("0x").unwrap(),
            )
            .unwrap(),
            domain_routing_ism: ContractId::from_str(
                config
                    .domain_routing_ism
                    .as_str()
                    .strip_prefix("0x")
                    .unwrap(),
            )
            .unwrap(),
            fallback_domain_routing_ism: ContractId::from_str(
                config
                    .fallback_domain_routing_ism
                    .as_str()
                    .strip_prefix("0x")
                    .unwrap(),
            )
            .unwrap(),
            message_id_multisig_ism: ContractId::from_str(
                config
                    .message_id_multisig_ism
                    .as_str()
                    .strip_prefix("0x")
                    .unwrap(),
            )
            .unwrap(),
            merkle_root_multisig_ism: ContractId::from_str(
                config
                    .merkle_root_multisig_ism
                    .as_str()
                    .strip_prefix("0x")
                    .unwrap(),
            )
            .unwrap(),
        }
    }
}

pub fn read_deployments_yaml() -> ParsedYamlConfig {
    let path = "../deploy/deployments/testnet/contract_addresses.yaml";
    let data = fs::read_to_string(path).expect("Unable to read YAML config file");
    let raw_config: YamlConfig = serde_yaml::from_str(&data).expect("YAML format error");
    ParsedYamlConfig::from(raw_config)
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

pub fn get_fuel_chain_id() -> u32 {
    get_value_from_json("fueltestnet", &["domainId"])
        .as_u64()
        .unwrap() as u32
}

pub fn get_basesepolia_chain_id() -> u32 {
    get_value_from_json("basesepolia", &["domainId"])
        .as_u64()
        .unwrap() as u32
}

pub fn stip_address_prefix(value: Value) -> ContractId {
    let value_str = value.as_str().unwrap_or_default();
    let value_str_stripped = value_str.strip_prefix("0x").unwrap();
    ContractId::from_str(value_str_stripped).unwrap()
}

pub async fn get_native_balance(provider: &Provider, recipient: ContractId) -> u64 {
    let asset = get_native_asset();
    let address = Address::from_str(recipient.to_string().as_str()).unwrap();

    provider
        .get_asset_balance(&address.into(), asset)
        .await
        .unwrap()
}

pub async fn get_bridged_balance(
    provider: &Provider,
    asset_id: AssetId,
    recipient: ContractId,
) -> u64 {
    let address = Address::from_str(recipient.to_string().as_str()).unwrap();

    provider
        .get_asset_balance(&address.into(), asset_id)
        .await
        .unwrap()
}

pub async fn _get_native_balance_of_wallet(provider: &Provider, wallet: &WalletUnlocked) -> u64 {
    let asset = get_native_asset();
    provider
        .get_asset_balance(&wallet.address().into(), asset)
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

pub async fn send_token_to_contract(from: WalletUnlocked, to: &Bech32ContractId, amount: u64) {
    let _ = from
        .force_transfer_to_contract(to, amount, get_native_asset(), TxPolicies::default())
        .await;
}

pub fn _write_demo_run_to_file(entires: Vec<String>) {
    let full_path = "./demo-run.log".to_string();
    let path = Path::new(&full_path);

    if let Some(parent) = path.parent() {
        create_dir_all(parent).unwrap();
    }
    let mut file = File::create(full_path.clone()).unwrap();
    for entry in entires {
        writeln!(file, "{}", entry).unwrap();
    }
}
