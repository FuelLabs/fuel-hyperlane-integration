use fuels::prelude::*;
use serde_json::Value;
use std::fs;
use std::str::FromStr;

use crate::utils::mocks::constants::*;

#[allow(dead_code)]
pub struct TokenMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64,
}

pub fn get_collateral_asset() -> AssetId {
    AssetId::from_str(BRIDGED_ASSET_ID).unwrap()
}

pub fn get_native_asset() -> AssetId {
    AssetId::default()
}

pub fn get_local_fuel_base_asset() -> AssetId {
    let file_path = "../infra/configs/local-fuel-snapshot/chain_config.json";
    let contents = fs::read_to_string(file_path).expect("Should have been able to read the file");

    let json: Value = serde_json::from_str(&contents).expect("JSON was not well-formatted");

    let base_asset_id = json["consensus_parameters"]["V2"]["base_asset_id"]
        .as_str()
        .expect("base_asset_id should be a string");

    AssetId::from_str(base_asset_id).unwrap()
}

pub fn get_token_metadata() -> TokenMetadata {
    TokenMetadata {
        name: "TestToken".to_string(),
        symbol: "TT".to_string(),
        decimals: BASE_ASSET_DECIMALS,
        total_supply: 100_000_000_000_000,
    }
}

pub async fn get_balance(
    provider: &Provider,
    address: &Bech32Address,
    asset: AssetId,
) -> std::result::Result<u64, Error> {
    provider.get_asset_balance(address, asset).await
}

pub async fn get_contract_balance(
    provider: &Provider,
    contract_id: &Bech32ContractId,
    asset: AssetId,
) -> std::result::Result<u64, Error> {
    provider
        .get_contract_asset_balance(contract_id, asset)
        .await
}

#[allow(dead_code)]
pub async fn send_gas_to_contract(from: WalletUnlocked, to: &Bech32ContractId, amount: u64) {
    let _ = from
        .force_transfer_to_contract(to, amount, get_native_asset(), TxPolicies::default())
        .await;
}

pub async fn send_gas_to_contract_2(
    from: WalletUnlocked,
    to: &Bech32ContractId,
    amount: u64,
    asset: AssetId,
) {
    let _ = from
        .force_transfer_to_contract(to, amount, asset, TxPolicies::default())
        .await;
}
