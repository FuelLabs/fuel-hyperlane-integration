use fuels::prelude::*;
use std::str::FromStr;

use crate::utils::constants::*;

pub struct TokenMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64,
}
//Token Metadata Example (COLLATERAL)
//TokenMetadata {
// name: "TestToken",
// symbol: "TT",
// decimals: 9,
// total_supply: 100000000000000,
// asset_id: 0000000000000000000000000000000000000000000000000000000000000000,
// sub_id: Bits256([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
// },

pub fn get_collateral_asset() -> AssetId {
    AssetId::from_str(BRIDGED_ASSET_ID).unwrap()
}

pub fn get_native_asset() -> AssetId {
    AssetId::default()
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

pub async fn send_gas_to_contract(from: WalletUnlocked, to: &Bech32ContractId, amount: u64) {
    let _ = from
        .force_transfer_to_contract(to, amount, get_native_asset(), TxPolicies::default())
        .await;
}
