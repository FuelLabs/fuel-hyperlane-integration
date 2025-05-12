use fuels::prelude::*;

pub fn get_native_asset() -> AssetId {
    AssetId::default()
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

pub async fn send_asset_to_contract(
    from: Wallet,
    to: &Bech32ContractId,
    amount: u64,
    asset: AssetId,
) {
    from.force_transfer_to_contract(to, amount, asset, TxPolicies::default())
        .await
        .unwrap();
}
