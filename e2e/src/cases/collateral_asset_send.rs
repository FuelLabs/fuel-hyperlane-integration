use crate::{
    cases::TestCase,
    setup::{abis::WarpRoute, get_loaded_wallet},
    utils::{
        local_contracts::{get_contract_address_from_yaml, get_value_from_agent_config_json},
        mocks::constants::TEST_RECIPIENT,
        token::{get_contract_balance, get_local_fuel_base_asset, send_gas_to_contract_2},
    },
};
use fuels::{
    programs::calls::CallParameters,
    types::{transaction_builders::VariableOutputPolicy, Bits256},
};
use tokio::time::Instant;

async fn collateral_asset_send() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;
    let warp_route_id = get_contract_address_from_yaml("warpRoute");

    let warp_route_instance = WarpRoute::new(warp_route_id, wallet.clone());
    let base_asset = get_local_fuel_base_asset();

    let remote_domain = get_value_from_agent_config_json("test1", "domainId")
        .unwrap()
        .as_u64()
        .map(|v| v as u32)
        .unwrap_or(9913371);

    let amount = 1000;

    let _ = send_gas_to_contract_2(
        wallet.clone(),
        warp_route_instance.contract_id(),
        1_000_000_000,
        base_asset,
    )
    .await;

    let fuel_mailbox_id = get_contract_address_from_yaml("mailbox");
    let fuel_igp_hook_id = get_contract_address_from_yaml("interchainGasPaymasterHook");
    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let gas_oracle_id = get_contract_address_from_yaml("interchainGasPaymasterOracle");
    let post_dispatch_hook_id = get_contract_address_from_yaml("postDispatch");

    let test_recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();

    let _ = warp_route_instance
        .methods()
        .transfer_remote(remote_domain, test_recipient, amount)
        .call_params(CallParameters::new(amount, base_asset, 20_000_000))
        .unwrap()
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .with_contract_ids(&[
            fuel_mailbox_id.into(),
            fuel_igp_hook_id.into(),
            igp_id.into(),
            gas_oracle_id.into(),
            post_dispatch_hook_id.into(),
        ])
        .call()
        .await
        .map_err(|e| format!("Failed to transfer remote message: {:?}", e))?;

    let warp_balance_after = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    if warp_balance_after != 0 {
        return Err(format!(
            "Warp balance after is not 0: {:?}",
            warp_balance_after
        ));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("collateral_asset_send", collateral_asset_send)
}
