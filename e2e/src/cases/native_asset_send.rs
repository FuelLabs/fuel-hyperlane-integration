use crate::{
    cases::TestCase,
    setup::{abis::WarpRoute, get_loaded_wallet},
    utils::{
        get_remote_domain, get_remote_test_recipient,
        local_contracts::*,
        token::{get_contract_balance, get_local_fuel_base_asset},
    },
};
use fuels::{
    programs::calls::CallParameters,
    types::{transaction_builders::VariableOutputPolicy, Bits256},
};
use tokio::time::Instant;

async fn native_asset_send() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;

    let base_asset = get_local_fuel_base_asset();

    let remote_domain = get_remote_domain();
    let amount = 1000;
    let test_recipient = get_remote_test_recipient();

    let warp_route_id = get_contract_address_from_yaml("warpRouteNative");
    let fuel_mailbox_id = get_contract_address_from_yaml("mailbox");
    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let gas_oracle_id = get_contract_address_from_yaml("gasOracle");
    let post_dispatch_hook_id = get_contract_address_from_yaml("postDispatch");

    let warp_route_instance = WarpRoute::new(warp_route_id, wallet.clone());

    let remote_wr = load_remote_wr_addresses("CTR").unwrap();
    let remote_wr_hex = hex::decode(remote_wr.strip_prefix("0x").unwrap()).unwrap();

    let mut remote_wr_array = [0u8; 32];
    remote_wr_array[12..].copy_from_slice(&remote_wr_hex);

    warp_route_instance
        .methods()
        .enroll_remote_router(remote_domain, Bits256(remote_wr_array))
        .call()
        .await
        .map_err(|e| format!("Failed to enroll remote router: {:?}", e))?;

    warp_route_instance
        .methods()
        .set_remote_router_decimals(Bits256(remote_wr_array), 18)
        .call()
        .await
        .unwrap();

    let quote = warp_route_instance
        .methods()
        .quote_gas_payment(remote_domain)
        .determine_missing_contracts(Some(5))
        .await
        .unwrap()
        .call()
        .await
        .map_err(|e| format!("Failed to get quote from warp route: {:?}", e))?;

    let warp_balance_before = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    let _ = warp_route_instance
        .methods()
        .transfer_remote(remote_domain, test_recipient, amount)
        .call_params(CallParameters::new(
            amount + quote.value,
            base_asset,
            20_000_000,
        ))
        .unwrap()
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .with_contract_ids(&[
            fuel_mailbox_id.into(),
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

    if warp_balance_after != warp_balance_before + amount {
        return Err(format!(
            "Warp balance is increased by {:?}, expected {:?}",
            warp_balance_after - warp_balance_before,
            amount
        ));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("native_asset_send", native_asset_send)
}
