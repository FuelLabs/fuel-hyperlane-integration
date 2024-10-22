use crate::{
    cases::TestCase,
    setup::{abis::WarpRoute, get_loaded_wallet},
    utils::{
        local_contracts::{get_contract_address_from_yaml, get_value_from_agent_config_json},
        mocks::constants::TEST_RECIPIENT,
        token::{
            get_balance, get_contract_balance, get_local_fuel_base_asset, send_gas_to_contract_2,
        },
    },
};
use fuels::{
    programs::calls::CallParameters,
    types::{transaction_builders::VariableOutputPolicy, Address, Bits256},
};
use tokio::time::Instant;

async fn bridged_asset_send() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;
    let warp_route_id = get_contract_address_from_yaml("warpRouteBridged");

    let warp_route_instance = WarpRoute::new(warp_route_id, wallet.clone());
    let base_asset = get_local_fuel_base_asset();

    let remote_domain = get_value_from_agent_config_json("test1", "domainId")
        .unwrap()
        .as_u64()
        .map(|v| v as u32)
        .unwrap_or(9913371);

    let amount = 100_000;

    //get token info
    let token_info = warp_route_instance
        .methods()
        .get_token_info()
        .call()
        .await
        .map_err(|e| format!("Failed to get token info: {:?}", e))?;

    let asset_id = token_info.value.asset_id;

    let wallet_balance_before_mint =
        get_balance(wallet.provider().unwrap(), wallet.address(), asset_id)
            .await
            .unwrap();

    //mint testing tokens to owner
    let mint_amount = 200_000;
    warp_route_instance
        .methods()
        .mint_tokens(Address::from(wallet.address()), mint_amount)
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .determine_missing_contracts(Some(5))
        .await
        .unwrap()
        .call()
        .await
        .map_err(|e| format!("Failed to mint and transfer tokens: {:?}", e))?;

    let wallet_balance = get_balance(wallet.provider().unwrap(), wallet.address(), asset_id)
        .await
        .unwrap();

    if wallet_balance - wallet_balance_before_mint != mint_amount {
        return Err(format!(
            "Wallet balance after mint does not match mint amount: {:?}",
            wallet_balance - wallet_balance_before_mint
        ));
    }

    //get updated token info
    let token_info_updated = warp_route_instance
        .methods()
        .get_token_info()
        .call()
        .await
        .unwrap();

    if token_info_updated.value.total_supply != token_info.value.total_supply + mint_amount {
        return Err(format!(
            "Total supply after mint does not match mint amount: {:?}",
            token_info_updated.value.total_supply
        ));
    }

    let fuel_mailbox_id = get_contract_address_from_yaml("mailbox");
    let fuel_igp_hook_id = get_contract_address_from_yaml("interchainGasPaymasterHook");
    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let gas_oracle_id = get_contract_address_from_yaml("interchainGasPaymasterOracle");
    let post_dispatch_hook_id = get_contract_address_from_yaml("postDispatch");

    let test_recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();

    let _ = send_gas_to_contract_2(
        wallet.clone(),
        warp_route_instance.contract_id(),
        50_000_000,
        base_asset,
    )
    .await;

    let _ = warp_route_instance
        .methods()
        .transfer_remote(remote_domain, test_recipient, amount)
        .call_params(CallParameters::new(amount, asset_id, 20_000_000))
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
    TestCase::new("bridged_asset_send", bridged_asset_send)
}
