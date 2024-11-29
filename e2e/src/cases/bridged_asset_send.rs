use crate::{
    cases::TestCase,
    setup::{abis::WarpRoute, get_loaded_wallet},
    utils::{
        build_message_body, get_remote_domain,
        local_contracts::{get_contract_address_from_yaml, load_remote_wr_addresses},
        token::{
            get_balance, get_contract_balance, get_local_fuel_base_asset, send_gas_to_contract_2,
        },
        TEST_RECIPIENT,
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
    let fuel_mailbox_id = get_contract_address_from_yaml("mailbox");
    let fuel_igp_hook_id = get_contract_address_from_yaml("interchainGasPaymasterHook");
    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let gas_oracle_id = get_contract_address_from_yaml("gasOracle");
    let post_dispatch_hook_id = get_contract_address_from_yaml("postDispatch");

    let base_asset = get_local_fuel_base_asset();
    let remote_domain = get_remote_domain();
    let amount = 100_000;

    let test_recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
    let remote_wr = load_remote_wr_addresses("STR").unwrap();
    let remote_wr_hex = hex::decode(remote_wr.strip_prefix("0x").unwrap()).unwrap();

    let mut remote_wr_array = [0u8; 32];
    remote_wr_array[12..].copy_from_slice(&remote_wr_hex);

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

    //minting is same as recieving remote adjusted amount
    //if 1*10^18 is sent, the minted amount is 1*10^(18-local_decimals)
    let local_decimals = token_info.value.decimals;
    let remote_adjusted_amount = amount * 10u64.pow(18 - local_decimals as u32);

    let body = build_message_body(
        Bits256(Address::from(wallet.address()).into()),
        remote_adjusted_amount,
    );

    warp_route_instance
        .methods()
        .set_remote_router_decimals(test_recipient, 18)
        .call()
        .await
        .unwrap();

    warp_route_instance
        .methods()
        .handle(remote_domain, test_recipient, body)
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .call()
        .await
        .unwrap();

    let wallet_balance = get_balance(wallet.provider().unwrap(), wallet.address(), asset_id)
        .await
        .unwrap();

    if wallet_balance - wallet_balance_before_mint != amount {
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

    if token_info_updated.value.total_supply != token_info.value.total_supply + amount {
        return Err(format!(
            "Total supply after mint does not match mint amount: {:?}",
            token_info_updated.value.total_supply
        ));
    }

    let _ = send_gas_to_contract_2(
        wallet.clone(),
        warp_route_instance.contract_id(),
        50_000_000,
        base_asset,
    )
    .await;

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
        .map_err(|e| format!("Failed to set remote router decimals: {:?}", e))?;

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
        asset_id,
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
