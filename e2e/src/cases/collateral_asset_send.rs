use crate::{
    cases::TestCase,
    evm::{get_evm_wallet, monitor_evm_for_delivery, SepoliaContracts},
    setup::{abis::WarpRoute, get_loaded_wallet},
    utils::{
        get_evm_domain, get_fuel_domain, get_remote_test_recipient,
        get_remote_test_recipient_address,
        local_contracts::*,
        token::{get_contract_balance, send_asset_to_contract},
    },
};
use alloy::primitives::{FixedBytes, U256};
use fuels::{
    programs::calls::CallParameters,
    types::{transaction_builders::VariableOutputPolicy, AssetId, Bits256},
};
use tokio::time::Instant;

async fn collateral_asset_send() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;

    let base_asset = AssetId::BASE;

    let evm_domain = get_evm_domain();
    let amount = 1000;
    let test_recipient = get_remote_test_recipient();

    let warp_route_id = get_contract_address_from_yaml("warpRouteCollateral");
    let fuel_mailbox_id = get_contract_address_from_yaml("mailbox");
    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let gas_oracle_id = get_contract_address_from_yaml("gasOracle");
    let post_dispatch_hook_id = get_contract_address_from_yaml("postDispatch");

    let warp_route_instance = WarpRoute::new(warp_route_id, wallet.clone());

    let remote_wr = load_remote_wr_addresses("CTR").unwrap();
    let remote_wr_hex = hex::decode(remote_wr.strip_prefix("0x").unwrap()).unwrap();

    let mut remote_wr_array = [0u8; 32];
    remote_wr_array[12..].copy_from_slice(&remote_wr_hex);

    let fuel_domain = get_fuel_domain();
    let remote_wallet = get_evm_wallet().await;

    let remote_contracts = SepoliaContracts::initialize(remote_wallet.clone()).await;
    let evm_wr_instance = remote_contracts.warp_route_collateral;
    let fuel_wr_parsed = FixedBytes::from_slice(warp_route_id.as_slice());

    evm_wr_instance
        .enrollRemoteRouter(fuel_domain, fuel_wr_parsed)
        .send()
        .await
        .unwrap()
        .watch()
        .await
        .map_err(|e| format!("Failed enroll router: {:?}", e))?;

    warp_route_instance
        .methods()
        .enroll_remote_router(evm_domain, Bits256(remote_wr_array))
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
        .quote_gas_payment(evm_domain)
        .determine_missing_contracts()
        .await
        .unwrap()
        .call()
        .await
        .map_err(|e| format!("Failed to get quote from warp route: {:?}", e))?;

    let fuel_token = warp_route_instance
        .methods()
        .get_token_info()
        .call()
        .await
        .unwrap()
        .value;

    let collateral_token_asset_id = fuel_token.asset_id;
    let collateral_token_decimals = fuel_token.decimals;

    let wallet_address = remote_wallet.default_signer().address();
    let wallet_balance_before = remote_contracts
        .collateral_asset
        .balanceOf(wallet_address)
        .call()
        .await
        .unwrap()
        ._0;

    remote_contracts
        .collateral_asset
        .transfer(*evm_wr_instance.address(), U256::from(amount))
        .send()
        .await
        .unwrap()
        .watch()
        .await
        .map_err(|e| format!("Failed to transfer tokens to contract: {:?}", e))?;

    let test_recipient_addr = get_remote_test_recipient_address();
    let remote_balance_before = evm_wr_instance
        .balanceOf(test_recipient_addr)
        .call()
        .await
        .unwrap()
        ._0;

    let warp_base_balance_before = get_contract_balance(
        wallet.provider(),
        warp_route_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    let collateral_token_balance_before = get_contract_balance(
        wallet.provider(),
        warp_route_instance.contract_id(),
        collateral_token_asset_id,
    )
    .await
    .unwrap();

    let _ = send_asset_to_contract(
        wallet.clone(),
        warp_route_instance.contract_id(),
        amount,
        collateral_token_asset_id,
    )
    .await;

    let _ = warp_route_instance
        .methods()
        .transfer_remote(evm_domain, test_recipient, amount, None, None)
        .call_params(CallParameters::new(quote.value, base_asset, 20_000_000))
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

    let warp_base_balance_after = get_contract_balance(
        wallet.provider(),
        warp_route_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    let collateral_token_balance_after = get_contract_balance(
        wallet.provider(),
        warp_route_instance.contract_id(),
        collateral_token_asset_id,
    )
    .await
    .unwrap();

    monitor_evm_for_delivery(*evm_wr_instance.address()).await;

    if warp_base_balance_after != warp_base_balance_before + quote.value {
        return Err(format!(
            "Warp balance is increased by {:?}, expected {:?}",
            warp_base_balance_after - warp_base_balance_before,
            amount
        ));
    }

    if collateral_token_balance_after - collateral_token_balance_before != amount {
        return Err(format!(
            "Collateral token balance is decreased by {:?}, expected {:?}",
            collateral_token_balance_after - collateral_token_balance_before,
            amount
        ));
    }

    let remote_balance_after = evm_wr_instance
        .balanceOf(test_recipient_addr)
        .call()
        .await
        .unwrap()
        ._0;

    if remote_balance_after - remote_balance_before
        != U256::from(amount * 10u64.pow(18 - collateral_token_decimals as u32))
    {
        return Err(format!(
            "Remote balance difference is {:?}, expected {:?}",
            remote_balance_after - remote_balance_before,
            amount * 10u64.pow(18 - collateral_token_decimals as u32)
        ));
    }

    // Verify wallet balance after transfer
    let wallet_balance_after = remote_contracts
        .collateral_asset
        .balanceOf(wallet_address)
        .call()
        .await
        .unwrap()
        ._0;

    if wallet_balance_before - wallet_balance_after != U256::from(amount) {
        return Err(format!(
            "Wallet balance decreased by {:?}, expected {:?}",
            wallet_balance_before - wallet_balance_after,
            amount
        ));
    }

    println!("✅ collateral_asset_send passed");

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("collateral_asset_send", collateral_asset_send)
}
