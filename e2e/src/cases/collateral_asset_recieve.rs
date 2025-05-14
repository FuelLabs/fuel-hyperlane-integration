use crate::{
    cases::TestCase,
    evm::{get_evm_wallet, monitor_fuel_for_delivery, SepoliaContracts},
    setup::{
        abis::{Mailbox, WarpRoute},
        get_loaded_wallet,
    },
    utils::{
        get_evm_domain, get_fuel_domain, get_fuel_test_recipient,
        local_contracts::{get_contract_address_from_yaml, load_remote_wr_addresses},
        token::{get_contract_balance, send_asset_to_contract},
    },
};
use alloy::primitives::{FixedBytes, U256};
use fuels::types::Bits256;
use tokio::time::Instant;

async fn collateral_asset_recieve() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;
    let evm_domain = get_evm_domain();
    let amount = 10_000_000_000_000;

    let warp_route_id = get_contract_address_from_yaml("warpRouteCollateral");
    let mailbox_id = get_contract_address_from_yaml("mailbox");

    let warp_route_instance = WarpRoute::new(warp_route_id, wallet.clone());
    let mailbox_instance = Mailbox::new(mailbox_id, wallet.clone());

    let wr_asset_id = warp_route_instance
        .methods()
        .get_token_info()
        .call()
        .await
        .unwrap()
        .value
        .asset_id;

    send_asset_to_contract(
        wallet.clone(),
        warp_route_instance.contract_id(),
        amount,
        wr_asset_id,
    )
    .await;

    let contract_balance = get_contract_balance(
        wallet.provider(),
        warp_route_instance.contract_id(),
        wr_asset_id,
    )
    .await
    .unwrap();

    let remote_wr_address = load_remote_wr_addresses("CTR").unwrap();
    let remote_wr_hex = hex::decode(remote_wr_address.strip_prefix("0x").unwrap()).unwrap();

    let mut remote_wr_array = [0u8; 32];
    remote_wr_array[12..].copy_from_slice(&remote_wr_hex);

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

    let recipient = get_fuel_test_recipient();
    let fuel_domain = get_fuel_domain();

    let remote_wallet = get_evm_wallet().await;
    let contracts = SepoliaContracts::initialize(remote_wallet.clone()).await;

    let remote_wr = contracts.warp_route_collateral;
    let collateral_asset_evm = contracts.collateral_asset;

    let fuel_wr_parsed = FixedBytes::from_slice(warp_route_id.as_slice());

    let _ = remote_wr
        .enrollRemoteRouter(fuel_domain, fuel_wr_parsed)
        .send()
        .await
        .unwrap()
        .watch()
        .await
        .map_err(|e| format!("Failed enroll router: {:?}", e))?;

    let quote_dispatch = remote_wr
        .quoteGasPayment(fuel_domain)
        .call()
        .await
        .unwrap()
        ._0;

    let remote_balance_before = remote_wr
        .balanceOf(remote_wallet.default_signer().address())
        .call()
        .await
        .unwrap()
        ._0;

    collateral_asset_evm
        .approve(*remote_wr.address(), remote_balance_before)
        .send()
        .await
        .unwrap()
        .watch()
        .await
        .map_err(|e| format!("Failed to approve tokens: {:?}", e))?;

    let _ = remote_wr
        .transferRemote_1(fuel_domain, recipient, U256::from(amount))
        .value(quote_dispatch)
        .send()
        .await
        .unwrap()
        .watch()
        .await
        .map_err(|e| format!("Failed to transfer remote: {:?}", e))?;

    let remote_mailbox = contracts.mailbox;
    let msg_id = remote_mailbox.latestDispatchedId().call().await.unwrap()._0;

    if FixedBytes::const_is_zero(&msg_id) {
        return Err("Failed to deliver message".to_string());
    }

    let res = monitor_fuel_for_delivery(mailbox_instance, msg_id).await;

    assert!(res, "Failed to recieve message from remote");

    let amount_18dec_to_local = amount / 10u64.pow(18 - 9);

    let contract_final_balance = get_contract_balance(
        wallet.provider(),
        warp_route_instance.contract_id(),
        wr_asset_id,
    )
    .await
    .unwrap();

    if contract_balance - contract_final_balance != amount_18dec_to_local {
        return Err(format!(
            "Final contract balance mismatch. Expected: {}, Got: {}",
            amount_18dec_to_local,
            contract_balance - contract_final_balance
        ));
    }

    let remote_balance_after = collateral_asset_evm
        .balanceOf(remote_wallet.default_signer().address())
        .call()
        .await
        .unwrap()
        ._0;

    let expected_diff = U256::from(amount);
    if remote_balance_before >= remote_balance_after {
        return Err(format!(
            "Remote balance didn't increase as expected. Diff: {}, Expected: {}",
            remote_balance_after - remote_balance_before,
            expected_diff
        ));
    }

    println!("✅ collateral_asset_recieve passed");

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("collateral_asset_recieve", collateral_asset_recieve)
}
