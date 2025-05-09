use crate::{
    cases::TestCase,
    evm::{get_evm_wallet, monitor_fuel_for_delivery, SepoliaContracts},
    setup::{
        abis::{Mailbox, MsgRecipient, WarpRoute},
        get_loaded_wallet,
    },
    utils::{
        get_evm_domain, get_fuel_domain, get_fuel_test_recipient,
        local_contracts::{get_contract_address_from_yaml, load_remote_wr_addresses},
        token::{get_contract_balance, send_gas_to_contract_2},
    },
};
use alloy::primitives::{FixedBytes, U256};
use fuels::types::{AssetId, Bits256};
use tokio::time::Instant;

async fn native_asset_recieve() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;
    let base_asset = AssetId::BASE;
    let evm_domain = get_evm_domain();
    let amount = 10_000_000_000_000;

    let warp_route_id = get_contract_address_from_yaml("warpRouteNative");
    let mailbox_id = get_contract_address_from_yaml("mailbox");
    let msg_recipient = get_contract_address_from_yaml("testRecipient");

    let warp_route_instance = WarpRoute::new(warp_route_id, wallet.clone());
    let mailbox_instance = Mailbox::new(mailbox_id, wallet.clone());
    let _msg_recipient_instance = MsgRecipient::new(msg_recipient, wallet.clone());

    let _ = send_gas_to_contract_2(
        wallet.clone(),
        warp_route_instance.contract_id(),
        amount,
        base_asset,
    )
    .await;

    let contract_balance = get_contract_balance(
        wallet.provider(),
        warp_route_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    let remote_wr_address = load_remote_wr_addresses("NTR").unwrap();
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
    let contracts = SepoliaContracts::initialize(remote_wallet).await;

    let remote_wr = contracts.warp_route_collateral;
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

    let _ = remote_wr
        .transferRemote_1(fuel_domain, recipient, U256::from(amount))
        .value(quote_dispatch + U256::from(amount))
        .send()
        .await
        .unwrap()
        .watch()
        .await
        .map_err(|e| format!("Failed enroll router: {:?}", e))?;

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
        base_asset,
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

    println!("✅ native_asset_recieve test passed");

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("native_asset_recieve", native_asset_recieve)
}
