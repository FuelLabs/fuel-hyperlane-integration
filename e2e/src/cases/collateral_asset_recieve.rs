use crate::{
    cases::TestCase,
    evm::{get_evm_wallet, monitor_fuel_for_delivery, SepoliaContracts},
    setup::{
        abis::{Mailbox, MsgRecipient, WarpRoute},
        get_loaded_wallet,
    },
    utils::{
        get_fuel_test_recipient, get_local_domain,
        local_contracts::get_contract_address_from_yaml,
        token::{get_contract_balance, get_local_fuel_base_asset, send_gas_to_contract_2},
    },
};
use alloy::primitives::{FixedBytes, U256};
use tokio::time::Instant;

async fn collateral_asset_recieve() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;
    let base_asset = get_local_fuel_base_asset();
    let amount = 10_000_000_000_000;

    let warp_route_id = get_contract_address_from_yaml("warpRoute");
    let mailbox_id = get_contract_address_from_yaml("mailbox");
    let msg_recipient = get_contract_address_from_yaml("testRecipient");

    let warp_route_instance = WarpRoute::new(warp_route_id, wallet.clone());
    let mailbox_instance = Mailbox::new(mailbox_id, wallet.clone());
    let msg_recipient_instance = MsgRecipient::new(msg_recipient, wallet.clone());

    let _ = send_gas_to_contract_2(
        wallet.clone(),
        warp_route_instance.contract_id(),
        1_000_000_000_000,
        base_asset,
    )
    .await;

    let contract_balance = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    let recipient_balance = get_contract_balance(
        wallet.provider().unwrap(),
        msg_recipient_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    let recipient = get_fuel_test_recipient();
    println!("recipient for remote {:?}", recipient);
    println!(
        "recipient fuel checks {:?}",
        msg_recipient_instance.contract_id()
    );

    let fuel_domain = get_local_domain();

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

    let recipient_final_balance = get_contract_balance(
        wallet.provider().unwrap(),
        msg_recipient_instance.contract_id(),
        base_asset,
    )
    .await
    .map_err(|e| format!("Failed to get final balance: {:?}", e))?;

    let amount_18dec_to_local = amount / 10u64.pow(18 - 9);

    let contract_final_balance = get_contract_balance(
        wallet.provider().unwrap(),
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

    if recipient_final_balance != recipient_balance + amount_18dec_to_local {
        return Err(format!(
            "Final balance mismatch. Expected: {}, Got: {}",
            recipient_balance + amount_18dec_to_local,
            recipient_final_balance
        ));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("collateral_asset_recieve", collateral_asset_recieve)
}
