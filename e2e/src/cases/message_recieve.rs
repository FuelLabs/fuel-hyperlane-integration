use alloy::primitives::FixedBytes;
use tokio::time::Instant;

use crate::{
    cases::TestCase,
    evm::{get_evm_wallet, monitor_fuel_for_delivery, SepoliaContracts},
    setup::{abis::Mailbox, get_loaded_wallet},
    utils::{
        get_fuel_domain, get_fuel_test_recipient, get_remote_msg_body,
        local_contracts::get_contract_address_from_json,
    },
};

async fn message_recieve() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;

    let fuel_mailbox_id = get_contract_address_from_json("fueltest1", "mailbox");
    let fuel_mailbox_instance = Mailbox::new(fuel_mailbox_id, wallet.clone());

    let wallet = get_evm_wallet().await;
    let contracts = SepoliaContracts::initialize(wallet.clone()).await;
    let remote_mailbox = contracts.mailbox;

    let recipient = get_fuel_test_recipient();
    let fuel_domain = get_fuel_domain();
    let body = get_remote_msg_body();

    let quote_dispatch = remote_mailbox
        .quoteDispatch_1(fuel_domain, recipient, body.clone())
        .call()
        .await
        .unwrap()
        .fee;

    let _dispatch_call = remote_mailbox
        .dispatch_2(fuel_domain, recipient, body.clone())
        .value(quote_dispatch)
        .send()
        .await
        .unwrap()
        .watch()
        .await;

    let msg_id = remote_mailbox.latestDispatchedId().call().await.unwrap()._0;

    if FixedBytes::const_is_zero(&msg_id) {
        return Err("Failed to deliver message".to_string());
    }

    let res = monitor_fuel_for_delivery(fuel_mailbox_instance, msg_id).await;

    assert!(res, "Failed to recieve message from remote");

    println!("✅ message_recieve test passed");

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("message_recieve", message_recieve)
}
