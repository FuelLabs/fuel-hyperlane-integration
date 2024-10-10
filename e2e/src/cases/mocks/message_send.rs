use super::TestCase;
use crate::{
    setup::*,
    utils::{
        _test_message,
        constants::{TEST_RECIPIENT, TEST_REMOTE_DOMAIN},
        contract_registry::ContractRegistry,
        hyperlane_message_to_bytes,
        token::{self, get_balance, get_contract_balance},
    },
};
use fuels::{
    programs::calls::CallParameters,
    types::{Bits256, Bytes},
};
use std::sync::Arc;
use token::get_native_asset;
use tokio::time::Instant;

async fn mock_message_send(registry: Arc<ContractRegistry>) -> Result<f64, String> {
    let start = Instant::now();
    let wallet = get_loaded_wallet().await;

    let mailbox = registry.mailbox.clone();
    let igp = registry.igp.clone();
    let igp_hook = registry.igp_hook.clone();
    let gas_oracle = registry.gas_oracle.clone();
    let msg_recipient = registry.msg_recipient.clone();
    let aggregation_ism = registry.aggregation_ism.clone();

    let wallet_balance = get_balance(
        wallet.provider().unwrap(),
        wallet.address(),
        get_native_asset(),
    )
    .await
    .unwrap();

    let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
    let amount = 100_000u64;

    let message = _test_message(&mailbox, msg_recipient.contract_id(), amount);
    let message_bytes = hyperlane_message_to_bytes(&message);

    println!("Testing quote_dispatch...");
    let quote_result = igp_hook
        .methods()
        .quote_dispatch(Bytes(message_bytes.clone()), Bytes(message_bytes.clone()))
        .with_contract_ids(&[igp.contract_id().clone(), gas_oracle.contract_id().clone()])
        .call()
        .await
        .map_err(|e| format!("Quote dispatch failed: {:?}", e))?;

    println!("Quote dispatch result: {:?}", quote_result.value);

    let igp_balance = get_contract_balance(
        wallet.provider().unwrap(),
        igp.contract_id(),
        get_native_asset(),
    )
    .await
    .unwrap();

    let last_dispatch_id = mailbox
        .methods()
        .latest_dispatched_id()
        .call()
        .await
        .unwrap();

    if last_dispatch_id.value != Bits256::zeroed() {
        return Err(format!(
            "Expected zeroed last_dispatch_id, got: {:?}",
            last_dispatch_id.value
        ));
    }

    let msg = mailbox
        .methods()
        .dispatch(
            TEST_REMOTE_DOMAIN,
            recipient,
            Bytes(message_bytes.clone()),
            Bytes(message_bytes.clone()),
            igp_hook.contract_id(),
        )
        .call_params(CallParameters::new(amount, get_native_asset(), 200_000_000))
        .unwrap()
        .with_contract_ids(&[
            mailbox.contract_id().into(),
            igp.contract_id().into(),
            igp_hook.contract_id().into(),
            gas_oracle.contract_id().clone(),
            msg_recipient.contract_id().clone(),
            aggregation_ism.contract_id().clone(),
        ])
        .call()
        .await
        .unwrap();

    println!("Message dispatch result: {:?}", msg.value);

    let verify_result = aggregation_ism
        .methods()
        .verify(Bytes(message_bytes.clone()), Bytes(message_bytes.clone()))
        .call()
        .await
        .unwrap();

    if !verify_result.value {
        return Err("Verification result is false".to_string());
    }
    let last_dispatch_id_2 = mailbox
        .methods()
        .latest_dispatched_id()
        .call()
        .await
        .unwrap();

    if last_dispatch_id_2.value != msg.value {
        return Err(format!(
            "Last dispatch ID mismatch. Expected: {:?}, Got: {:?}",
            msg.value, last_dispatch_id_2.value
        ));
    }

    let igp_balance_2 = get_contract_balance(
        wallet.provider().unwrap(),
        igp.contract_id(),
        get_native_asset(),
    )
    .await
    .unwrap();

    let wallet_balance_2 = get_balance(
        wallet.provider().unwrap(),
        wallet.address(),
        get_native_asset(),
    )
    .await
    .unwrap();

    if wallet_balance - wallet_balance_2 < amount {
        return Err(format!("Wallet balance difference is less than the expected amount. Expected at least: {}, Got: {}", amount, wallet_balance - wallet_balance_2));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("mock_message_send", |registry| async move {
        message_send(registry).await
    })
}
