use super::TestCase;
use crate::{
    setup::*,
    utils::{
        _test_message,
        constants::{TEST_RECIPIENT, TEST_REMOTE_DOMAIN},
        contract_registry::get_contract_registry,
        hyperlane_message_to_bytes,
        token::{self, get_balance, get_contract_balance},
    },
};
use fuels::{
    programs::calls::CallParameters,
    types::{Bits256, Bytes},
};
use token::get_native_asset;
use tokio::time::Instant;

async fn message_send() -> Result<f64, String> {
    let start = Instant::now();
    let wallet = get_loaded_wallet().await;

    let (mailbox, igp, igp_hook, gas_oracle, msg_recipient, aggregation_ism) = {
        let registry = get_contract_registry();
        (
            registry.mailbox.clone(),
            registry.igp.clone(),
            registry.igp_hook.clone(),
            registry.gas_oracle.clone(),
            registry.msg_recipient.clone(),
            registry.aggregation_ism.clone(),
        )
    };

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
        .unwrap();

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

    assert_eq!(last_dispatch_id.value, Bits256::zeroed());

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

    let verify_result = aggregation_ism
        .methods()
        .verify(Bytes(message_bytes.clone()), Bytes(message_bytes.clone()))
        .call()
        .await
        .unwrap();

    assert!(verify_result.value);

    let last_dispatch_id_2 = mailbox
        .methods()
        .latest_dispatched_id()
        .call()
        .await
        .unwrap();

    assert_eq!(last_dispatch_id_2.value, msg.value);

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

    assert!(
        wallet_balance - wallet_balance_2 >= amount,
        "Wallet balance difference is less than the expected amount"
    );

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("message_send", message_send)
}
