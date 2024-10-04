use std::str::FromStr;

use super::TestCase;
use crate::{
    setup::*,
    utils::{
        _test_message,
        constants::{TEST_MESSAGE_ID, TEST_RECIPIENT, TEST_REMOTE_DOMAIN},
        contract_registry::get_contract_registry,
        hyperlane_message_to_bytes,
        token::{get_balance, get_contract_balance, get_native_asset},
    },
};

use fuels::types::{transaction_builders::VariableOutputPolicy, Address, Bits256, Bytes};
use tokio::time::Instant;

async fn asset_receive() -> Result<f64, String> {
    let start = Instant::now();
    let wallet = get_loaded_wallet().await;

    let (mailbox, aggregation_ism, warp_route, msg_recipient, merkle_root_multisig_ism) = {
        let registry = get_contract_registry(); // Access the registry
        (
            registry.mailbox.clone(),
            registry.aggregation_ism.clone(),
            registry.warp_route.clone(),
            registry.msg_recipient.clone(),
            registry.multisig_ism.clone(),
        )
    };

    let amount = 100_000u64;
    let recipient_address = Address::from_str(TEST_RECIPIENT).unwrap();

    let message = _test_message(&mailbox, msg_recipient.contract_id(), amount);
    let message_bytes = hyperlane_message_to_bytes(&message);

    let contract_balance = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route.contract_id(),
        get_native_asset(),
    )
    .await
    .unwrap();

    let initial_balance = get_balance(
        wallet.provider().unwrap(),
        &recipient_address.into(),
        get_native_asset(),
    )
    .await
    .unwrap();

    let process_result = mailbox
        .methods()
        .process(Bytes(message_bytes.clone()), Bytes(message_bytes.clone()))
        .with_contract_ids(&[
            msg_recipient.contract_id().clone(),
            aggregation_ism.contract_id().clone(),
            merkle_root_multisig_ism.contract_id().clone(),
        ])
        .call()
        .await;

    assert!(process_result.is_ok());

    let aggregation_verify_result = aggregation_ism
        .methods()
        .verify(Bytes(message_bytes.clone()), Bytes(message_bytes.clone()))
        .call()
        .await
        .unwrap();

    assert!(aggregation_verify_result.value);

    // Test WarpRoute handle message
    let handle_result = warp_route
        .methods()
        .handle_message(
            Bits256::from_hex_str(TEST_MESSAGE_ID).unwrap(),
            TEST_REMOTE_DOMAIN,
            Bits256(Address::from(wallet.address()).into()),
            Bytes(message.body),
        )
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .call()
        .await;

    assert!(handle_result.is_ok());

    //Recipient should posses the amount sent
    let final_balance = get_balance(
        wallet.provider().unwrap(),
        &recipient_address.into(),
        get_native_asset(),
    )
    .await
    .unwrap();

    assert_eq!(final_balance, initial_balance + amount);

    //WarpRoute should have spent the amount sent
    let final_contract_balance = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route.contract_id(),
        get_native_asset(),
    )
    .await
    .unwrap();

    assert_eq!(final_contract_balance, contract_balance - amount);

    println!("Asset receive test completed in {:?}", start.elapsed());
    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("asset_receive", asset_receive)
}
