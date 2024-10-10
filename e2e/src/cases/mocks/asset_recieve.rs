use std::str::FromStr;

use super::TestCase;
use crate::{
    setup::*,
    utils::{
        _test_message,
        constants::{TEST_MESSAGE_ID, TEST_RECIPIENT, TEST_REMOTE_DOMAIN},
        contract_registry::ContractRegistry,
        hyperlane_message_to_bytes,
        token::{get_balance, get_contract_balance, get_native_asset},
    },
};

use fuels::types::{transaction_builders::VariableOutputPolicy, Address, Bits256, Bytes};
use std::sync::Arc;
use tokio::time::Instant;

async fn mock_asset_receive(registry: Arc<ContractRegistry>) -> Result<f64, String> {
    let start = Instant::now();
    let wallet = get_loaded_wallet().await;

    let mailbox = registry.mailbox.clone();
    let aggregation_ism = registry.aggregation_ism.clone();
    let warp_route = registry.warp_route.clone();
    let msg_recipient = registry.msg_recipient.clone();
    let merkle_root_multisig_ism = registry.multisig_ism.clone();

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
    .map_err(|e| format!("Failed to get contract balance: {:?}", e))?;

    let initial_balance = get_balance(
        wallet.provider().unwrap(),
        &recipient_address.into(),
        get_native_asset(),
    )
    .await
    .map_err(|e| format!("Failed to get initial balance: {:?}", e))?;

    mailbox
        .methods()
        .process(Bytes(message_bytes.clone()), Bytes(message_bytes.clone()))
        .with_contract_ids(&[
            msg_recipient.contract_id().clone(),
            aggregation_ism.contract_id().clone(),
            merkle_root_multisig_ism.contract_id().clone(),
        ])
        .call()
        .await
        .map_err(|e| format!("Message processing failed: {:?}", e))?;

    let aggregation_verify_result = aggregation_ism
        .methods()
        .verify(Bytes(message_bytes.clone()), Bytes(message_bytes.clone()))
        .call()
        .await
        .map_err(|e| format!("Aggregation verification failed: {:?}", e))?;

    if !aggregation_verify_result.value {
        return Err("Aggregation verification result is false".to_string());
    }

    warp_route
        .methods()
        .handle_message(
            Bits256::from_hex_str(TEST_MESSAGE_ID).unwrap(),
            TEST_REMOTE_DOMAIN,
            Bits256(Address::from(wallet.address()).into()),
            Bytes(message.body),
        )
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .call()
        .await
        .map_err(|e| format!("Handle message failed: {:?}", e))?;

    let final_balance = get_balance(
        wallet.provider().unwrap(),
        &recipient_address.into(),
        get_native_asset(),
    )
    .await
    .map_err(|e| format!("Failed to get final balance: {:?}", e))?;

    if final_balance != initial_balance + amount {
        return Err(format!(
            "Final balance mismatch. Expected: {}, Got: {}",
            initial_balance + amount,
            final_balance
        ));
    }

    let final_contract_balance = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route.contract_id(),
        get_native_asset(),
    )
    .await
    .map_err(|e| format!("Failed to get final contract balance: {:?}", e))?;

    if final_contract_balance != contract_balance - amount {
        return Err(format!(
            "Final contract balance mismatch. Expected: {}, Got: {}",
            contract_balance - amount,
            final_contract_balance
        ));
    }

    println!("Asset receive test completed in {:?}", start.elapsed());
    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("mock_asset_receive", |registry| async move {
        mock_asset_receive(registry).await
    })
}
