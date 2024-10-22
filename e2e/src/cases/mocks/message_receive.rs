use super::TestCase;
use crate::utils::{
    _test_message, contract_registry::ContractRegistry, hyperlane_message_to_bytes,
};
use fuels::types::Bytes;
use std::sync::Arc;
use tokio::time::Instant;

async fn mock_message_receive(registry: Arc<ContractRegistry>) -> Result<f64, String> {
    let start = Instant::now();

    let mailbox = registry.mailbox.clone();
    let aggregation_ism = registry.aggregation_ism.clone();
    let msg_recipient = registry.msg_recipient.clone();
    let merkle_root_multisig_ism = registry.multisig_ism.clone();

    let amount = 100_000u64;
    let message = _test_message(&mailbox, msg_recipient.contract_id(), amount);
    let message_bytes = hyperlane_message_to_bytes(&message);

    let process_result = mailbox
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

    let handled = msg_recipient
        .methods()
        .handled()
        .call()
        .await
        .map_err(|e| format!("Failed to check if message was handled: {:?}", e))?;

    if !handled.value {
        return Err("Message was not handled".to_string());
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("mock_message_receive", |registry| async move {
        message_receive(registry).await
    })
}
