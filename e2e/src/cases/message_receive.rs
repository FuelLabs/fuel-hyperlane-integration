use super::TestCase;
use crate::utils::{
    _test_message, contract_registry::get_contract_registry, hyperlane_message_to_bytes,
};
use fuels::types::Bytes;
use tokio::time::Instant;

async fn message_receive() -> Result<f64, String> {
    let start = Instant::now();

    let (
        mailbox,
        aggregation_ism,
        message_id_multisig_ism,
        msg_recipient,
        merkle_root_multisig_ism,
        domain_routing_ism,
    ) = {
        let registry = get_contract_registry();
        (
            registry.mailbox.clone(),
            registry.aggregation_ism.clone(),
            registry.message_id_multisig_ism.clone(),
            registry.msg_recipient.clone(),
            registry.multisig_ism.clone(),
            registry.routing_ism.clone(),
        )
    };

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
        .await;

    assert!(process_result.is_ok());

    let aggregation_verify_result = aggregation_ism
        .methods()
        .verify(Bytes(message_bytes.clone()), Bytes(message_bytes.clone()))
        .call()
        .await
        .unwrap();

    assert!(aggregation_verify_result.value);

    let handled = msg_recipient.methods().handled().call().await.unwrap();
    assert!(handled.value);

    // Test Domain Routing ISM verification
    // println!("Testing Domain Routing ISM verification...");
    // let routing_verify_result = domain_routing_ism
    //     .methods()
    //     .verify(Bytes(message_bytes.clone()), Bytes(message_bytes.clone()))
    //     .determine_missing_contracts(Some(8))
    //     .await
    //     .unwrap()
    //     .call()
    //     .await;

    // match routing_verify_result {
    //     Ok(result) => println!("Domain Routing ISM verification result: {:?}", result),
    //     Err(e) => println!("Domain Routing ISM verification error: {:?}", e),
    // }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("message_receive", message_receive)
}
