use super::TestCase;
use crate::{
    setup::*,
    utils::{
        _test_message,
        constants::*,
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

async fn asset_send() -> Result<f64, String> {
    let start = Instant::now();
    let wallet = get_loaded_wallet().await;

    let (mailbox, igp, igp_hook, gas_oracle, warp_route, msg_recipient, aggregation_ism) = {
        let registry = get_contract_registry(); // Access the registry
        (
            registry.mailbox.clone(),
            registry.igp.clone(),
            registry.igp_hook.clone(),
            registry.gas_oracle.clone(),
            registry.warp_route.clone(),
            registry.msg_recipient.clone(),
            registry.aggregation_ism.clone(),
        )
    };

    println!("igp_hook: {:?}", igp_hook.contract_id());
    println!("warp_route: {:?}", warp_route.contract_id());
    println!("mailbox: {:?}", mailbox.contract_id());
    println!("msg_recipient: {:?}", msg_recipient.contract_id());
    println!("igp: {:?}", igp.contract_id());
    println!("gas_oracle: {:?}", gas_oracle.contract_id());

    let wallet_balance = get_balance(
        wallet.provider().unwrap(),
        wallet.address(),
        get_native_asset(),
    )
    .await
    .unwrap();
    println!(
        "Wallet Balance before warp route transaction {:?}",
        wallet_balance
    );

    let contract_balance = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route.contract_id(),
        get_native_asset(),
    )
    .await
    .unwrap();
    println!(
        "Contract Balance before warp route transaction {:?}",
        contract_balance
    );

    let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
    let amount = 100u64;

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

    // Test post_dispatch
    let dispatch_result = warp_route
        .methods()
        .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
        .call_params(CallParameters::new(amount, get_native_asset(), 20_000_000))
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
        .await;

    println!("{:?}", dispatch_result);

    let wallet_balance = get_balance(
        wallet.provider().unwrap(),
        wallet.address(),
        get_native_asset(),
    )
    .await
    .unwrap();
    println!(
        "Wallet Balance after warp route transaction {:?}",
        wallet_balance
    );

    let contract_balance = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route.contract_id(),
        get_native_asset(),
    )
    .await
    .unwrap();
    println!(
        "Contract Balance after warp route transaction {:?}",
        contract_balance
    );

    let igp_balance = get_contract_balance(
        wallet.provider().unwrap(),
        igp.contract_id(),
        get_native_asset(),
    )
    .await
    .unwrap();
    println!("IGP balance after transaction {:?}", igp_balance);

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("asset_send", asset_send)
}
