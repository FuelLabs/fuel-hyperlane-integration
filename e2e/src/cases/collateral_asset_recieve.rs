use crate::{
    cases::TestCase,
    setup::{
        abis::{Mailbox, MsgRecipient, WarpRoute},
        get_loaded_wallet,
    },
    utils::{
        _test_message,
        local_contracts::get_contract_address_from_yaml,
        mocks::constants::{TEST_RECIPIENT, TEST_REMOTE_DOMAIN},
        token::{
            get_balance, get_contract_balance, get_local_fuel_base_asset, send_gas_to_contract_2,
        },
    },
};
use fuels::types::{transaction_builders::VariableOutputPolicy, Address, Bits256, Bytes};
use std::str::FromStr;
use tokio::time::Instant;

async fn collateral_asset_recieve() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;

    let base_asset = get_local_fuel_base_asset();

    let amount = 100_000;
    let recipient_address = Address::from_str(TEST_RECIPIENT).unwrap();

    let warp_route_id = get_contract_address_from_yaml("warpRoute");
    let mailbox_id = get_contract_address_from_yaml("mailbox");
    let msg_recipient = get_contract_address_from_yaml("testRecipient");

    let warp_route_instance = WarpRoute::new(warp_route_id, wallet.clone());
    let mailbox_instance = Mailbox::new(mailbox_id, wallet.clone());
    let msg_recipient_instance = MsgRecipient::new(msg_recipient, wallet.clone());

    let _ = send_gas_to_contract_2(
        wallet.clone(),
        warp_route_instance.contract_id(),
        amount,
        base_asset,
    )
    .await;

    let recipient_balance = get_balance(
        wallet.provider().unwrap(),
        &recipient_address.into(),
        base_asset,
    )
    .await
    .unwrap();

    let message = _test_message(
        &mailbox_instance,
        msg_recipient_instance.contract_id(),
        amount,
    );
    //random message id generate so that the test can run multiple times
    //needs to have this length: 6fa0fecded4a4b1f57b908435dc44d2f0b77834414d385d744c5c96cc2296471
    let message_id = format!("{:064x}", rand::random::<u128>());
    let _ = warp_route_instance
        .methods()
        .handle_message(
            Bits256::from_hex_str(&message_id).unwrap(),
            TEST_REMOTE_DOMAIN,
            Bits256(Address::from(wallet.address()).into()),
            Bytes(message.clone().body),
        )
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .call()
        .await
        .map_err(|e| format!("Handle message failed: {:?}", e))?;

    let should_return_error = warp_route_instance
        .methods()
        .handle_message(
            Bits256::from_hex_str(&message_id).unwrap(),
            TEST_REMOTE_DOMAIN,
            Bits256(Address::from(wallet.address()).into()),
            Bytes(message.body),
        )
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .call()
        .await;

    if should_return_error.is_ok() {
        return Err(format!(
            "Expected MessageAlreadyDelivered error, but handle message succeeded. Message ID: {}",
            message_id
        ));
    }

    let recipient_balance_after = get_balance(
        wallet.provider().unwrap(),
        &recipient_address.into(),
        base_asset,
    )
    .await
    .unwrap();

    if recipient_balance_after != recipient_balance + amount {
        return Err(format!(
            "Recipient balance after is not increased by amount: {:?}",
            recipient_balance_after - recipient_balance
        ));
    }

    let warp_balance_after = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    if warp_balance_after != 0 {
        return Err(format!(
            "Warp balance after is not 0: {:?}",
            warp_balance_after
        ));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("collateral_asset_recieve", collateral_asset_recieve)
}
