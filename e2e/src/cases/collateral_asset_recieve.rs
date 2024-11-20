use crate::{
    cases::TestCase,
    setup::{
        abis::{Mailbox, MsgRecipient, WarpRoute},
        get_loaded_wallet,
    },
    utils::{
        _test_message,
        constants::{TEST_RECIPIENT, TEST_REMOTE_DOMAIN},
        local_contracts::get_contract_address_from_yaml,
        token::{get_balance, get_local_fuel_base_asset},
    },
};
use fuels::types::{transaction_builders::VariableOutputPolicy, Address, Bits256, Bytes};
use std::str::FromStr;
use test_utils::get_revert_reason;
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

    let _ = warp_route_instance
        .methods()
        .pause()
        .call()
        .await
        .map_err(|e| format!("Pause failed: {:?}", e))?;

    let is_paused = warp_route_instance
        .methods()
        .is_paused()
        .call()
        .await
        .map_err(|e| format!("Is paused failed: {:?}", e))?;

    if !is_paused.value {
        return Err("Warp route should have been paused".to_string());
    }

    let should_return_error = warp_route_instance
        .methods()
        .handle(
            TEST_REMOTE_DOMAIN,
            Bits256(Address::from(wallet.address()).into()),
            Bytes(message.clone().body),
        )
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .call()
        .await;

    assert_eq!(
        get_revert_reason(should_return_error.err().unwrap()),
        "Paused"
    );

    let _ = warp_route_instance
        .methods()
        .unpause()
        .call()
        .await
        .map_err(|e| format!("Unpause failed: {:?}", e))?;

    let _ = warp_route_instance
        .methods()
        .handle(
            TEST_REMOTE_DOMAIN,
            Bits256(Address::from(wallet.address()).into()),
            Bytes(message.clone().body),
        )
        .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
        .call()
        .await
        .map_err(|e| format!("Handle message failed: {:?}", e))?;

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

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("collateral_asset_recieve", collateral_asset_recieve)
}
