use tokio::time::Instant;

use fuels::{
    programs::calls::CallParameters,
    types::{transaction_builders::VariableOutputPolicy, Bytes},
};

use crate::{
    cases::TestCase,
    setup::{
        abis::{GasOracle, IGPHook, InterchainGasPaymaster, Mailbox},
        get_loaded_wallet,
    },
    utils::{
        get_msg_body, get_remote_domain, get_remote_test_recipient,
        local_contracts::{get_contract_address_from_json, get_contract_address_from_yaml},
        token::{get_balance, get_contract_balance, get_local_fuel_base_asset},
    },
};

async fn send_message_with_gas() -> Result<f64, String> {
    let start = Instant::now();
    let wallet = get_loaded_wallet().await;

    let remote_recipient = get_remote_test_recipient();
    let base_asset = get_local_fuel_base_asset();
    let remote_domain = get_remote_domain();
    let msg_body = get_msg_body();

    let fuel_mailbox_id = get_contract_address_from_json("fueltest1", "mailbox");
    let fuel_igp_hook_id = get_contract_address_from_yaml("interchainGasPaymasterHook");
    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let gas_oracle_id = get_contract_address_from_yaml("gasOracle");
    let post_dispatch_hook_id = get_contract_address_from_yaml("postDispatch");

    let fuel_mailbox_instance = Mailbox::new(fuel_mailbox_id, wallet.clone());
    let fuel_igp_hook_instance = IGPHook::new(fuel_igp_hook_id, wallet.clone());
    let fuel_igp_instance = InterchainGasPaymaster::new(igp_id, wallet.clone());
    let fuel_gas_oracle_instance = GasOracle::new(gas_oracle_id, wallet.clone());

    let wallet_balance = get_balance(wallet.provider().unwrap(), wallet.address(), base_asset)
        .await
        .unwrap();

    let quote = fuel_igp_instance
        .methods()
        .quote_gas_payment(remote_domain, 5000)
        .with_contract_ids(&[
            fuel_igp_instance.contract_id().clone(),
            fuel_gas_oracle_instance.contract_id().clone(),
        ])
        .call()
        .await
        .map_err(|e| format!("Failed to get quote: {:?}", e))?;

    let contract_balance = get_contract_balance(
        wallet.provider().unwrap(),
        fuel_igp_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    fuel_mailbox_instance
        .methods()
        .set_required_hook(post_dispatch_hook_id)
        .call()
        .await
        .unwrap();

    let send_message_response = fuel_mailbox_instance
        .methods()
        .dispatch(
            remote_domain,
            remote_recipient,
            Bytes(msg_body.clone()),
            Bytes(msg_body.clone()),
            fuel_igp_hook_instance.contract_id(),
        )
        .call_params(CallParameters::new(10_000_000, base_asset, 10_000_000))
        .unwrap()
        .with_contracts(&[
            &fuel_igp_instance,
            &fuel_gas_oracle_instance,
            &fuel_igp_hook_instance,
        ])
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .determine_missing_contracts(Some(5))
        .await
        .unwrap()
        .call()
        .await
        .map_err(|e| format!("Failed to send dispatch message: {:?}", e))?;

    let last_dispatch_id = fuel_mailbox_instance
        .methods()
        .latest_dispatched_id()
        .call()
        .await
        .unwrap();

    if last_dispatch_id.value != send_message_response.value {
        return Err(format!(
            "Expected last_dispatch_id to be equal to send_message_response, got: {:?}",
            last_dispatch_id.value
        ));
    }

    let wallet_balance_final =
        get_balance(wallet.provider().unwrap(), wallet.address(), base_asset)
            .await
            .unwrap();

    let contract_balance_final = get_contract_balance(
        wallet.provider().unwrap(),
        fuel_igp_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    if wallet_balance - wallet_balance_final != quote.value {
        return Err(format!(
            "Expected wallet balance difference to be equal to {:?}, got: {:?}",
            quote.value,
            wallet_balance - wallet_balance_final
        ));
    }

    if contract_balance_final - contract_balance != quote.value {
        return Err(format!(
            "Expected contract balance difference to be equal to {:?}, got: {:?}",
            quote.value,
            contract_balance_final - contract_balance
        ));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("send_message_with_gas", || async move {
        send_message_with_gas().await
    })
}
