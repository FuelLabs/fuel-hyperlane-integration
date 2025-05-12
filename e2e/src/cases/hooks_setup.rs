use tokio::time::Instant;

use fuels::{
    programs::calls::CallParameters,
    types::{transaction_builders::VariableOutputPolicy, AssetId, Bytes},
};

use crate::{
    cases::TestCase,
    setup::{
        abis::{GasOracle, InterchainGasPaymaster, Mailbox, ProtocolFee},
        get_loaded_wallet,
    },
    utils::{
        create_mock_metadata, get_evm_domain, get_msg_body, get_remote_test_recipient,
        local_contracts::{get_contract_address_from_json, get_contract_address_from_yaml},
        token::get_contract_balance,
    },
};

async fn send_message_with_aggregation_and_protocol_fee_hook() -> Result<f64, String> {
    let start = Instant::now();
    let wallet = get_loaded_wallet().await;

    let remote_recipient = get_remote_test_recipient();
    let base_asset = AssetId::BASE;
    let evm_domain = get_evm_domain();
    let msg_body = get_msg_body();

    let fuel_mailbox_id = get_contract_address_from_json("fueltest1", "mailbox");
    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let gas_oracle_id = get_contract_address_from_yaml("gasOracle");
    let aggregation_hook_id = get_contract_address_from_yaml("aggregationHook");
    let protocol_fee_hook_id = get_contract_address_from_yaml("protocolFee");
    let post_dispatch_hook_id = get_contract_address_from_yaml("postDispatch");

    let fuel_mailbox_instance = Mailbox::new(fuel_mailbox_id, wallet.clone());
    let fuel_igp_instance = InterchainGasPaymaster::new(igp_id, wallet.clone());
    let fuel_gas_oracle_instance = GasOracle::new(gas_oracle_id, wallet.clone());
    let protocol_fee_hook_instance = ProtocolFee::new(protocol_fee_hook_id, wallet.clone());

    let metadata = create_mock_metadata(&wallet);

    let contract_balance_igp = get_contract_balance(
        wallet.provider(),
        fuel_igp_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    let contract_balance_protocol_fee =
        get_contract_balance(wallet.provider(), &protocol_fee_hook_id.into(), base_asset)
            .await
            .unwrap();

    let protocol_fee_quote = protocol_fee_hook_instance
        .methods()
        .protocol_fee()
        .call()
        .await
        .unwrap()
        .value;

    fuel_mailbox_instance
        .methods()
        .set_required_hook(protocol_fee_hook_id)
        .call()
        .await
        .unwrap();

    let involved_contracts = vec![
        fuel_igp_instance.contract_id().clone(),
        fuel_gas_oracle_instance.contract_id().clone(),
        aggregation_hook_id.into(),
        protocol_fee_hook_id.into(),
        post_dispatch_hook_id.into(),
    ];

    let quote = fuel_mailbox_instance
        .methods()
        .quote_dispatch(
            evm_domain,
            remote_recipient,
            Bytes(msg_body.clone()),
            metadata.clone(),
            aggregation_hook_id,
        )
        .determine_missing_contracts()
        .await
        .unwrap()
        .call()
        .await
        .unwrap();

    let send_message_response = fuel_mailbox_instance
        .methods()
        .dispatch(
            evm_domain,
            remote_recipient,
            Bytes(msg_body.clone()),
            metadata,
            aggregation_hook_id,
        )
        .call_params(CallParameters::new(quote.value, base_asset, 10_000_000))
        .unwrap()
        .with_contract_ids(&involved_contracts)
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
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

    // let wallet_balance_final =
    //     get_balance(wallet.provider().unwrap(), wallet.address(), base_asset)
    //         .await
    //         .unwrap();

    let contract_balance_igp_final = get_contract_balance(
        wallet.provider(),
        fuel_igp_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    let contract_balance_protocol_fee_final =
        get_contract_balance(wallet.provider(), &protocol_fee_hook_id.into(), base_asset)
            .await
            .unwrap();

    // if wallet_balance - wallet_balance_final != quote.value {
    //     return Err(format!(
    //         "Expected wallet balance difference to be equal to {:?}, got: {:?}",
    //         quote.value,
    //         wallet_balance - wallet_balance_final
    //     ));
    // }

    if contract_balance_igp_final - contract_balance_igp != quote.value - protocol_fee_quote {
        return Err(format!(
            "Expected contract balance difference to be equal to {:?}, got: {:?}",
            quote.value - protocol_fee_quote,
            contract_balance_igp_final - contract_balance_igp
        ));
    }

    if contract_balance_protocol_fee_final - contract_balance_protocol_fee != protocol_fee_quote {
        return Err(format!(
            "Expected contract balance difference to be equal to {:?}, got: {:?}",
            protocol_fee_quote,
            contract_balance_protocol_fee_final - contract_balance_protocol_fee
        ));
    }

    println!("✅ send_message_with_aggregation_and_protocol_fee_hook passed");

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new(
        "send_message_with_aggregation_and_protocol_fee_hook",
        send_message_with_aggregation_and_protocol_fee_hook,
    )
}
