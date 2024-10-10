use hyperlane_core::Encode;
use std::str::FromStr;
use tokio::time::Instant;

use fuels::{
    accounts::{provider::Provider, wallet::WalletUnlocked},
    crypto::SecretKey,
    programs::calls::CallParameters,
    types::{transaction_builders::VariableOutputPolicy, AssetId, Bits256, Bytes, ContractId},
};

use crate::{
    cases::TestCase,
    setup::abis::{GasOracle, IGPHook, InterchainGasPaymaster, Mailbox},
    utils::{
        _test_message,
        constants::TEST_RECIPIENT,
        local_contracts::{
            get_contract_address_from_json, get_contract_address_from_yaml,
            get_value_from_agent_config_json,
        },
        token::{get_balance, get_contract_balance},
    },
};

async fn send_message_with_gas() -> Result<f64, String> {
    let start = Instant::now();

    let fuel_provider = Provider::connect("127.0.0.1:4000").await.unwrap();
    let secret_key =
        SecretKey::from_str("0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711")
            .unwrap();
    let wallet = WalletUnlocked::new_from_private_key(secret_key, Some(fuel_provider.clone()));

    let fuel_mailbox_id = get_contract_address_from_json("fueltest1", "mailbox");
    let fuel_igp_hook_id = get_contract_address_from_yaml("interchainGasPaymasterHook");

    // Remove '0x' prefix and pad with zeros
    let eth_address = "8A791620dd6260079BF849Dc5567aDC3F2FdC318";
    let padded_address = format!("{:0>64}", eth_address);

    let base_asset =
        AssetId::from_str("0xf8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07")
            .unwrap();

    // Create ContractId from the padded string
    let remote_mailbox_id = ContractId::from_str(&padded_address).unwrap();
    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let gas_oracle_id = get_contract_address_from_yaml("interchainGasPaymasterOracle");
    let post_dispatch_hook_id = get_contract_address_from_yaml("postDispatch");

    // let remote_mailbox_id =
    // let remote_mailbox_id =
    //     Bech32ContractId::from_str("0x8A791620dd6260079BF849Dc5567aDC3F2FdC318").unwrap();
    //get_contract_address_from_json("test1", "mailbox");

    let fuel_mailbox_instance = Mailbox::new(fuel_mailbox_id, wallet.clone());
    let remote_mailbox_instance = Mailbox::new(remote_mailbox_id, wallet.clone());

    let fuel_igp_hook_instance = IGPHook::new(fuel_igp_hook_id, wallet.clone());
    let fuel_igp_instance = InterchainGasPaymaster::new(igp_id, wallet.clone());
    let fuel_gas_oracle_instance = GasOracle::new(gas_oracle_id, wallet.clone());

    let wallet_balance = get_balance(&fuel_provider, wallet.address(), base_asset)
        .await
        .unwrap();

    let remote_domain = get_value_from_agent_config_json("test1", "domainId")
        .unwrap()
        .as_u64()
        .map(|v| v as u32)
        .unwrap_or(9913371);

    let message = _test_message(
        &fuel_mailbox_instance,
        remote_mailbox_instance.contract_id(),
        500,
    );

    let quote = fuel_igp_hook_instance
        .methods()
        .quote_dispatch(Bytes(message.body.clone()), Bytes(message.to_vec()))
        .with_contract_ids(&[
            fuel_igp_instance.contract_id().clone(),
            fuel_gas_oracle_instance.contract_id().clone(),
        ])
        .call()
        .await
        .map_err(|e| format!("Failed to get quote: {:?}", e))?;

    let contract_balance =
        get_contract_balance(&fuel_provider, fuel_igp_instance.contract_id(), base_asset)
            .await
            .unwrap();

    // fuel_igp_instance
    //     .methods()
    //     .pay_for_gas(
    //         Bits256::from_hex_str(TEST_MESSAGE_ID).unwrap(),
    //         TEST_REMOTE_DOMAIN,
    //         500,
    //         Identity::Address(wallet.address().into()),
    //     )
    //     .call_params(CallParameters::new(10_000_000, base_asset, 10_000_000))
    //     .unwrap()
    //     .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
    //     .with_contracts(&[
    //         &fuel_igp_instance,
    //         &fuel_gas_oracle_instance,
    //         &fuel_igp_hook_instance,
    //     ])
    //     .call()
    //     .await
    //     .map_err(|e| format!("Failed to pay for gas: {:?}", e))?;

    // let contract_balance_2 =
    //     get_contract_balance(&fuel_provider, fuel_igp_instance.contract_id(), base_asset)
    //         .await
    //         .unwrap();

    // println!("contract_balance after payment: {:?}", contract_balance_2);
    // println!(
    //     "contract_balance - contract_balance_2: {:?}",
    //     contract_balance_2 - contract_balance
    // );

    // let wallet_balance_final = get_balance(&fuel_provider, wallet.address(), base_asset)
    //     .await
    //     .unwrap();
    // println!("final wallet_balance: {:?}", wallet_balance_final);
    // println!(
    //     "wallet_balance - wallet_balance_final: {:?}",
    //     wallet_balance - wallet_balance_final
    // );

    // println!(
    //     "wallet.address(): {:?}",
    //     Identity::Address(wallet.address().into())
    // );

    // let payment = fuel_igp_hook_instance
    //     .methods()
    //     .post_dispatch(Bytes(message.body.clone()), Bytes(message.to_vec()))
    //     .call_params(CallParameters::new(10_000_000, base_asset, 10_000_000))
    //     .unwrap()
    //     .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
    //     .with_contracts(&[&fuel_igp_instance, &fuel_gas_oracle_instance])
    //     .call()
    //     .await
    //     .unwrap();

    // let contract_balance_after_post_dispatch =
    //     get_contract_balance(&fuel_provider, fuel_igp_instance.contract_id(), base_asset)
    //         .await
    //         .unwrap();

    // println!(
    //     "difference after post dispatch: {:?}",
    //     contract_balance_after_post_dispatch - contract_balance
    // );

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
            Bits256::from_hex_str(TEST_RECIPIENT).unwrap(),
            Bytes(message.body.clone()),
            Bytes(message.body.clone()),
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

    let wallet_balance_final = get_balance(&fuel_provider, wallet.address(), base_asset)
        .await
        .unwrap();

    let contract_balance_final =
        get_contract_balance(&fuel_provider, fuel_igp_instance.contract_id(), base_asset)
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
