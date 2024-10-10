use std::str::FromStr;
use tokio::time::Instant;

use fuels::{
    accounts::{provider::Provider, wallet::WalletUnlocked},
    crypto::SecretKey,
    programs::calls::CallParameters,
    types::{bech32::Bech32ContractId, AssetId, Bits256, Bytes, ContractId},
};

use crate::{
    cases::TestCase,
    setup::abis::Mailbox,
    utils::{
        _test_message,
        constants::TEST_RECIPIENT,
        local_contracts::{get_contract_address_from_json, get_value_from_agent_config_json},
        token::get_balance,
    },
};

async fn send_message() -> Result<f64, String> {
    let start = Instant::now();

    let fuel_provider = Provider::connect("127.0.0.1:4000").await.unwrap();
    let secret_key =
        SecretKey::from_str("0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711")
            .unwrap();
    let wallet = WalletUnlocked::new_from_private_key(secret_key, Some(fuel_provider.clone()));

    let fuel_mailbox_id = get_contract_address_from_json("fueltest1", "mailbox");

    // Remove '0x' prefix and pad with zeros
    let eth_address = "8A791620dd6260079BF849Dc5567aDC3F2FdC318";
    let padded_address = format!("{:0>64}", eth_address);

    let base_asset =
        AssetId::from_str("0xf8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07")
            .unwrap();

    // Create ContractId from the padded string
    let remote_mailbox_id = ContractId::from_str(&padded_address).unwrap();

    // let remote_mailbox_id =
    //     Bech32ContractId::from_str("0x8A791620dd6260079BF849Dc5567aDC3F2FdC318").unwrap();
    //get_contract_address_from_json("test1", "mailbox");

    let fuel_mailbox_instance = Mailbox::new(fuel_mailbox_id, wallet.clone());
    let remote_mailbox_instance = Mailbox::new(remote_mailbox_id, wallet.clone());

    let amount = 0;

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
        amount,
    );

    let default_hook_id = fuel_mailbox_instance
        .methods()
        .default_hook()
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
            Bech32ContractId::from(default_hook_id.value),
        )
        .call_params(CallParameters::new(amount, base_asset, 100_000_000))
        .unwrap()
        .with_contract_ids(&[Bech32ContractId::from(default_hook_id.value)])
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

    if wallet_balance - wallet_balance_final != amount {
        return Err(format!(
            "Expected difference to be equal to amount, got: {:?}",
            wallet_balance - wallet_balance_final
        ));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("send_message", send_message)
}
