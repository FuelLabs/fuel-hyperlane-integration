use crate::{
    cases::TestCase,
    setup::abis::Mailbox,
    utils::local_contracts::{
        get_contract_address_from_json, get_contract_address_from_yaml,
        get_value_from_agent_config_json,
    },
};
use fuels::{
    accounts::{provider::Provider, wallet::WalletUnlocked},
    crypto::SecretKey,
};
use std::str::FromStr;
use tokio::time::Instant;

async fn mailbox_config() -> Result<f64, String> {
    let start = Instant::now();

    let fuel_provider = Provider::connect("127.0.0.1:4000").await.unwrap();
    let secret_key =
        SecretKey::from_str("0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711")
            .unwrap();
    let wallet = WalletUnlocked::new_from_private_key(secret_key, Some(fuel_provider.clone()));

    let mailbox_id = get_contract_address_from_json("fueltest1", "mailbox");

    let mailbox_instance = Mailbox::new(mailbox_id, wallet.clone());

    let domain = mailbox_instance
        .methods()
        .local_domain()
        .call()
        .await
        .map_err(|e| format!("Failed to get local domain: {:?}", e))?;

    let expected_domain = get_value_from_agent_config_json("fueltest1", "domainId").unwrap();

    if domain.value.to_string() != expected_domain.to_string() {
        return Err(format!(
            "Domain mismatch. Expected: {}, Got: {}",
            expected_domain, domain.value
        ));
    }

    let ism = mailbox_instance
        .methods()
        .default_ism()
        .call()
        .await
        .map_err(|e| format!("Failed to get default ISM: {:?}", e))?;

    let expected_ism_id = get_contract_address_from_yaml("interchainSecurityModule");
    if ism.value != expected_ism_id {
        return Err(format!(
            "ISM mismatch. Expected: {:?}, Got: {:?}",
            expected_ism_id, ism.value
        ));
    }

    let hook = mailbox_instance
        .methods()
        .default_hook()
        .call()
        .await
        .map_err(|e| format!("Failed to get default hook: {:?}", e))?;

    let hook_id = get_contract_address_from_yaml("postDispatch");
    if hook.value != hook_id {
        return Err(format!(
            "Hook mismatch. Expected: {:?}, Got: {:?}",
            hook_id, hook.value
        ));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("mailbox_config", mailbox_config)
}
