use crate::{
    cases::TestCase,
    evm::{get_evm_client_and_wallet, get_evm_metadata_from_yaml},
    utils::local_contracts::get_value_from_agent_config_json,
};
use tokio::time::Instant;

use ethers::{core::types::Address, prelude::*};

abigen!(Mailbox, "e2e/src/evm/abis/Mailbox.json",);

async fn remote_mailbox_test() -> Result<f64, String> {
    let start: Instant = Instant::now();

    let (client, wallet) = get_evm_client_and_wallet();

    let mailbox_address: Address = get_value_from_agent_config_json("test1", "mailbox")
        .unwrap()
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let mailbox = Mailbox::new(mailbox_address, client.clone());

    // TODO: Something to check
    println!("wallet address: {:?}", wallet.address());

    let owner = mailbox.owner().call().await.unwrap();
    println!("mailbox owner: {:?}", owner);
    // if owner != wallet.address() {
    //     return Err("Mailbox not owned by wallet".to_string());
    // }

    let expected_domain = get_evm_metadata_from_yaml().domainId;
    let local_domain = mailbox.local_domain().call().await.unwrap();

    if local_domain.to_string() != expected_domain {
        return Err(format!(
            "Domain mismatch. Expected: {}, Got: {}",
            expected_domain, local_domain
        ));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("remote_mailbox_test", remote_mailbox_test)
}
