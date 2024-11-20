use tokio::time::Instant;

use crate::{
    cases::TestCase,
    evm::get_evm_client_and_wallet,
    setup::{
        abis::{Mailbox, MsgRecipient},
        get_loaded_wallet,
    },
    utils::{
        _test_message,
        local_contracts::{
            get_contract_address_from_json, get_contract_address_from_yaml,
            get_value_from_agent_config_json,
        },
    },
};

use ethers::{core::types::Address, prelude::*};
abigen!(RemoteMailbox, "e2e/src/evm/abis/Mailbox.json",);

async fn message_recieve() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;

    let fuel_mailbox_id = get_contract_address_from_json("fueltest1", "mailbox");
    let test_recipient = get_contract_address_from_yaml("testRecipient");

    let fuel_mailbox_instance = Mailbox::new(fuel_mailbox_id, wallet.clone());
    let test_recipient_instance = MsgRecipient::new(test_recipient, wallet.clone());
    let amount = 0;

    let message = _test_message(
        &fuel_mailbox_instance,
        test_recipient_instance.contract_id(),
        amount,
    );

    let (remote_client, remote_wallet) = get_evm_client_and_wallet();

    let remote_mailbox_address: Address = get_value_from_agent_config_json("test1", "mailbox")
        .unwrap()
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    println!("remote_mailbox_address: {:?}", remote_mailbox_address);

    let remote_mailbox = RemoteMailbox::new(remote_mailbox_address, remote_client.clone());

    println!("remote balance: {:?}", remote_wallet);
    let my_array: [u8; 32] = [0; 32];

    let fuel_domain = get_value_from_agent_config_json("fueltest1", "domainId")
        .unwrap()
        .as_u64()
        .map(|v| v as u32)
        .unwrap();

    let quote_dispatch = remote_mailbox
        .quote_dispatch(
            fuel_domain,
            my_array,
            ethers::types::Bytes::from(message.body.clone()),
        )
        .call()
        .await
        .unwrap();

    println!("quote_dispatch: {:?}", quote_dispatch);

    let amount_to_send = ethers::utils::parse_ether("0.0002").unwrap(); // Quote yields 200000000000000 Wei

    let dispatch_call = remote_mailbox
        .dispatch_0(
            fuel_domain,
            my_array,
            ethers::types::Bytes::from(message.body.clone()),
        )
        .value(amount_to_send);

    let dispatch_res = dispatch_call.send().await.unwrap();
    println!("dispatch_res: {:?}", dispatch_res);

    let latest_message_id = remote_mailbox.latest_dispatched_id().call().await.unwrap();
    println!("latest_message_id: {:?}", latest_message_id);

    let delivered = remote_mailbox
        .delivered(latest_message_id)
        .call()
        .await
        .unwrap();

    println!("delivered: {:?}", delivered);

    let test = fuel_mailbox_instance
        .methods()
        .latest_dispatched_id()
        .call()
        .await
        .unwrap();

    println!("test: {:?}", test.value);

    let handled = test_recipient_instance
        .methods()
        .handled()
        .call()
        .await
        .unwrap();

    println!("handled: {:?}", handled);

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("message_recieve", message_recieve)
}
