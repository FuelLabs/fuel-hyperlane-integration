pub mod local_contracts;
pub mod token;

use crate::cases::FailedTestCase;
use crate::setup::abis::Mailbox;

use alloy::primitives::{Bytes as AlloyBytes, FixedBytes};
use fuels::{
    accounts::wallet::WalletUnlocked,
    types::{bech32::Bech32ContractId, Bits256, Bytes, U256},
};
use hyperlane_core::{HyperlaneMessage, H256};
use local_contracts::{get_contract_address_from_yaml, get_value_from_agent_config_json};
use rand::{thread_rng, Rng};
use tokio::time::Instant;

pub const TEST_RECIPIENT: &str =
    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub fn summary(test_amount: usize, failed: Vec<FailedTestCase>, start: Instant) {
    println!("\nRan {} test cases", test_amount);
    println!("- Successful: {}", test_amount - failed.len());
    println!("- Failed: {}", failed.len());
    if !failed.is_empty() {
        failed.iter().for_each(|case| case.log());
    }
    println!("Total time: {:.3} sec", start.elapsed().as_secs_f64());
}

pub fn _test_message(
    mailbox: &Mailbox<WalletUnlocked>,
    recipient: &Bech32ContractId,
    amount: u64,
) -> HyperlaneMessage {
    let hash = mailbox.account().address().hash();
    let sender = hash.as_slice();

    let recipient_user = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
    let message_body = build_message_body(recipient_user, amount);

    HyperlaneMessage {
        version: 3u8,
        nonce: 0u32,
        origin: get_local_domain(),
        sender: H256::from_slice(sender),
        destination: get_remote_domain(),
        recipient: H256::from_slice(recipient.hash().as_slice()),
        body: message_body.into(),
    }
}

pub fn build_message_body(recipient: Bits256, amount: u64) -> Bytes {
    let mut buffer = Vec::new();

    let amount_u256 = U256::from(amount);
    let mut amount_bytes = [0u8; 32];
    amount_u256.to_big_endian(&mut amount_bytes);

    buffer.extend(&recipient.0);
    buffer.extend(&amount_bytes);

    Bytes(buffer)
}

pub fn get_remote_domain() -> u32 {
    get_value_from_agent_config_json("test1", "domainId")
        .unwrap()
        .as_u64()
        .map(|v| v as u32)
        .unwrap_or(31337)
}

pub fn get_local_domain() -> u32 {
    get_value_from_agent_config_json("fueltest1", "domainId")
        .unwrap()
        .as_u64()
        .map(|v| v as u32)
        .unwrap_or(13374)
}

pub fn get_msg_body() -> Vec<u8> {
    let rnd_number = thread_rng().gen_range(0..10000);
    let body_text = format!("Hello from Fuel! {}", rnd_number);
    hex::encode(body_text).into_bytes()
}

pub fn get_remote_msg_body() -> AlloyBytes {
    let rnd_number = thread_rng().gen_range(0..10000);
    let body_text = format!("Hello from sepolia! {}", rnd_number);
    AlloyBytes::copy_from_slice(body_text.as_bytes())
}

pub fn get_remote_test_recipient() -> Bits256 {
    let recipient_address = get_value_from_agent_config_json("test1", "testRecipient").unwrap();
    let recipient_str = recipient_address.as_str().unwrap();
    let recipient_str = recipient_str.strip_prefix("0x").unwrap();

    let mut address_array = [0u8; 32];
    let recipient_bytes = hex::decode(recipient_str).expect("Invalid hex string");

    address_array[12..].copy_from_slice(&recipient_bytes);
    Bits256(address_array)
}

pub fn get_fuel_test_recipient() -> FixedBytes<32> {
    let recipient_address = get_contract_address_from_yaml("testRecipient");
    FixedBytes::from_slice(recipient_address.as_slice())
}
