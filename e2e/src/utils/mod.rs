pub mod local_contracts;
pub mod token;

use crate::cases::FailedTestCase;

use alloy::primitives::{Bytes as AlloyBytes, FixedBytes};
use fuels::{
    accounts::{wallet::Wallet, ViewOnlyAccount},
    types::{
        bech32::Bech32ContractId,
        errors::{transaction::Reason, Error},
        Bits256, Bytes, U256,
    },
};
use hyperlane_core::{HyperlaneMessage, H256};
use local_contracts::{get_contract_address_from_yaml, get_value_from_agent_config_json};
use rand::{thread_rng, Rng};
use tokio::time::Instant;

pub const TEST_RECIPIENT: &str =
    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const MIN_METADATA_LENGTH: u64 = 98;
const TEST_GAS_AMOUNT: u64 = 5000;

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
    recipient: &Bech32ContractId,
    amount: u64,
    recipient_user: Bits256,
    sender: Bits256,
) -> HyperlaneMessage {
    let message_body = build_message_body(recipient_user, amount);

    HyperlaneMessage {
        version: 3u8,
        nonce: thread_rng().gen_range(0..1000000) as u32,
        origin: get_evm_domain(),
        sender: H256::from(sender.0),
        destination: get_fuel_domain(),
        recipient: H256::from_slice(recipient.hash().as_slice()),
        body: message_body.into(),
    }
}

pub fn get_revert_reason(call_error: Error) -> String {
    if let Error::Transaction(Reason::Failure { reason, .. }) = call_error {
        reason
    } else {
        panic!(
            "Error is not a RevertTransactionError. Error: {:?}",
            call_error
        );
    }
}

#[allow(dead_code)]
pub fn build_message_body(recipient: Bits256, amount: u64) -> Bytes {
    let mut buffer = Vec::new();

    let amount_u256 = U256::from(amount);
    let mut amount_bytes = [0u8; 32];
    amount_u256.to_big_endian(&mut amount_bytes);

    buffer.extend(&recipient.0);
    buffer.extend(&amount_bytes);

    Bytes(buffer)
}

pub fn get_evm_domain() -> u32 {
    get_value_from_agent_config_json("test1", "domainId")
        .unwrap()
        .as_u64()
        .map(|v| v as u32)
        .unwrap_or(9913371)
}

pub fn get_fuel_domain() -> u32 {
    get_value_from_agent_config_json("fueltest1", "domainId")
        .unwrap()
        .as_u64()
        .map(|v| v as u32)
        .unwrap_or(13373)
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

pub fn get_remote_test_recipient_address() -> alloy::primitives::Address {
    let recipient_address = get_value_from_agent_config_json("test1", "testRecipient").unwrap();
    let recipient_str = recipient_address.as_str().unwrap();
    recipient_str.parse().expect("Invalid address format")
}

pub fn get_remote_test_recipient() -> Bits256 {
    let recipient_address = get_remote_test_recipient_address();
    let recipient_bytes = recipient_address.to_vec();

    let mut address_array = [0u8; 32];
    address_array[12..].copy_from_slice(&recipient_bytes);
    Bits256(address_array)
}

pub fn get_fuel_test_recipient() -> FixedBytes<32> {
    let recipient_address = get_contract_address_from_yaml("testRecipient");
    FixedBytes::from_slice(recipient_address.as_slice())
}

// variant:        [0:2]     // Set to 1
// msg_value:      [2:34]    // Left as 0
// gas_limit:      [34:66]   // Left as 0
// refund_address: [66:98]   // Set to wallet address
pub fn create_mock_metadata(wallet: &Wallet) -> Bytes {
    let mut metadata = vec![0u8; MIN_METADATA_LENGTH as usize];

    metadata[0] = 0;
    metadata[1] = 1;

    let mut gas_limit_bytes = [0u8; 32];

    gas_limit_bytes[24..32].copy_from_slice(&TEST_GAS_AMOUNT.to_be_bytes());
    metadata[34..66].copy_from_slice(&gas_limit_bytes);

    let wallet_bytes: [u8; 32] = wallet.address().hash().into();
    metadata[66..98].copy_from_slice(&wallet_bytes);

    Bytes(metadata)
}
