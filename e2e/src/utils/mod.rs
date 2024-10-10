pub mod constants;
pub mod local_contracts;
pub mod mock_contracts_registry;
pub mod token;

use crate::cases::FailedTestCase;
use crate::setup::abis::Mailbox;

use fuels::{
    accounts::wallet::WalletUnlocked,
    types::{bech32::Bech32ContractId, Bits256, Bytes},
};
use hyperlane_core::{HyperlaneMessage, H256};
use token::get_token_metadata;
use tokio::time::Instant;

use constants::*;

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
        origin: TEST_LOCAL_DOMAIN,
        sender: H256::from_slice(sender),
        destination: TEST_REMOTE_DOMAIN,
        recipient: H256::from_slice(recipient.hash().as_slice()),
        body: message_body.into(),
    }
}

pub fn build_message_body(recipient: Bits256, amount: u64) -> Bytes {
    let mut buffer = Vec::new();

    let token = get_token_metadata();

    buffer.extend(&recipient.0);
    buffer.extend(&amount.to_be_bytes());
    buffer.extend(&token.decimals.to_be_bytes());
    buffer.extend(&token.total_supply.to_be_bytes());
    Bytes(buffer)
}

pub fn hyperlane_message_to_bytes(message: &HyperlaneMessage) -> Vec<u8> {
    let mut bytes = Vec::new();

    bytes.push(message.version);
    bytes.extend_from_slice(&message.nonce.to_be_bytes());
    bytes.extend_from_slice(&message.origin.to_be_bytes());
    bytes.extend_from_slice(message.sender.as_bytes());
    bytes.extend_from_slice(&message.destination.to_be_bytes());
    bytes.extend_from_slice(message.recipient.as_bytes());
    bytes.extend_from_slice(&message.body);

    bytes
}
