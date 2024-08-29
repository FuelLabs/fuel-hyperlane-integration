use crate::cases::FailedTestCase;
use crate::setup::abis::Mailbox;
use fuels::{accounts::wallet::WalletUnlocked, types::bech32::Bech32ContractId};
use hyperlane_core::{HyperlaneMessage, H256};
use tokio::time::Instant;

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
) -> HyperlaneMessage {
    let hash = mailbox.account().address().hash();
    let sender = hash.as_slice();

    HyperlaneMessage {
        version: 3u8,
        nonce: 0u32,
        origin: 0x6675656cu32,
        sender: H256::from_slice(sender),
        destination: 0x6675656cu32,
        recipient: H256::from_slice(recipient.hash().as_slice()),
        body: vec![10u8; 100],
    }
}
