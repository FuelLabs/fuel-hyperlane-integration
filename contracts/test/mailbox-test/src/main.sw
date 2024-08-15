contract;

use std::bytes::Bytes;
use message::EncodedMessage;

abi MailboxTest {
    #[storage(read)]
    fn build_outbound_message(
        destination_domain: u32,
        recipient_address: b256,
        body: Bytes,
    ) -> Bytes;

    #[storage(write)]
    fn update_latest_dispatched_id(message_id: b256);

    #[storage(read)]
    fn latest_dispatched_id() -> b256;
}

configurable {
    LOCAL_DOMAIN: u32 = 0x6675656cu32,
}

storage {
    latest_dispatched_id: b256 = b256::zero(),
    nonce: u32 = 0,
}

impl MailboxTest for Contract {
    #[storage(read)]
    fn build_outbound_message(
        destination_domain: u32,
        recipient_address: b256,
        body: Bytes,
    ) -> Bytes {
        let message = _build_message(destination_domain, recipient_address, body);
        message.bytes
    }

    #[storage(write)]
    fn update_latest_dispatched_id(message_id: b256) {
        storage.latest_dispatched_id.write(message_id);
    }

    #[storage(read)]
    fn latest_dispatched_id() -> b256 {
        storage.latest_dispatched_id.read()
    }
}

/// Builds an outbound message. Copied from contracts/mailbox/src/main.sw.
#[storage(read)]
fn _build_message(
    destination_domain: u32,
    recipient: b256,
    message_body: Bytes,
) -> EncodedMessage {
    let nonce = storage.nonce.read();
    let sender = b256::from(msg_sender().unwrap().as_address().unwrap());

    EncodedMessage::new(
        3,
        nonce,
        LOCAL_DOMAIN,
        sender,
        destination_domain,
        recipient,
        message_body,
    )
}
