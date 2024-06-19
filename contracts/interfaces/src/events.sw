library;

use message::EncodedMessage;

/// Logged when a message is dispatched.
/// Although the message ID can be calculated by hashing the message contents,
/// this is also logged for convenience.
pub struct DispatchIdEvent {
    pub message_id: b256,
}

pub struct DispatchEvent {
    pub message_id: b256,
    pub destination_domain: u32,
    pub recipient_address: b256,
    pub message: EncodedMessage,
}

/// Logged when a message is processed.
pub struct ProcessEvent {
    pub message_id: b256,
    pub origin: u32,
    pub sender: b256,
    pub recipient: b256,
}

/// Logged when the default ISM is set.
pub struct DefaultIsmSetEvent {
    module: ContractId,
}
