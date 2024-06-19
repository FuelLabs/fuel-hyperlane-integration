library;


/// Logged when a message is dispatched.
/// Although the message ID can be calculated by hashing the message contents,
/// this is also logged for convenience.
pub struct DispatchIdEvent {
    message_id: b256,
}

/// Logged when a message is processed.
pub struct ProcessEvent {
    message_id: b256,
    origin: u32,
    sender: b256,
    recipient: b256,
}

/// Logged when the default ISM is set.
pub struct DefaultIsmSetEvent {
    module: ContractId,
}
