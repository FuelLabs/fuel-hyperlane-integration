library;

use std::bytes::Bytes;

abi MessageRecipient {
    /// Handles a message once it has been verified by Mailbox.process
    ///
    /// ### Arguments
    ///
    /// * `origin`: [u32] - The origin domain identifier.
    /// * `sender`: [b256] - The sender address on the origin chain.
    /// * `message_body`: [Bytes] - Raw bytes content of the message body.
    #[storage(read, write)]
    fn handle(origin: u32, sender: b256, message_body: Bytes);

    /// Returns the address of the ISM used for message verification.
    /// If zero address is returned, the mailbox default ISM is used.
    ///
    /// ### Returns
    ///
    /// * [ContractId] - The ISM contract address.
    #[storage(read)]
    fn interchain_security_module() -> ContractId;
}
