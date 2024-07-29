library;

use std::{bytes::Bytes, storage::*};
use message::EncodedMessage;

abi Mailbox {
    /// Initializes the contract.
    #[storage(write)]
    fn initialize(
        owner: b256,
        default_ism: b256,
        default_hook: b256,
        required_hook: b256,
    );

    /// Returns the domain of the chain where the contract is deployed.
    #[storage(read)]
    fn local_domain() -> u32;

    /// Returns true if the message has been processed.
    ///
    /// ### Arguments
    ///
    /// * `message_id` - The unique identifier of the message.
    #[storage(read)]
    fn delivered(message_id: b256) -> bool;

    /// Sets the default ISM used for message verification.
    ///
    /// ### Arguments
    ///
    /// * `module` - Address implementing ISM interface.
    #[storage(read, write)]
    fn set_default_ism(module: ContractId);

    /// Gets the default ISM used for message verification.
    #[storage(read)]
    fn default_ism() -> ContractId;

    #[storage(write)]
    fn set_default_hook(module: ContractId);

    #[storage(read)]
    fn default_hook() -> ContractId;

    #[storage(write)]
    fn set_required_hook(module: ContractId);

    #[storage(read)]
    fn required_hook() -> ContractId;

    /// Returns the ID of the last dispatched message.
    #[storage(read)]
    fn latest_dispatched_id() -> b256;

    /// Dispatches a message to the destination domain and recipient.
    /// Returns the message's ID.
    ///
    /// ### Arguments
    ///
    /// * `destination_domain` - The domain of the destination chain.
    /// * `recipient` - Address of the recipient on the destination chain.
    /// * `message_body` - Raw bytes content of the message body.
    #[payable]
    #[storage(read, write)]
    fn dispatch(
        destination_domain: u32,
        recipient: b256,
        message_body: Bytes,
        metadata: Bytes,
        hook: ContractId,
    ) -> b256;

    #[storage(read)]
    fn quote_dispatch(
        destination_domain: u32,
        recipient_address: b256,
        message_body: Bytes,
        metadata: Bytes,
        hook: ContractId,
    ) -> u64;

    /// Processes a message.
    ///
    /// ### Arguments
    ///
    /// * `metadata` - The metadata for ISM verification.
    /// * `message` - The message as emitted by dispatch.
    #[storage(read, write)]
    fn process(metadata: Bytes, message: Bytes);

    /// Returns the number of inserted leaves (i.e. messages) in the merkle tree.
    #[storage(read)]
    fn nonce() -> u32;

    /// Returns the ISM set by a recipient.
    ///
    /// ### Arguments
    ///
    /// * `recipient` - The recipient's contract Id.
    ///
    /// ### Returns
    ///
    /// * The ISM contract Id.
    #[storage(read, write)]
    fn recipient_ism(recipient: ContractId) -> ContractId;
}
