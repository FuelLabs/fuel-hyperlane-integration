library;

use std::{bytes::Bytes, storage::*};
use message::EncodedMessage;

pub enum MailboxError {
    InvalidISMAddress: (),
    InvalidHookAddress: (),
    InvalidProtocolVersion: u8,
    UnexpectedDestination: u32,
    MessageAlreadyDelivered: (),
    MessageVerificationFailed: (),
    MessageTooLarge: u64,
}


abi Mailbox {
    /// Initializes the contract.
    ///
    /// ### Arguments
    ///
    /// * `owner`: [Identity] - The owner of the contract.
    /// * `default_ism`: [b256] - The default ISM contract Id.
    /// * `default_hook`: [b256] - The default hook contract Id.
    /// * `required_hook`: [b256] - The required hook contract Id.
    #[storage(write)]
    fn initialize(
        owner: Identity,
        default_ism: b256,
        default_hook: b256,
        required_hook: b256,
    );

    /// Gets the domain which is specified on contract initialization.
    ///
    /// ### Returns
    ///
    /// * [u32] - The domain of the contract.
    fn local_domain() -> u32;

    /// Returns true if the message has been processed.
    ///
    /// ### Arguments
    ///
    /// * `message_id`: [b256] - The unique identifier of the message.
    ///
    /// ### Returns
    ///
    /// * [bool] - True if the message has been processed.
    #[storage(read)]
    fn delivered(message_id: b256) -> bool;

    /// Sets the default ISM used for message verification.
    ///
    /// ### Arguments
    ///
    /// * `module`: [ContractId] - Address implementing ISM interface.
    #[storage(read, write)]
    fn set_default_ism(module: ContractId);

    /// Gets the default ISM used for message verification.
    ///
    /// ### Returns
    ///
    /// * [ContractId] - Address implementing ISM interface.
    #[storage(read)]
    fn default_ism() -> ContractId;

    /// Sets the required hook used for message verification.
    ///
    /// ### Arguments
    ///
    /// * `module`: [ContractId] - Address implementing Hook interface.
    #[storage(write)]
    fn set_default_hook(module: ContractId);

    /// Gets the default hook used for message verification.
    ///
    /// ### Returns
    ///
    /// * [ContractId] - Address implementing Hook interface.
    #[storage(read)]
    fn default_hook() -> ContractId;

    /// Sets the required hook used for message verification.
    ///
    /// ### Arguments
    ///
    /// * `module`: [ContractId] - Address implementing Hook interface.
    #[storage(write)]
    fn set_required_hook(module: ContractId);

    /// Gets the required hook used for message verification.
    ///
    /// ### Returns
    ///
    /// * [ContractId] - Address implementing Hook interface.
    #[storage(read)]
    fn required_hook() -> ContractId;

    /// Returns the ID of the last dispatched message.
    ///
    /// ### Returns
    ///
    /// * [b256] - The ID of the last dispatched message.
    #[storage(read)]
    fn latest_dispatched_id() -> b256;

    /// Dispatches a message to the destination domain and recipient.
    /// Returns the message's ID.
    ///
    /// ### Arguments
    ///
    /// * `destination_domain`: [u32] - The domain of the destination chain.
    /// * `recipient`: [b256] - Address of the recipient on the destination chain.
    /// * `message_body`: [Bytes] - Raw bytes content of the message body.
    /// * `metadata`: [Bytes] - Raw bytes content of the metadata.
    /// * `hook`: [ContractId] - The hook contract Id.
    ///
    /// ### Returns
    ///
    /// * [b256] - The ID of the dispatched message.
    #[payable]
    #[storage(read, write)]
    fn dispatch(
        destination_domain: u32,
        recipient: b256,
        message_body: Bytes,
        metadata: Bytes,
        hook: ContractId,
    ) -> b256;

    /// Quotes a price for dispatching a message
    ///
    /// ### Arguments
    ///
    /// * `destination_domain`: [u32] - The domain of the destination chain.
    /// * `recipient_address`: [b256] - Address of the recipient on the destination chain.
    /// * `message_body`: [Bytes] - Raw bytes content of the message body.
    /// * `metadata`: [Bytes] - Raw bytes content of the metadata.
    /// * `hook`: [ContractId] - The hook contract Id.
    ///
    /// ### Returns
    ///
    /// * [u64] - The price of the dispatch.
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
    /// * `metadata`: [Bytes] - The metadata for ISM verification.
    /// * `message`: [Bytes] - The message as emitted by dispatch.
    #[storage(read, write)]
    fn process(metadata: Bytes, message: Bytes);

    /// Returns the number of inserted leaves (i.e. messages) in the merkle tree.
    ///
    /// ### Returns
    ///
    /// * [u32] - The number of leaves in the merkle tree.
    #[storage(read)]
    fn nonce() -> u32;

    /// Returns the ISM set by a recipient.
    ///
    /// ### Arguments
    ///
    /// * `recipient`: [ContractId] - The recipient's contract Id.
    ///
    /// ### Returns
    ///
    /// * [ContractId] - The ISM contract Id.
    #[storage(read)]
    fn recipient_ism(recipient: ContractId) -> ContractId;
}
