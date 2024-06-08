library;

use std::bytes::Bytes;

abi Mailbox {
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

    fn set_default_hook(module: ContractId);

    fn default_hook() -> ContractId;

    fn set_required_hook(module: ContractId);

    fn required_hook() -> ContractId;

    fn latest_dispatched_id() -> b256;

    /// Dispatches a message to the destination domain and recipient.
    /// Returns the message's ID.
    ///
    /// ### Arguments
    ///
    /// * `destination_domain` - The domain of the destination chain.
    /// * `recipient` - Address of the recipient on the destination chain.
    /// * `message_body` - Raw bytes content of the message body.
    // TODO #[payable]
    #[storage(read, write)]
    fn dispatch(
        destination_domain: u32,
        recipient: b256,
        message_body: Bytes,
    ) -> b256;

    // TODO #[payable]
    fn quote_dispatch(
        destination_domain: u32,
        recipient: b256,
        message_body: Bytes,
    ) -> b256;

    /// Processes a message.
    ///
    /// ### Arguments
    ///
    /// * `metadata` - The metadata for ISM verification.
    /// * `message` - The message as emitted by dispatch.
    #[storage(read, write)]
    fn process(metadata: Bytes, message: Bytes);

    /// Returns the number of inserted leaves (i.e. messages) in the merkle tree.
    // TODO nonce ?
    #[storage(read)]
    fn count() -> u32;

    /// Calculates and returns the merkle tree's current root.
    #[storage(read)]
    fn root() -> b256;

    /// Returns a checkpoint representing the current merkle tree:
    /// (root of merkle tree, index of the last element in the tree).
    #[storage(read)]
    fn latest_checkpoint() -> (b256, u32);
}
