library;

use std::{bytes::Bytes, storage::*};
use message::EncodedMessage;

/// Event emitted when tokens are transferred to a remote domain.
/// This event contains information about the destination chain, recipient, and amount.
pub struct SentTransferRemoteEvent {
    /// The identifier of the destination chain
    pub destination: u32,
    /// The address of the recipient on the destination chain
    pub recipient: b256,
    /// The amount of tokens being transferred
    pub amount: u64,
}

/// Event emitted when tokens are received from a remote domain.
/// This event contains information about the origin chain, recipient, and amount.
pub struct ReceivedTransferRemoteEvent {
    /// The identifier of the origin chain
    pub origin: u32,
    /// The address of the recipient on this chain
    pub recipient: b256,
    /// The amount of tokens received
    pub amount: u64,
}

/// Errors that can occur when interacting with the TokenRouter contract
pub enum TokenRouterError {
    /// Thrown when attempting to initialize an already initialized contract
    ContractAlreadyInitialized: (),
    /// Thrown when trying to interact with an uninitialized contract
    ContractNotInitialized: (),
    /// Thrown when attempting to interact with a domain that has no router set
    RouterNotSet: (),
    /// Thrown when the message sender doesn't match the enrolled router
    InvalidSender: (),
    /// Thrown when the length of domains and routers arrays don't match
    RouterLengthMismatch: (),
}

/// Interface for the TokenRouter contract which handles cross-chain token transfers
abi TokenRouter {
    /// Transfers tokens to a recipient on a remote domain using the specified hook
    /// and message parameters.
    ///
    /// ### Arguments
    ///
    /// * `destination`: [u32] - The identifier of the destination chain
    /// * `recipient`: [b256] - The address of the recipient on the destination chain
    /// * `amount`: [u64] - The amount of tokens to transfer
    /// * `message_body`: [Bytes] - The encoded message body
    /// * `metadata`: [Bytes] - Additional metadata for the hook
    /// * `hook`: [ContractId] - The post dispatch hook contract to use
    ///
    /// ### Returns
    ///
    /// * [b256] - The message ID of the dispatched transfer
    #[payable]
    #[storage(read, write)]
    fn transfer_remote(
        destination: u32,
        recipient: b256,
        amount: u64,
        message_body: Bytes,
        metadata: Bytes,
        hook: ContractId,
    ) -> b256;

    /// Handles an incoming transfer message from a remote domain
    ///
    /// ### Arguments
    ///
    /// * `origin`: [u32] - The origin domain
    /// * `sender`: [b256] - The sender address
    /// * `message`: [Bytes] - The transfer message
    #[storage(read, write)]
    fn handle(origin: u32, sender: b256, message: Bytes);

    /// Gets the router address for a specific domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to query
    ///
    /// ### Returns
    ///
    /// * [b256] - The router address for the domain
    #[storage(read)]
    fn router(domain: u32) -> b256;

    /// Enrolls a new router for a specific domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to enroll
    /// * `router`: [b256] - The router address to enroll
    #[storage(read, write)]
    fn enroll_remote_router(domain: u32, router: b256);

    /// Batch enrolls multiple routers for multiple domains
    ///
    /// ### Arguments
    ///
    /// * `domains`: [Vec<u32>] - The domains to enroll
    /// * `routers`: [Vec<b256>] - The router addresses to enroll
    #[storage(read, write)]
    fn enroll_remote_routers(domains: Vec<u32>, routers: Vec<b256>);

    /// Removes a router for a specific domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to unenroll
    #[storage(read, write)]
    fn unenroll_remote_router(domain: u32);
}

