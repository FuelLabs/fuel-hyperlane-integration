library;

use std::{bytes::Bytes, storage::*};
use message::EncodedMessage;

abi Router {
    /// Returns all enrolled domain IDs.
    ///
    /// ### Returns
    ///
    /// * [Vec<u32>] - List of enrolled domain IDs.
    #[storage(read)]
    fn domains() -> Vec<u32>;

    /// Returns the router address for the given domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The remote domain ID.
    ///
    /// ### Returns
    ///
    /// * [b256] - The address of the Router contract for the given domain
    #[storage(read)]
    fn routers(domain: u32) -> b256;

    /// Unregister a domain's router.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain of the remote Application Router
    #[storage(write)]
    fn unenroll_remote_router(domain: u32);

    /// Register the address of a Router contract for the same Application on a remote chain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain of the remote Application Router
    /// * `router`: [b256] - The address of the remote Application Router
    #[storage(write)]
    fn enroll_remote_router(domain: u32, router: b256);

    /// Batch version of `enroll_remote_router`.
    ///
    /// ### Arguments
    ///
    /// * `domains`: [Vec<u32>] - The domains of the remote Application Routers
    /// * `routers`: [Vec<b256>] - The addresses of the remote Application Routers
    #[storage(write)]
    fn enroll_remote_routers(domains: Vec<u32>, routers: Vec<b256>);

    /// Batch version of `unenroll_remote_router`.
    ///
    /// ### Arguments
    ///
    /// * `domains`: [Vec<u32>] - The domains of the remote Application Routers
    #[storage(write)]
    fn unenroll_remote_routers(domains: Vec<u32>);

    /// Handles an incoming message.
    ///
    /// ### Arguments
    ///
    /// * `origin`: [u32] - The origin domain
    /// * `sender`: [b256] - The sender address
    /// * `message`: [Bytes] - The message
    #[storage(read)]
    fn handle(origin: u32, sender: b256, message: Bytes);

    /// Dispatches a message to a remote router.
    ///
    /// ### Arguments
    ///
    /// * `destination_domain`: [u32] - The destination domain
    /// * `value`: [u64] - The value to send with the message
    /// * `message_body`: [Bytes] - The message body
    /// * `hook_metadata`: [Bytes] - Additional metadata for hooks
    /// * `hook`: [ContractId] - The hook contract to use
    ///
    /// ### Returns
    ///
    /// * [b256] - The message ID
    #[storage(read)]
    fn dispatch(
        destination_domain: u32,
        value: u64,
        message_body: Bytes,
        hook_metadata: Bytes,
        hook: ContractId,
    ) -> b256;

    /// Quotes the cost of dispatching a message.
    ///
    /// ### Arguments
    ///
    /// * `destination_domain`: [u32] - The destination domain
    /// * `message_body`: [Bytes] - The message body
    /// * `hook_metadata`: [Bytes] - Additional metadata for hooks
    /// * `hook`: [ContractId] - The hook contract to use
    ///
    /// ### Returns
    ///
    /// * [u64] - The quoted cost
    #[storage(read)]
    fn quote_dispatch(
        destination_domain: u32,
        message_body: Bytes,
        hook_metadata: Bytes,
        hook: ContractId,
    ) -> u64;
}
