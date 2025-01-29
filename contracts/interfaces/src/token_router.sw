library;

use std::{bytes::Bytes, storage::*};
use message::EncodedMessage;

/// Errors that can occur when interacting with the TokenRouter contract
pub enum TokenRouterError {
    RouterNotSet: (),
    /// Thrown when the length of domains and routers arrays don't match
    RouterLengthMismatch: (),
}

/// Interface for the TokenRouter contract which handles cross-chain token transfers
abi TokenRouter {
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

    /// Gets all routers enrolled in the contract
    ///
    /// ### Returns
    ///
    /// * [Vec<b256>] - The routers enrolled in the contract
    #[storage(read)]
    fn all_routers() -> Vec<b256>;

    /// Gets all domains enrolled in the contract
    ///
    /// ### Returns
    ///
    /// * [Vec<u32>] - The domains enrolled in the contract
    #[storage(read)]
    fn all_domains() -> Vec<u32>;

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
    #[storage(write)]
    fn unenroll_remote_router(domain: u32) -> bool;

    /// Gets the decimals for a specific remote router
    ///
    /// ### Arguments
    ///
    /// * `router`: [b256] - The router to query
    #[storage(read)]
    fn remote_router_decimals(router: b256) -> u8;

    /// Sets the decimals for a specific remote router
    ///
    /// ### Arguments
    ///
    /// * `router`: [b256] - The router to set
    /// * `decimals`: [u8] - The decimals to set
    #[storage(write)]
    fn set_remote_router_decimals(router: b256, decimals: u8);
}
