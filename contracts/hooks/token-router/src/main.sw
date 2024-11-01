contract;

use message::{EncodedMessage, Message};
use std::{bytes::Bytes, context::msg_amount, hash::Hash};
use interfaces::{mailbox::mailbox::*, post_dispatch_hook::*, token_router::*, warp_route::*};

/// Storage for managing cross-chain token routing
storage {
    /// Mapping of domain identifiers to their corresponding router addresses
    /// Each domain has a unique router that handles token transfers
    routers: StorageMap<u32, b256> = StorageMap {},
    /// The contract ID of the mailbox used for cross-chain messaging
    /// This is set during initialization and cannot be changed
    mailbox: ContractId = ContractId::zero(),
}

impl PostDispatchHookHelper for Contract {
    /// Initializes the TokenRouter contract with a mailbox contract ID
    /// This can only be called once and sets up the cross-chain messaging capability
    ///
    /// ### Arguments
    ///
    /// * `contract_id`: [ContractId] - The contract ID of the mailbox to use for messaging
    ///
    /// ### Reverts
    ///
    /// * If the contract has already been initialized
    #[storage(write)]
    fn initialize(contract_id: ContractId) {
        require(
            !_is_initialized(),
            TokenRouterError::ContractAlreadyInitialized,
        );
        storage.mailbox.write(contract_id);
    }
}

impl PostDispatchHook for Contract {
    /// Identifies this contract as a routing type hook in the Hyperlane protocol
    ///
    /// ### Returns
    ///
    /// * [PostDispatchHookType] - Always returns ROUTING type
    #[storage(read)]
    fn hook_type() -> PostDispatchHookType {
        PostDispatchHookType::ROUTING
    }

    /// Indicates whether this hook supports the given metadata
    /// This implementation accepts all metadata
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata to check (unused)
    ///
    /// ### Returns
    ///
    /// * [bool] - Always returns true
    #[storage(read)]
    fn supports_metadata(_metadata: Bytes) -> bool {
        true
    }

    /// Handles post-dispatch operations for token transfers
    /// Currently implemented as a no-op
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - Additional metadata for the operation
    /// * `message`: [Bytes] - The message being processed
    #[payable]
    #[storage(read, write)]
    fn post_dispatch(_metadata: Bytes, message: Bytes) {}

    /// Calculates the cost for post-dispatch operations
    /// Currently implemented with no cost
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - Additional metadata for the operation
    /// * `message`: [Bytes] - The message to be processed
    ///
    /// ### Returns
    ///
    /// * [u64] - Always returns 0
    #[storage(read)]
    fn quote_dispatch(_metadata: Bytes, message: Bytes) -> u64 {
        0
    }
}

impl TokenRouter for Contract {
    /// Initiates a cross-chain token transfer
    ///
    /// ### Arguments
    ///
    /// * `destination`: [u32] - The destination chain's domain ID
    /// * `recipient`: [b256] - The recipient's address on the destination chain
    /// * `amount`: [u64] - The amount of tokens to transfer
    /// * `message_body`: [Bytes] - The encoded message body
    /// * `metadata`: [Bytes] - Additional metadata for the transfer
    /// * `hook`: [ContractId] - The post-dispatch hook to use
    ///
    /// ### Returns
    ///
    /// * [b256] - The message ID of the transfer
    ///
    /// ### Reverts
    ///
    /// * If the contract is not initialized
    /// * If the destination domain has no router set
    #[payable]
    #[storage(read, write)]
    fn transfer_remote(
        destination: u32,
        recipient: b256,
        amount: u64,
        message_body: Bytes,
        metadata: Bytes,
        hook: ContractId,
    ) -> b256 {
        require(_is_initialized(), TokenRouterError::ContractNotInitialized);

        let remote_domain_router = _get_router(destination);
        require(
            remote_domain_router != b256::zero(),
            TokenRouterError::RouterNotSet,
        );

        // Dispatch via mailbox
        let mailbox_contract = abi(Mailbox, storage.mailbox.read().bits());
        let message_id = mailbox_contract.dispatch {
            asset_id: b256::from(AssetId::base()),
            coins: msg_amount(),
        }(
            destination,
            remote_domain_router,
            message_body,
            metadata,
            hook,
        );

        message_id
    }

    /// Handles an incoming transfer from another chain
    ///
    /// ### Arguments
    ///
    /// * `origin`: [u32] - The origin chain's domain ID
    /// * `sender`: [b256] - The sender's address from the origin chain
    /// * `message`: [Bytes] - The transfer message
    ///
    /// ### Reverts
    ///
    /// * If the sender is not the enrolled router for the origin domain
    #[storage(read, write)]
    fn handle(origin: u32, sender: b256, message: Bytes) {
        let router = _get_router(origin);
        require(router == sender, TokenRouterError::InvalidSender);

        // Emit event
        // log(ReceivedTransferRemoteEvent {
        //     origin,
        //     recipient: token_message.recipient,
        //     amount: token_message.amount,
        // });
    }

    /// Gets the router address for a specific domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to query
    ///
    /// ### Returns
    ///
    /// * [b256] - The router address (zero address if not set)
    #[storage(read)]
    fn router(domain: u32) -> b256 {
        _get_router(domain)
    }

    /// Removes a router for a specific domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to remove the router for
    #[storage(read, write)]
    fn unenroll_remote_router(domain: u32) {
        storage.routers.remove(domain);
    }

    /// Enrolls a new router for a specific domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to enroll
    /// * `router`: [b256] - The router address to enroll
    #[storage(read, write)]
    fn enroll_remote_router(domain: u32, router: b256) {
        _insert_route_to_state(domain, router);
    }

    /// Batch enrolls multiple routers for multiple domains
    ///
    /// ### Arguments
    ///
    /// * `domains`: [Vec<u32>] - The domains to enroll
    /// * `routers`: [Vec<b256>] - The router addresses to enroll
    ///
    /// ### Reverts
    ///
    /// * If the lengths of domains and routers arrays don't match
    #[storage(read, write)]
    fn enroll_remote_routers(domains: Vec<u32>, routers: Vec<b256>) {
        require(
            domains.len() == routers.len(),
            TokenRouterError::RouterLengthMismatch,
        );

        let mut domains = domains;
        let mut routers = routers;

        while true {
            let domain = domains.pop();
            let router = routers.pop();
            if domain.is_some() && router.is_some() {
                _insert_route_to_state(domain.unwrap(), router.unwrap());
            } else {
                break;
            }
        }
    }
}

// ------------------------------------------------------------
// ------------------ Internal Functions ----------------------
// ------------------------------------------------------------

/// Checks if the contract has been initialized
///
/// ### Returns
///
/// * [bool] - True if the contract has been initialized
#[storage(read)]
fn _is_initialized() -> bool {
    storage.mailbox.read() != ContractId::zero()
}

/// Gets the router address for a specific domain
///
/// ### Arguments
///
/// * `domain`: [u32] - The domain to query
///
/// ### Returns
///
/// * [b256] - The router address (zero address if not set)
#[storage(read)]
fn _get_router(domain: u32) -> b256 {
    storage.routers.get(domain).try_read().unwrap_or(b256::zero())
}

/// Stores a router address for a domain in the contract storage
///
/// ### Arguments
///
/// * `domain`: [u32] - The domain to set the router for
/// * `router`: [b256] - The router address to store
#[storage(read, write)]
fn _insert_route_to_state(domain: u32, router: b256) {
    storage.routers.insert(domain, router);
}
