contract;

use interfaces::{
    hooks::{
        fallback_domain_routing_hook::*,
        post_dispatch_hook::*,
    },
    ownable::*,
};
use standards::src5::State;
use sway_libs::{ownership::*, pausable::*};
use std::bytes::Bytes;
use std::{constants::ZERO_B256, context::msg_amount, hash::*, storage::storage_map::*};
use message::*;

configurable {
    EXPECTED_OWNER: b256 = b256::zero(),
}

storage {
    /// The hook to fall back to if no hook is found.
    fallback_hook: b256 = ZERO_B256,
    /// The hooks for each destination domain.
    hooks: StorageMap<u32, b256> = StorageMap::<u32, b256> {},
}

impl FallbackDomainRoutingHook for Contract {
    /// Initializes the contract.
    ///
    /// ### Arguments
    ///
    /// * `owner`: [Identity] - The owner of the contract.
    /// * `fallback`: [b256] - The hook to fall back to if no hook is found.
    #[storage(write)]
    fn initialize(owner: Identity, fallback: b256) {
        initialize_ownership(owner);
        storage.fallback_hook.write(fallback);
    }

    /// Sets the hook for a given destinationd domain.
    ///
    /// ### Arguments
    ///
    /// * `destination`: [u32] - The destination domain.
    /// * `hook`: [b256] - The hook to call for that domain.
    #[storage(read, write)]
    fn set_hook(destination: u32, hook: b256) {
        only_owner();
        storage.hooks.insert(destination, hook);
    }

    /// Sets the hooks for multiple destination domains.
    ///
    /// ### Arguments
    ///
    /// * `hooks`: [Vec<HookConfig>] - The hooks to set.
    #[storage(read, write)]
    fn set_hooks(hooks: Vec<HookConfig>) {
        only_owner();
        let mut hooks = hooks;
        while true {
            let hook = hooks.pop();

            if hook.is_some() {
                let hook = hook.unwrap();
                storage.hooks.insert(hook.destination, hook.hook);
            } else {
                break;
            }
        };
    }
}

impl PostDispatchHook for Contract {
    /// Returns an enum that represents the type of hook
    ///
    /// ### Returns
    ///
    /// * [PostDispatchHookType] - The type of the hook.
    fn hook_type() -> PostDispatchHookType {
        PostDispatchHookType::FALLBACK_ROUTING
    }

    /// Returns whether the hook supports metadata
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata to be checked.
    ///
    /// ### Returns
    ///
    /// * [bool] - Whether the hook supports the metadata.
    fn supports_metadata(_metadata: Bytes) -> bool {
        // routing hook does not care about metadata shape
        true
    }

    /// Post action after a message is dispatched via the Mailbox
    /// For the MerkleTreeHook, this function inserts the message ID into the MerkleTree.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata required for the hook.
    /// * `message`: [Bytes] - The message to be processed.
    ///
    /// ### Reverts
    ///
    /// * If the contract is paused.
    #[payable]
    #[storage(read, write)]
    fn post_dispatch(metadata: Bytes, message: Bytes) {
        let hook_id = _get_configured_hook(message);
        let hook = abi(PostDispatchHook, hook_id);

        let base = AssetId::base();

        hook
            .post_dispatch {
                asset_id: b256::from(base),
                coins: msg_amount(),
            }(metadata, message);
    }

    /// Compute the payment required by the postDispatch call
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata required for the hook.
    /// * `message`: [Bytes] - The message to be processed.
    ///
    /// ### Returns
    ///
    /// * [u64] - The payment required for the postDispatch call.
    #[storage(read)]
    fn quote_dispatch(metadata: Bytes, message: Bytes) -> u64 {
        let hook_id = _get_configured_hook(message);
        let hook = abi(PostDispatchHook, hook_id);
        hook.quote_dispatch(metadata, message)
    }
}

#[storage(read)]
fn _get_configured_hook(message: Bytes) -> b256 {
    let domain = EncodedMessage::from_bytes(message).destination();
    let hook = storage.hooks.get(domain).try_read();

    if hook.is_some() {
        hook.unwrap()
    } else {
        storage.fallback_hook.read()
    }
}

// --- Ownership ---

impl Ownable for Contract {
    #[storage(read)]
    fn owner() -> State {
        _owner()
    }
    #[storage(read)]
    fn only_owner() {
        only_owner();
    }
    #[storage(write)]
    fn transfer_ownership(new_owner: Identity) {
        transfer_ownership(new_owner);
    }
    #[storage(read, write)]
    fn initialize_ownership(new_owner: Identity) {
        _is_expected_owner(new_owner);
        initialize_ownership(new_owner);
    }
    #[storage(read, write)]
    fn renounce_ownership() {
        renounce_ownership();
    }
}


// Front-run guard
fn _is_expected_owner(owner: Identity) {
    require(owner.bits() == EXPECTED_OWNER, OwnableError::UnexpectedOwner);
}