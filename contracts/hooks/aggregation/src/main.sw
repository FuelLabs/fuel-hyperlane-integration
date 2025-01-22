contract;

use std::{
    bytes::Bytes,
    context::msg_amount,
    contract_id::ContractId,
    revert::revert,
    storage::storage_vec::*,
};

use sway_libs::ownership::*;
use standards::src5::State;
use std_hook_metadata::*;
use interfaces::{aggregation_hook::*, ownable::Ownable, post_dispatch_hook::*,};

storage {
    /// The list of hooks to aggregate
    hooks: StorageVec<ContractId> = StorageVec {},
}

impl AggregationHook for Contract {
    /// Initializes the AggregationHook contract.
    ///
    /// ### Arguments
    ///
    /// * `owner`: [b256] - The owner of the contract.
    /// * `hooks`: [Vec<ContractId>] - The hooks to initialize with.
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized.
    #[storage(write)]
    fn initialize(owner: b256, hooks: Vec<ContractId>) {
        require(
            !_is_initialized(),
            AggregationHookError::ContractAlreadyInitialized,
        );
        initialize_ownership(Identity::Address(Address::from(owner)));
        let mut i = 0;
        while i < hooks.len() {
            storage.hooks.push(hooks.get(i).unwrap());
            i += 1;
        }
    }

    /// Adds a new hook to the aggregator
    ///
    /// ### Arguments
    ///
    /// * `hook`: [ContractId] - The hook to add
    ///
    /// ### Reverts
    ///
    /// * If the contract is not initialized
    /// * If the caller is not the owner
    /// * If the hook already exists
    #[storage(read, write)]
    fn add_hook(hook: ContractId) {
        only_owner();
        require(
            _is_initialized(),
            AggregationHookError::ContractNotInitialized,
        );
        require(!_hook_exists(hook), AggregationHookError::HookAlreadyExists);

        storage.hooks.push(hook);
    }

    /// Removes a hook from the contract.
    ///
    /// ### Arguments
    ///
    /// * `hook`: [ContractId] - The hook to remove
    ///
    /// ### Reverts
    ///
    /// * If the contract is not initialized
    /// * If the caller is not the owner
    /// * If the hook does not exist
    #[storage(read, write)]
    fn remove_hook(hook: ContractId) {
        only_owner();
        require(
            _is_initialized(),
            AggregationHookError::ContractNotInitialized,
        );

        let hooks = storage.hooks.load_vec();
        let mut i = 0;
        let mut found = false;

        while i < hooks.len() {
            if hooks.get(i).unwrap() == hook {
                let removed = storage.hooks.remove(i);
                require(removed == hook, AggregationHookError::HookCannotBeRemoved);
                found = true;
                break;
            }
            i += 1;
        }

        require(found, AggregationHookError::HookNotFound);
    }

    /// Returns the hooks.
    ///
    /// ### Returns
    ///
    /// * `hooks`: [Vec<ContractId>] - The hooks.
    #[storage(read)]
    fn get_hooks() -> Vec<ContractId> {
        require(
            _is_initialized(),
            AggregationHookError::ContractNotInitialized,
        );
        storage.hooks.load_vec()
    }
}

impl PostDispatchHook for Contract {
    /// Returns an enum that represents the type of hook
    ///
    /// ### Returns
    ///
    /// * [PostDispatchHookType] - The type of the hook.
    fn hook_type() -> PostDispatchHookType {
        PostDispatchHookType::AGGREGATION
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
    #[storage(read)]
    fn supports_metadata(metadata: Bytes) -> bool {
        StandardHookMetadata::is_valid(metadata)
    }

    /// Compute the payment required by the postDispatch call
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata required for the hook.
    /// * `message`: [Bytes] - The message being dispatched.
    ///
    /// ### Returns
    ///
    /// * [u64] - The payment required for the postDispatch call.
    ///
    /// ### Reverts
    ///
    /// * If the contract is not initialized.
    #[storage(read)]
    fn quote_dispatch(metadata: Bytes, message: Bytes) -> u64 {
        let hooks = storage.hooks.load_vec();
        require(hooks.len() > 0, AggregationHookError::NoHooksConfigured);

        let (_, total) = _calculate_quotes(hooks, metadata, message);
        total
    }

    /// Executes the postDispatch call on all hooks
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata required for the hook.
    /// * `message`: [Bytes] - The message being dispatched.
    ///
    /// ### Reverts
    ///
    /// * If the contract is not initialized.
    #[payable]
    #[storage(read, write)]
    fn post_dispatch(metadata: Bytes, message: Bytes) {
        let hooks = storage.hooks.load_vec();
        require(hooks.len() > 0, AggregationHookError::NoHooksConfigured);

        let (quotes, total) = _calculate_quotes(hooks, metadata, message);
        require(
            msg_amount() == total,
            AggregationHookError::IncorrectTotalHookPayment,
        );

        let mut i = 0;
        while i < hooks.len() {
            let hook = hooks.get(i).unwrap();
            let quote = quotes.get(i).unwrap();

            let hook_contract = abi(PostDispatchHook, hook.bits());
            hook_contract.post_dispatch {
                asset_id: b256::from(AssetId::base()),
                coins: quote,
            }(metadata.clone(), message.clone());

            i += 1;
        }
    }
}

// --------------------------------------------
// --------- Ownable Implementation -----------
// --------------------------------------------

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
        initialize_ownership(new_owner);
    }
    #[storage(read, write)]
    fn renounce_ownership() {
        renounce_ownership();
    }
}

// ------------------------------------------------------------
// ------------------ Internal Functions ----------------------
// ------------------------------------------------------------

/// Checks if the contract is initialized.
///
/// ### Returns
///
/// * [bool] - Whether the contract is initialized.
#[storage(read)]
fn _is_initialized() -> bool {
    _owner() != State::Uninitialized
}

/// Checks if a hook exists in the contract.
///
/// ### Arguments
///
/// * `hook`: [ContractId] - The hook to check for
///
/// ### Returns
///
/// * [bool] - Whether the hook exists.
#[storage(read)]
fn _hook_exists(hook: ContractId) -> bool {
    let hooks = storage.hooks.load_vec();
    let mut i = 0;
    while i < hooks.len() {
        if hooks.get(i).unwrap() == hook {
            return true;
        }
        i += 1;
    }
    false
}

/// Internal function to calculate quotes for all hooks
///
/// ### Arguments
///
/// * hooks: [Vec<ContractId>] - List of hooks to calculate quotes for
/// * metadata: [Bytes] - The metadata to pass to each hook
/// * message: [Bytes] - The message to pass to each hook
///
/// ### Returns
///
/// * ([Vec<u64>], u64) - Tuple of (individual quotes, total sum)
fn _calculate_quotes(hooks: Vec<ContractId>, metadata: Bytes, message: Bytes) -> (Vec<u64>, u64) {
    let mut quotes = Vec::new();
    let mut total = 0;

    let mut i = 0;
    while i < hooks.len() {
        let hook = hooks.get(i).unwrap();
        let hook_contract = abi(PostDispatchHook, hook.bits());
        let quote = hook_contract.quote_dispatch(metadata.clone(), message.clone());

        quotes.push(quote);
        total += quote;

        i += 1;
    }
    (quotes, total)
}
