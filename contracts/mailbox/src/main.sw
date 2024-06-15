contract;

use sway_libs::{
    ownership::_owner,
    pausable::{
        _is_paused,
        _pause,
        _unpause,
        Pausable,
    },
    reentrancy::reentrancy_guard,
};
use standards::src5::{SRC5, State};
use interfaces::mailbox::Mailbox;
use std::{
    bytes::Bytes,
    constants::ZERO_B256,
    contract_id::ContractId,
    hash::*,
    storage::storage_map::*,
};
use merkle::*;
// use message::{EncodedMessage, Message};

configurable {
    /// The domain of the local chain.
    /// Defaults to `fuel` (0x6675656c).
    LOCAL_DOMAIN: u32 = 0x6675656cu32,
}

storage {
    delivered: StorageMap<b256, bool> = StorageMap::<b256, bool> {},
    /// A merkle tree that includes outbound message IDs as leaves.
    merkle_tree: StorageMerkleTree = StorageMerkleTree {},
    default_ism: ContractId = ContractId::from(ZERO_B256),
    default_hook: ContractId = ContractId::from(ZERO_B256),
    required_hook: ContractId = ContractId::from(ZERO_B256),
    latest_dispatched_id: b256 = ZERO_B256,
}

impl Mailbox for Contract {
    /// Returns the domain of the chain where the contract is deployed.
    #[storage(read)]
    fn local_domain() -> u32 {
        LOCAL_DOMAIN
    }

    /// Returns true if the message has been processed.
    ///
    /// ### Arguments
    ///
    /// * `message_id` - The unique identifier of the message.
    #[storage(read)]
    fn delivered(message_id: b256) -> bool {
        storage.delivered.get(message_id).try_read().unwrap_or(false)
    }

    /// Sets the default ISM used for message verification.
    ///
    /// ### Arguments
    ///
    /// * `module` - Address implementing ISM interface.
    #[storage(read, write)]
    fn set_default_ism(module: ContractId) {
        storage.default_ism.write(module);
    }

    /// Gets the default ISM used for message verification.
    #[storage(read)]
    fn default_ism() -> ContractId {
        storage.default_ism.read()
    }

    fn set_default_hook(module: ContractId) {}

    fn default_hook() -> ContractId {
        ContractId::from(ZERO_B256)
    }

    fn set_required_hook(module: ContractId) {}

    fn required_hook() -> ContractId {
        ContractId::from(ZERO_B256)
    }

    fn latest_dispatched_id() -> b256 {
        ZERO_B256
    }

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
    ) -> b256 {
        ZERO_B256
    }

    // TODO #[payable]
    fn quote_dispatch(
        destination_domain: u32,
        recipient: b256,
        message_body: Bytes,
    ) -> b256 {
        ZERO_B256
    }

    /// Processes a message.
    ///
    /// ### Arguments
    ///
    /// * `metadata` - The metadata for ISM verification.
    /// * `message` - The message as emitted by dispatch.
    #[storage(read, write)]
    fn process(metadata: Bytes, message: Bytes) {}

    /// Returns the number of inserted leaves (i.e. messages) in the merkle tree.
    // TODO nonce ?
    #[storage(read)]
    fn count() -> u32 {
        0
    }

    /// Calculates and returns the merkle tree's current root.
    #[storage(read)]
    fn root() -> b256 {
        ZERO_B256
    }

    /// Returns a checkpoint representing the current merkle tree:
    /// (root of merkle tree, index of the last element in the tree).
    #[storage(read)]
    fn latest_checkpoint() -> (b256, u32) {
        (ZERO_B256, 0)
    }
}

impl Pausable for Contract {
    #[storage(write)]
    fn pause() {
        _pause();
    }

    #[storage(write)]
    fn unpause() {
        _unpause();
    }

    #[storage(read)]
    fn is_paused() -> bool {
        _is_paused()
    }
}

impl SRC5 for Contract {
    #[storage(read)]
    fn owner() -> State {
        _owner()
    }
}
