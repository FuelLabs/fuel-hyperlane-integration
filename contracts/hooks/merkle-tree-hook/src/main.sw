contract;

use merkle::*;
use message::{EncodedMessage, Message};
use std::storage::storage_vec::*;
use std::{block::height, bytes::Bytes, context::msg_amount};
use interfaces::{mailbox::mailbox::*, merkle_tree_hook::*, post_dispatch_hook::*};

storage {
    merkle_tree: StorageMerkleTree = StorageMerkleTree {},
    mailbox: ContractId = ContractId::zero(),
    latest_insertion_block: u32 = 0,
    finalized_tree: StorageVec<b256> = StorageVec {},
    finalized_root: b256 = b256::zero(),
    finalized_count: u32 = 0,
}

impl MerkleTreeHook for Contract {
    /// Initializes the MerkleTreeHook contract with the given mailbox contract ID.
    ///
    /// ### Arguments
    ///
    /// * `mailbox`: [ContractId] - The contract ID of the mailbox contract.
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized.
    #[storage(write)]
    fn initialize(mailbox: ContractId) {
        require(
            !_is_initialized(),
            MerkleTreeError::ContractAlreadyInitialized,
        );
        storage.mailbox.write(mailbox);
        storage.finalized_root.write(_root());
    }

    /// Returns the count from the MerkleTree.
    ///
    /// ### Returns
    ///
    /// * [u32] - The count from the MerkleTree.
    #[storage(read)]
    fn count() -> u32 {
        _finalized_count()
    }

    /// Gets the stored count of the MerkleTree library.
    /// And the current block number.
    /// Used since we cannot query point in time data.
    ///
    /// ### Returns
    ///
    /// * [(u32, u32)] - The count and the current block number.
    #[storage(read)]
    fn count_and_block() -> (u32, u32) {
        _finalized_count_with_block()
    }

    /// Returns the root from the MerkleTree.
    ///
    /// ### Returns
    ///
    /// * [b256] - The root from the MerkleTree.
    #[storage(read)]
    fn root() -> b256 {
        _finalized_root()
    }

    /// Returns the latest checkpoint from the MerkleTree.
    ///
    /// ### Returns
    ///
    /// * [b256] - The root from the MerkleTree.
    /// * [u32] - The count from the MerkleTree.
    #[storage(read)]
    fn tree() -> MerkleTree {
        _finalized_tree()
    }

    #[storage(read)]
    fn latest_checkpoint() -> (b256, u32) {
        _finalized_checkpoint()
    }
}

impl PostDispatchHook for Contract {
    /// Returns an enum that represents the type of hook
    ///
    /// ### Returns
    ///
    /// * [PostDispatchHookType] - The type of the hook.
    #[storage(read)]
    fn hook_type() -> PostDispatchHookType {
        PostDispatchHookType::MERKLE_TREE
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
    fn supports_metadata(_metadata: Bytes) -> bool {
        false
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
    /// * If the contract is not initialized.
    /// * If the message ID is not the latest dispatched ID.
    /// * If there was assets sent with the function call.
    #[payable]
    #[storage(read, write)]
    fn post_dispatch(_metadata: Bytes, message: Bytes) {
        require(msg_amount() == 0, MerkleTreeError::NoValueExpected);
        require(_is_initialized(), MerkleTreeError::ContractNotInitialized);

        let message = EncodedMessage::from_bytes(message);

        let id = message.id();
        let mailbox = abi(Mailbox, b256::from(storage.mailbox.read()));
        let latest_dispatched = mailbox.latest_dispatched_id();

        require(
            latest_dispatched == id,
            MerkleTreeError::MessageNotDispatching(id),
        );

        let index = _count();
        _store_insertion_data(index);
        storage.merkle_tree.insert(id);
        log(InsertedIntoTreeEvent {
            message_id: id,
            index,
        });
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
    fn quote_dispatch(_metadata: Bytes, _message: Bytes) -> u64 {
        0
    }
}

// ------------------------------------------------------------
// ------------------ Internal Functions ----------------------
// ------------------------------------------------------------

// ------------------ Base Read Functions ---------------------

#[storage(read)]
fn _count() -> u32 {
    storage.merkle_tree.get_count()
}

#[storage(read)]
fn _tree() -> MerkleTree {
    storage.merkle_tree.load()
}

#[storage(read)]
fn _root() -> b256 {
    storage.merkle_tree.root()
}

#[storage(read)]
fn _checkpoint() -> (b256, u32) {
    (_root(), _count() - 1)
}

// ------------------------ Checks ----------------------------

#[storage(read)]
fn _is_initialized() -> bool {
    storage.mailbox.read() != ContractId::zero()
}

#[storage(read)]
fn _is_latest_insertion_block() -> bool {
    storage.latest_insertion_block.read() == height()
}

// --------------- Each insertion data write --------------------

#[storage(write, read)]
fn _store_insertion_data(current_count: u32) {
    if _is_latest_insertion_block() {
        return;
    }

    storage.finalized_tree.store_vec(_tree().branch);
    storage.finalized_root.write(_root());
    storage.finalized_count.write(current_count);
    storage.latest_insertion_block.write(height());
}

// ----------- Getters with enforced finality ----------------

#[storage(read)]
fn _finalized_count_with_block() -> (u32, u32) {
    if _is_latest_insertion_block() {
        (storage.finalized_count.read(), height())
    } else {
        (_count(), height())
    }
}

#[storage(read)]
fn _finalized_count() -> u32 {
    if _is_latest_insertion_block() {
        storage.finalized_count.read()
    } else {
        _count()
    }
}

#[storage(read)]
fn _finalized_tree() -> MerkleTree {
    if _is_latest_insertion_block() {
        MerkleTree {
            branch: storage.finalized_tree.load_vec(),
            count: storage.finalized_count.read(),
        }
    } else {
        _tree()
    }
}

#[storage(read)]
fn _finalized_checkpoint() -> (b256, u32) {
    if _is_latest_insertion_block() {
        (storage.finalized_root.read(), storage.finalized_count.read() - 1)
    } else {
        _checkpoint()
    }
}

#[storage(read)]
fn _finalized_root() -> b256 {
    if _is_latest_insertion_block() {
        storage.finalized_root.read()
    } else {
        _root()
    }
}
