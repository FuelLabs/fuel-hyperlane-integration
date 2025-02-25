contract;

use merkle::*;
use message::EncodedMessage;
use std::storage::storage_vec::*;
use std::{block::height, bytes::Bytes, context::msg_amount};
use interfaces::{mailbox::mailbox::*, hooks::{merkle_tree_hook::*, post_dispatch_hook::*}};

configurable {
    EXPECTED_INITIALIZER: b256 = b256::zero(),
}

storage {
    merkle_tree: StorageMerkleTree = StorageMerkleTree {},
    mailbox: ContractId = ContractId::zero(),
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
        _is_expected_caller();
        require(
            !_is_initialized(),
            MerkleTreeHookError::ContractAlreadyInitialized,
        );
        storage.mailbox.write(mailbox);
    }

    /// Returns the count from the MerkleTree.
    ///
    /// ### Returns
    ///
    /// * [u32] - The count from the MerkleTree.
    #[storage(read)]
    fn count() -> u32 {
        _count()
    }

    /// Gets the stored count of the MerkleTree.
    /// And the current block number.
    /// Used since we cannot query point in time data.
    ///
    /// ### Returns
    ///
    /// * [(u32, u32)] - The count and the current block number.
    #[storage(read)]
    fn count_and_block() -> (u32, u32) {
        (_count(), height())
    }

    /// Returns the root from the MerkleTree.
    ///
    /// ### Returns
    ///
    /// * [b256] - The root from the MerkleTree.
    #[storage(read)]
    fn root() -> b256 {
        _root()
    }

    /// Returns the latest checkpoint from the MerkleTree.
    ///
    /// ### Returns
    ///
    /// * [b256] - The root from the MerkleTree.
    /// * [u32] - The count from the MerkleTree.
    #[storage(read)]
    fn tree() -> MerkleTree {
        storage.merkle_tree.load()
    }

    #[storage(read)]
    fn latest_checkpoint() -> (b256, u32) {
        _checkpoint()
    }
}

impl PostDispatchHook for Contract {
    /// Returns an enum that represents the type of hook
    ///
    /// ### Returns
    ///
    /// * [PostDispatchHookType] - The type of the hook.
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
        require(msg_amount() == 0, MerkleTreeHookError::NoValueExpected);
        require(
            _is_initialized(),
            MerkleTreeHookError::ContractNotInitialized,
        );

        let message = EncodedMessage::from_bytes(message);

        let id = message.id();
        let mailbox = abi(Mailbox, b256::from(storage.mailbox.read()));
        let latest_dispatched = mailbox.latest_dispatched_id();

        require(
            latest_dispatched == id,
            MerkleTreeHookError::MessageNotDispatching(id),
        );

        let index = _count();
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

// Front-run guard
fn _is_expected_caller() {
    let sender = msg_sender().unwrap().bits();
    require(sender == EXPECTED_INITIALIZER, MerkleTreeHookError::UnexpectedInitAddress);
}
