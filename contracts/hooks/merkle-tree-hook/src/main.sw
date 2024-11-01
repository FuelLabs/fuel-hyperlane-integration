contract;

use merkle::*;
use message::{EncodedMessage, Message};
use std::{bytes::Bytes, context::msg_amount,};
use interfaces::{mailbox::mailbox::*, merkle_tree_hook::*, post_dispatch_hook::*};

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
        require(
            !_is_initialized(),
            MerkleTreeError::ContractAlreadyInitialized,
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

    /// Returns the root from the MerkleTree.
    ///
    /// ### Returns
    ///
    /// * [b256] - The root from the MerkleTree.
    #[storage(read)]
    fn root() -> b256 {
        storage.merkle_tree.root()
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
        (storage.merkle_tree.root(), storage.merkle_tree.get_count() - 1)
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
        storage.merkle_tree.insert(id);
        log(MerkleTreeEvent::InsertedIntoTree((id, index)));
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

#[storage(read)]
fn _count() -> u32 {
    storage.merkle_tree.get_count()
}

#[storage(read)]
fn _is_initialized() -> bool {
    storage.mailbox.read() != ContractId::zero()
}
