contract;

use merkle::*;
use message::{EncodedMessage, Message};
use std::{bytes::Bytes, context::msg_amount,};
use interfaces::{mailbox::*, merkle_tree_hook::*, post_dispatch_hook::*};

storage {
    merkle_tree: StorageMerkleTree = StorageMerkleTree {},
    mailbox: ContractId = ContractId::zero(),
}

impl MerkleTreeHook for Contract {
    #[storage(write)]
    fn initialize(mailbox: ContractId) {
        require(
            !_is_initialized(),
            MerkleTreeError::ContractAlreadyInitialized,
        );
        storage.mailbox.write(mailbox);
    }

    #[storage(read)]
    fn count() -> u32 {
        _count()
    }

    #[storage(read)]
    fn root() -> b256 {
        storage.merkle_tree.root()
    }

    #[storage(read)]
    fn latest_checkpoint() -> (b256, u32) {
        (storage.merkle_tree.root(), storage.merkle_tree.get_count() - 1)
    }
}

impl PostDispatchHook for Contract {
    #[storage(read)]
    fn hook_type() -> PostDispatchHookType {
        PostDispatchHookType::MERKLE_TREE
    }

    #[storage(read)]
    fn supports_metadata(_metadata: Bytes) -> bool {
        false
    }

    #[payable]
    #[storage(read, write)]
    fn post_dispatch(_metadata: Bytes, message: Bytes) {
        require(msg_amount() == 0, MerkleTreeError::NoValueExpected);
        require(_is_initialized(), MerkleTreeError::ContractNotInitialized);

        let message = EncodedMessage::from_bytes(message);

        let id = message.id();
        let mailbox = abi(Mailbox, b256::from(storage.mailbox.read()));
        let latest_dispatched = mailbox.latest_dispatched_id();
        // let latest_dispatched = b256::zero();

        require(
            latest_dispatched == id,
            MerkleTreeError::MessageNotDispatching(id),
        );

        let index = _count();
        storage.merkle_tree.insert(id);
        log(MerkleTreeEvent::InsertedIntoTree((id, index)));
    }

    #[storage(read)]
    fn quote_dispatch(_metadata: Bytes, _message: Bytes) -> u64 {
        0
    }
}

#[storage(read)]
fn _count() -> u32 {
    storage.merkle_tree.get_count()
}

#[storage(read)]
fn _is_initialized() -> bool {
    storage.mailbox.read() != ContractId::zero()
}
