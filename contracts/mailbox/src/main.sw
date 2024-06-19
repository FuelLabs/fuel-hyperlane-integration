contract;

use standards::src5::State;
use sway_libs::{ownership::*, pausable::*, reentrancy::reentrancy_guard,};

use interfaces::{
    events::*,
    ism::*,
    mailbox::Mailbox,
    message_recipient::MessageRecipient,
    ownable::Ownable,
    post_dispatch_hook::*,
};
use std::{
    bytes::Bytes,
    constants::ZERO_B256,
    context::msg_amount,
    contract_id::ContractId,
    hash::*,
    revert::revert,
    storage::storage_map::*,
};
use merkle::*;
use message::{EncodedMessage, Message};

/// Hyperlane Protocol Version.
const VERSION = 3;

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
    nonce: u32 = 0,
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
        _delivered(message_id)
    }

    /// Sets the default ISM used for message verification.
    ///
    /// ### Arguments
    ///
    /// * `module` - Address implementing ISM interface.
    #[storage(read, write)]
    fn set_default_ism(module: ContractId) {
        only_owner();
        require(!module.is_zero(), "Invalid ISM address");
        storage.default_ism.write(module);
    }

    /// Gets the default ISM used for message verification.
    #[storage(read)]
    fn default_ism() -> ContractId {
        storage.default_ism.read()
    }

    /// Sets the default hook used for message processing.
    #[storage(write)]
    fn set_default_hook(module: ContractId) {
        only_owner();
        require(!module.is_zero(), "Invalid hook address");
        storage.default_hook.write(module);
    }

    /// Gets the default hook used for message processing.
    #[storage(read)]
    fn default_hook() -> ContractId {
        storage.default_hook.read()
    }

    /// Sets the required hook used for message processing.
    #[storage(write)]
    fn set_required_hook(module: ContractId) {
        only_owner();
        require(!module.is_zero(), "Invalid hook address");
        storage.required_hook.write(module);
    }

    /// Gets the required hook used for message processing.
    #[storage(read)]
    fn required_hook() -> ContractId {
        storage.required_hook.read()
    }

    #[storage(read)]
    fn latest_dispatched_id() -> b256 {
        storage.latest_dispatched_id.read()
    }

    /// Dispatches a message to the destination domain and recipient.
    /// Returns the message's ID.
    ///
    /// ### Arguments
    ///
    /// * `destination_domain` - The domain of the destination chain.
    /// * `recipient` - Address of the recipient on the destination chain.
    /// * `message_body` - Raw bytes content of the message body.
    #[payable]
    #[storage(read, write)]
    fn dispatch(
        destination_domain: u32,
        recipient_address: b256,
        message_body: Bytes,
        metadata: Bytes,
        hook: ContractId,
    ) -> b256 {
        reentrancy_guard();
        require_not_paused();

        // ref mut hook in the function params does not work 
        let mut hook = hook;
        if hook == ContractId::from(ZERO_B256) {
            hook = storage.default_hook.read();
        }

        let message = _build_message(destination_domain, recipient_address, message_body);

        log(message.bytes);
        let id = message.id();
        log(id);

        storage.latest_dispatched_id.write(id);
        let nonce = storage.nonce.read();
        storage.nonce.write(nonce + 1);
        log(DispatchEvent {
            message_id: id,
            destination_domain,
            recipient_address: recipient_address,
            message,
        });
        log(DispatchIdEvent { message_id: id });

        // let hook = abi(PostDispatchHook, b256::from(hook));
        // let required_hook = abi(PostDispatchHook, b256::from(storage.required_hook.read()));
        // let mut required_value = required_hook.quote_dispatch(metadata, message_body);
        // if (msg_amount() < required_value) {
        //     required_value = msg_amount()
        // }
        // let base = AssetId::base();

        // required_hook
        //     .post_dispatch {
        //         asset_id: b256::from(base),
        //         coins: required_value,
        //     }(metadata, message.bytes);
        // hook
        //     .post_dispatch {
        //         asset_id: b256::from(base),
        //         coins: msg_amount() - required_value,
        //     }(metadata, message.bytes);

        id
    }

    /// Quotes the cost of dispatching a message to the destination domain and recipient.
    ///
    /// ### Arguments
    ///
    /// * `destination_domain` - The domain of the destination chain.
    /// * `recipient` - Address of the recipient on the destination chain.
    /// * `message_body` - Raw bytes content of the message body.
    #[storage(read)]
    fn quote_dispatch(
        destination_domain: u32,
        recipient_address: b256,
        message_body: Bytes,
        metadata: Bytes,
        hook: ContractId,
    ) -> u64 {
        let mut hook = hook;
        if hook == ContractId::from(ZERO_B256) {
            hook = storage.default_hook.read();
        }

        let message = _build_message(destination_domain, recipient_address, message_body);

        let required_hook = abi(PostDispatchHook, b256::from(storage.required_hook.read()));
        let hook = abi(PostDispatchHook, b256::from(hook));

        required_hook.quote_dispatch(metadata, message_body) + hook.quote_dispatch(metadata, message_body)
    }

    /// Processes a message.
    ///
    /// ### Arguments
    ///
    /// * `metadata` - The metadata for ISM verification.
    /// * `message` - The message as emitted by dispatch.
    #[storage(read, write)]
    fn process(metadata: Bytes, message: Bytes) {
        reentrancy_guard();
        require_not_paused();

        let message = EncodedMessage { bytes: message };

        require(message.version() == VERSION, "Invalid message version");
        require(
            message
                .origin() == LOCAL_DOMAIN,
            "Message origin does not match local domain",
        );
        let id = message.id();
        require(!_delivered(id), "Message already delivered");
        storage.delivered.insert(id, true);

        let recipient = message.recipient();

        let msg_recipient = abi(MessageRecipient, recipient);
        let mut ism_id = msg_recipient.interchain_security_module();
        if (ism_id == ContractId::from(ZERO_B256)) {
            ism_id = storage.default_ism.read()
        }

        let ism = abi(InterchainSecurityModule, ism_id.into());
        require(
            ism
                .verify(metadata, message.bytes),
            "Message verification failed",
        );

        let origin = message.origin();
        let sender = message.sender();

        msg_recipient.handle(origin, sender, message.body());

        log(ProcessEvent {
            message_id: id,
            origin,
            sender,
            recipient,
        });
    }

    /// Returns the number of inserted leaves (i.e. messages) in the merkle tree.
    #[storage(read)]
    fn count() -> u64 {
        // storage.merkle_tree.get_count()
        0
    }

    /// Calculates and returns the merkle tree's current root.
    #[storage(read)]
    fn root() -> b256 {
        // storage.merkle_tree.root()
        ZERO_B256
    }

    /// Returns a checkpoint representing the current merkle tree:
    /// (root of merkle tree, index of the last element in the tree).
    #[storage(read)]
    fn latest_checkpoint() -> (b256, u64) {
        // (storage.merkle_tree.root(), storage.merkle_tree.get_count())
        (ZERO_B256, 0)
    }
}

// Internal Contract Functions

#[storage(read)]
fn _build_message(
    destination_domain: u32,
    recipient: b256,
    message_body: Bytes,
) -> EncodedMessage {
    let nonce = storage.nonce.read();
    let sender = b256::from(msg_sender().unwrap().as_address().unwrap());

    EncodedMessage::new(
        3,
        nonce,
        LOCAL_DOMAIN,
        sender,
        destination_domain,
        recipient,
        message_body,
    )
}

#[storage(read)]
fn _delivered(message_id: b256) -> bool {
    storage.delivered.get(message_id).try_read().unwrap_or(false)
}

// Pausable and Ownable Implementations

impl Pausable for Contract {
    #[storage(write)]
    fn pause() {
        only_owner();
        _pause();
    }

    #[storage(write)]
    fn unpause() {
        only_owner();
        _unpause();
    }

    #[storage(read)]
    fn is_paused() -> bool {
        _is_paused()
    }
}

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

#[test]
fn initialize_mailbox() {
    let mailbox = abi(Mailbox, CONTRACT_ID);

    assert(mailbox.local_domain() == 0x6675656cu32);
    assert(mailbox.default_ism() == ContractId::from(ZERO_B256));
}
