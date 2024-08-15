contract;

use sway_libs::{ownership::*, pausable::*, reentrancy::reentrancy_guard,};
use standards::src5::State;

use interfaces::{
    isms::ism::*,
    mailbox::{mailbox::*, events::*},
    message_recipient::MessageRecipient,
    ownable::Ownable,
    post_dispatch_hook::*,
};
use std::{
    bytes::Bytes,
    constants::ZERO_B256,
    context::msg_amount,
    contract_id::ContractId,
    convert::Into,
    hash::*,
    revert::revert,
    storage::storage_map::*,
};
use message::{EncodedMessage, Message};

/// Hyperlane Protocol Version.
const VERSION = 3;

/// The max bytes in a message body. Equal to 2 KiB, or 2 * (2 ** 10).
const MAX_MESSAGE_BODY_BYTES: u64 = 2048;

enum MailboxError {
    InvalidISMAddress: (),
    InvalidHookAddress: (),
    InvalidProtocolVersion: u8,
    InvalidMessageOrigin: u32,
    MessageAlreadyDelivered: (),
    MessageVerificationFailed: (),
    AlreadyInitialized: (),
    MessageTooLarge: u64,
}

configurable {
    /// The domain of the local chain.
    /// Defaults to `fuel` (0x6675656c).
    LOCAL_DOMAIN: u32 = 0x6675656cu32,
}

storage {
    delivered: StorageMap<b256, bool> = StorageMap::<b256, bool> {},
    default_ism: ContractId = ContractId::from(ZERO_B256),
    default_hook: ContractId = ContractId::from(ZERO_B256),
    required_hook: ContractId = ContractId::from(ZERO_B256),
    latest_dispatched_id: b256 = ZERO_B256,
    nonce: u32 = 0,
}

impl Mailbox for Contract {
    /// Initializes the contract.
    #[storage(write)]
    fn initialize(
        owner: b256,
        default_ism: b256,
        default_hook: b256,
        required_hook: b256,
    ) {
        require(
            _owner() == State::Uninitialized,
            MailboxError::AlreadyInitialized,
        );

        initialize_ownership(Identity::Address(Address::from(owner)));
        storage.default_ism.write(ContractId::from(default_ism));
        storage.default_hook.write(ContractId::from(default_hook));
        storage.required_hook.write(ContractId::from(required_hook));
    }

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
        require(!module.is_zero(), MailboxError::InvalidISMAddress);
        storage.default_ism.write(module);
        log(DefaultIsmSetEvent { module });
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
        require(!module.is_zero(), MailboxError::InvalidHookAddress);
        storage.default_hook.write(module);
        log(DefaultHookSetEvent { module });
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
        require(!module.is_zero(), MailboxError::InvalidHookAddress);
        storage.required_hook.write(module);
        log(RequiredHookSetEvent { module });
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

    #[storage(read)]
    fn nonce() -> u32 {
        _nonce()
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

        require(
            message_body
                .len() <= MAX_MESSAGE_BODY_BYTES,
            MailboxError::MessageTooLarge(message_body.len()),
        );

        // ref mut hook in the function params does not work 
        let mut hook = hook;
        if hook == ContractId::from(ZERO_B256) {
            hook = storage.default_hook.read();
        }

        let message = _build_message(destination_domain, recipient_address, message_body);
        let id = message.id();

        storage.latest_dispatched_id.write(id);
        let nonce = _nonce();
        storage.nonce.write(nonce + 1);
        log(DispatchEvent {
            message_id: id,
            destination_domain,
            recipient_address: recipient_address,
            message: message.message_clean(),
        });
        log(DispatchIdEvent { message_id: id });

        let hook = abi(PostDispatchHook, b256::from(hook));
        let required_hook = abi(PostDispatchHook, b256::from(storage.required_hook.read()));
        let mut required_value = required_hook.quote_dispatch(metadata, message_body);
        if (msg_amount() < required_value) {
            required_value = msg_amount()
        }
        let base = AssetId::base();

        required_hook
            .post_dispatch {
                asset_id: b256::from(base),
                coins: required_value,
            }(metadata, message.bytes);
        hook
            .post_dispatch {
                asset_id: b256::from(base),
                coins: msg_amount() - required_value,
            }(metadata, message.bytes);

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

        let message = EncodedMessage::from_bytes(message);

        let version = message.version();
        require(
            version == VERSION,
            MailboxError::InvalidProtocolVersion(version),
        );
        let domain = message.origin();
        require(
            domain == LOCAL_DOMAIN,
            MailboxError::InvalidMessageOrigin(domain),
        );
        let id = message.id();
        require(!_delivered(id), MailboxError::MessageAlreadyDelivered);
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
            MailboxError::MessageVerificationFailed,
        );

        let sender = message.sender();
        msg_recipient.handle(domain, sender, message.body());

        log(ProcessEvent {
            message_id: id,
            origin: domain,
            sender,
            recipient,
        });
    }

    #[storage(read, write)]
    fn recipient_ism(recipient: ContractId) -> ContractId {
        let recipient = abi(MessageRecipient, recipient.into());
        recipient.interchain_security_module() 
    }
}

// Internal Contract Functions

#[storage(read)]
fn _nonce() -> u32 {
    storage.nonce.read()
}

#[storage(read)]
fn _build_message(
    destination_domain: u32,
    recipient: b256,
    message_body: Bytes,
) -> EncodedMessage {
    let nonce = _nonce();
    let sender = b256::from(msg_sender().unwrap().as_address().unwrap());

    EncodedMessage::new(
        VERSION,
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
