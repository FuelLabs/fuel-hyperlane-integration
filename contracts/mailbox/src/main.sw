contract;

use sway_libs::{ownership::*, pausable::*, reentrancy::reentrancy_guard,};
use standards::src5::State;

use interfaces::{
    isms::ism::*,
    mailbox::{
        events::*,
        mailbox::*,
    },
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

/// Errors that can occur while interacting with the mailbox contract.
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
    /// A map of message IDs to a boolean indicating if the message has been processed.
    delivered: StorageMap<b256, bool> = StorageMap::<b256, bool> {},
    /// The default ISM used for message verification.
    default_ism: ContractId = ContractId::from(ZERO_B256),
    /// The default post dispatch hook, invoked after a message is dispatched.
    default_hook: ContractId = ContractId::from(ZERO_B256),
    /// The required post dispatch hook, invoked after a message is dispatched.
    required_hook: ContractId = ContractId::from(ZERO_B256),
    /// The latest dispatched message ID.
    latest_dispatched_id: b256 = ZERO_B256,
    /// The nonce used for message IDs.
    nonce: u32 = 0,
}

impl Mailbox for Contract {
    /// Initializes the contract.
    ///
    /// ### Arguments
    ///
    /// * `owner`: [b256] - The owner of the contract.
    /// * `default_ism`: [b256] - The default ISM contract Id.
    /// * `default_hook`: [b256] - The default hook contract Id.
    /// * `required_hook`: [b256] - The required hook contract Id.
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized.
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

    /// Gets the domain which is specified on contract initialization.
    ///
    /// ### Returns
    ///
    /// * [u32] - The domain of the contract.
    fn local_domain() -> u32 {
        LOCAL_DOMAIN
    }

    /// Returns true if the message has been processed.
    ///
    /// ### Arguments
    ///
    /// * `message_id`: [b256] - The unique identifier of the message.
    ///
    /// ### Returns
    ///
    /// * [bool] - True if the message has been processed.
    #[storage(read)]
    fn delivered(message_id: b256) -> bool {
        _delivered(message_id)
    }

    /// Sets the default ISM used for message verification.
    ///
    /// ### Arguments
    ///
    /// * `module`: [ContractId] - Address implementing ISM interface.
    ///
    /// ### Reverts
    ///
    /// * If the caller is not the owner.
    /// * If the provided ISM address is zero.
    #[storage(read, write)]
    fn set_default_ism(module: ContractId) {
        only_owner();
        require(!module.is_zero(), MailboxError::InvalidISMAddress);
        storage.default_ism.write(module);
        log(DefaultIsmSetEvent { module });
    }

    /// Gets the default ISM used for message verification.
    ///
    /// ### Returns
    ///
    /// * [ContractId] - Address implementing ISM interface.
    #[storage(read)]
    fn default_ism() -> ContractId {
        storage.default_ism.read()
    }

    /// Sets the required hook used for message verification.
    ///
    /// ### Arguments
    ///
    /// * `module`: [ContractId] - Address implementing Hook interface.
    ///
    /// ### Reverts
    ///
    /// * If the caller is not the owner.
    /// * If the provided hook address is zero.
    #[storage(write)]
    fn set_default_hook(module: ContractId) {
        only_owner();
        require(!module.is_zero(), MailboxError::InvalidHookAddress);
        storage.default_hook.write(module);
        log(DefaultHookSetEvent { module });
    }

    /// Gets the default hook used for message verification.
    ///
    /// ### Returns
    ///
    /// * [ContractId] - Address implementing Hook interface.
    #[storage(read)]
    fn default_hook() -> ContractId {
        storage.default_hook.read()
    }

    /// Sets the required hook used for message verification.
    ///
    /// ### Arguments
    ///
    /// * `module`: [ContractId] - Address implementing Hook interface.
    ///
    /// ### Reverts
    ///
    /// * If the caller is not the owner.
    /// * If the provided hook address is zero.
    #[storage(write)]
    fn set_required_hook(module: ContractId) {
        only_owner();
        require(!module.is_zero(), MailboxError::InvalidHookAddress);
        storage.required_hook.write(module);
        log(RequiredHookSetEvent { module });
    }

    /// Gets the required hook used for message verification.
    ///
    /// ### Returns
    ///
    /// * [ContractId] - Address implementing Hook interface.
    #[storage(read)]
    fn required_hook() -> ContractId {
        storage.required_hook.read()
    }

    /// Returns the ID of the last dispatched message.
    ///
    /// ### Returns
    ///
    /// * [b256] - The ID of the last dispatched message.
    #[storage(read)]
    fn latest_dispatched_id() -> b256 {
        storage.latest_dispatched_id.read()
    }

    /// Returns the number of inserted leaves (i.e. messages) in the merkle tree.
    ///
    /// ### Returns
    ///
    /// * [u32] - The number of leaves in the merkle tree.
    #[storage(read)]
    fn nonce() -> u32 {
        _nonce()
    }

    /// Dispatches a message to the destination domain and recipient.
    /// Returns the message's ID.
    ///
    /// ### Arguments
    ///
    /// * `destination_domain`: [u32] - The domain of the destination chain.
    /// * `recipient`: [b256] - Address of the recipient on the destination chain.
    /// * `message_body`: [Bytes] - Raw bytes content of the message body.
    /// * `metadata`: [Bytes] - Raw bytes content of the metadata.
    /// * `hook`: [ContractId] - The hook contract Id.
    ///
    /// ### Returns
    ///
    /// * [b256] - The ID of the dispatched message.
    ///
    /// ### Reverts
    ///
    /// * If the message body is too large.
    /// * If the contract is paused.
    /// * If reentrancy is detected.
    /// * If any external call fails.
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
            }(metadata, message.message_clean().bytes);
        hook
            .post_dispatch {
                asset_id: b256::from(base),
                coins: msg_amount() - required_value,
            }(metadata, message.message_clean().bytes);

        id
    }

    /// Quotes a price for dispatching a message
    ///
    /// ### Arguments
    ///
    /// * `destination_domain`: [u32] - The domain of the destination chain.
    /// * `recipient_address`: [b256] - Address of the recipient on the destination chain.
    /// * `message_body`: [Bytes] - Raw bytes content of the message body.
    /// * `metadata`: [Bytes] - Raw bytes content of the metadata.
    /// * `hook`: [ContractId] - The hook contract Id.
    ///
    /// ### Returns
    ///
    /// * [u64] - The price of the dispatch.
    ///
    /// ### Reverts
    ///
    /// * If any external call fails.
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
    /// * `metadata`: [Bytes] - The metadata for ISM verification.
    /// * `message`: [Bytes] - The message as emitted by dispatch.
    ///
    /// ### Reverts
    ///
    /// * If the contract is paused.
    /// * If reentrancy is detected.
    /// * If the message has already been delivered.
    /// * If the message's protocol version is invalid.
    /// * If the message's origin is invalid.
    /// * If the message's verification fails.
    /// * If any external call fails.
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
        let origin_domain = message.origin();
        require(
            origin_domain != LOCAL_DOMAIN,
            MailboxError::InvalidMessageOrigin(origin_domain),
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
                .verify(metadata, message.message_clean().bytes),
            MailboxError::MessageVerificationFailed,
        );

        let sender = message.sender();
        msg_recipient.handle(origin_domain, sender, message.body());

        log(ProcessEvent {
            message_id: id,
            origin: origin_domain,
            sender,
            recipient,
        });
    }

    /// Returns the ISM set by a recipient.
    ///
    /// ### Arguments
    ///
    /// * `recipient`: [ContractId] - The recipient's contract Id.
    ///
    /// ### Returns
    ///
    /// * [ContractId] - The ISM contract Id.
    ///
    /// ### Reverts
    ///
    /// * If recipient call fails.
    #[storage(read)]
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
    let sender: b256 = match msg_sender().unwrap() {
        Identity::Address(address) => address.into(),
        Identity::ContractId(contract_id) => contract_id.into(),
    };

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
