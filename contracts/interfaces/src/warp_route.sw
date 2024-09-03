library;

use std::{bytes::Bytes, storage::storage_string::*, string::String, u128::U128};
use message::Message;

pub enum WarpRouteError {
    PaymentError: (),
    Unauthorized: (),
    InsufficientFunds: (),
    MessageAlreadyDelivered: (),
    AlreadyInitialized: (),
    InvalidAddress: (),
    AssetIdRequiredForCollateral: (),
    MaxMinted: (),
    NoRouter: u32,
}

pub enum WarpRouteTokenMode {
    BRIDGED: (),
    COLLATERAL: (),
}

pub struct TokenMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64,
    pub asset_id: AssetId,
    pub sub_id: SubId,
}

abi WarpRoute {
    #[storage(read, write)]
    fn initialize(
        owner: b256,
        mailbox_address: b256,
        mode: WarpRouteTokenMode,
        hook: b256,
        //Token Details
        token_name: String,
        token_symbol: String,
        decimals: u8,
        total_supply: u64,
        asset_id: Option<AssetId>,
    );

    #[storage(read, write)]
    #[payable]
    fn transfer_remote(destination_domain: u32, recipient: b256, amount: u64);

    #[storage(read, write)]
    fn handle_message(id: b256, origin: u32, sender: b256, message_body: Bytes);

    #[storage(read)]
    fn get_token_mode() -> WarpRouteTokenMode;

    #[storage(read)]
    fn get_token_info() -> TokenMetadata;

    #[storage(read)]
    fn get_mailbox() -> b256;

    #[storage(read)]
    fn get_hook() -> b256;

    #[storage(write)]
    fn set_mailbox(mailbox_address: b256);

    #[storage(write)]
    fn set_hook(hook: b256);

    #[storage(read)]
    fn is_message_delivered(message_id: b256) -> bool;

    #[storage(read)]
    fn get_cumulative_supply() -> u64; 

    // TODO: must be removed after unit and E2E testing 
    #[storage(read, write)]
    fn mint_tokens(recipient: Address, amount: u64);
}

/// Events
pub struct TransferRemoteEvent {
    pub destination_domain: u32,
    pub hook_contract: ContractId,
    pub message_id: b256,
}

pub struct HandleMessageEvent {
    pub recipient: b256,
    pub amount: u64,
    pub token_metadata: TokenMetadata,
}
