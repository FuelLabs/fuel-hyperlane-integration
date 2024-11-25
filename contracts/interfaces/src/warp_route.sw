library;

use std::{bytes::Bytes, storage::storage_string::*, string::String, u128::U128};
use message::Message;

/// Errors that can occur when interacting with the WarpRoute contract
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

/// The mode of the WarpRoute contract
pub enum WarpRouteTokenMode {
    BRIDGED: (),
    COLLATERAL: (),
}

/// The metadata of the token managed by the WarpRoute contract
pub struct TokenMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64,
    pub asset_id: AssetId,
    pub sub_id: SubId,
}

abi WarpRoute {
    /// Initializes the WarpRoute contract
    ///
    /// ### Arguments
    ///
    /// * `owner`: [b256] - The address of the owner of the contract
    /// * `mailbox_address`: [b256] - The address of the mailbox contract to use
    /// * `mode`: [WarpRouteTokenMode] - The mode of the WarpRoute contract
    /// * `hook`: [b256] - The address of the post dispatch hook contract to use
    /// * `token_name`: [string] - The name of the token
    /// * `token_symbol`: [string] - The symbol of the token
    /// * `decimals`: [u8] - The number of decimals of the token
    /// * `total_supply`: [u64] - The total supply of the token
    /// * `asset_id`: [Option<AssetId>] - The asset ID of the token
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

    /// Transfers tokens to a remote domain
    ///
    /// ### Arguments
    ///
    /// * `destination_domain`: [u32] - The domain to transfer the tokens to
    /// * `recipient`: [b256] - The address of the recipient
    /// * `amount`: [u64] - The amount of tokens to transfer
    #[payable]
    #[storage(read, write)]
    fn transfer_remote(destination_domain: u32, recipient: b256, amount: u64) -> b256;

    /// Gets the token mode of the WarpRoute contract
    ///
    /// ### Returns
    ///
    /// * [WarpRouteTokenMode] - The token mode
    #[storage(read)]
    fn get_token_mode() -> WarpRouteTokenMode;

    /// Gets the token metadata of the WarpRoute contract
    ///
    /// ### Returns
    ///
    /// * [TokenMetadata] - The token metadata
    #[storage(read)]
    fn get_token_info() -> TokenMetadata;

    /// Gets the mailbox contract ID that the WarpRoute contract is using for transfers
    ///
    /// ### Returns
    ///
    /// * [b256] - The mailbox contract ID
    #[storage(read)]
    fn get_mailbox() -> b256;

    /// Gets the post dispatch hook contract ID that the WarpRoute contract is using
    ///
    /// ### Returns
    ///
    /// * [b256] - The post dispatch hook contract ID
    #[storage(read)]
    fn get_hook() -> b256;

    /// Sets the mailbox contract ID that the WarpRoute contract is using for transfers
    ///
    /// ### Arguments
    ///
    /// * `mailbox_address`: [b256] - The mailbox contract ID
    #[storage(write)]
    fn set_mailbox(mailbox_address: b256);

    /// Sets the post dispatch hook contract ID that the WarpRoute contract is using
    ///
    /// ### Arguments
    ///
    /// * `hook`: [b256] - The post dispatch hook contract ID
    #[storage(write)]
    fn set_hook(hook: b256);

    /// Gets the total number of coins ever minted for an asset.
    ///
    /// ### Returns
    ///
    /// * [u64] - The total number of coins ever minted for an asset.
    #[storage(read)]
    fn get_cumulative_supply() -> u64;

    /// Sets the default ISM
    ///
    /// ### Arguments
    ///
    /// * `module`: [ContractId] - The ISM contract ID
    #[storage(read, write)]
    fn set_ism(module: ContractId);
}

// --------------- Events ---------------

/// Event emitted when tokens are transferred to a remote domain.
/// This event contains information about the destination chain, recipient, and amount.
pub struct SentTransferRemoteEvent {
    /// The identifier of the destination chain
    pub destination: u32,
    /// The address of the recipient on the destination chain
    pub recipient: b256,
    /// The amount of tokens being transferred
    pub amount: u64,
}

/// Event emitted when tokens are received from a remote domain.
/// This event contains information about the origin chain, recipient, and amount.
pub struct ReceivedTransferRemoteEvent {
    /// The identifier of the origin chain
    pub origin: u32,
    /// The address of the recipient on this chain
    pub recipient: b256,
    /// The amount of tokens received
    pub amount: u64,
}

/// Event emitted when tokens are locked in the WarpRoute contract
pub struct TokensLockedEvent {
    pub amount: u64,
    pub asset: AssetId,
}
