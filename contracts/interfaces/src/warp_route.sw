library;

use std::{bytes::Bytes, storage::storage_string::*, string::String, u128::U128};
use message::Message;

/// Errors that can occur when interacting with the WarpRoute contract
pub enum WarpRouteError {
    InvalidAssetSend: (),
    PaymentNotEqualToRequired: (),
    InvalidAddress: (),
    AssetIdRequiredForCollateral: (),
    MaxMinted: (),
    RemoteDecimalsNotSet: (),
    AmountNotConvertible: (),
    SenderNotMailbox: (),
}

/// The mode of the WarpRoute contract
pub enum WarpRouteTokenMode {
    SYNTHETIC: (),
    COLLATERAL: (),
    NATIVE: (),
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
    /// * `owner`: [Identity] - The address of the owner of the contract
    /// * `mailbox_address`: [b256] - The address of the mailbox contract to use
    /// * `mode`: [WarpRouteTokenMode] - The mode of the WarpRoute contract
    /// * `hook`: [b256] - The address of the post dispatch hook contract to use
    /// * `ism`: [b256] - The address of the ISM contract to use
    /// * `token_name`: [Option<String>] - The name of the token
    /// * `token_symbol`: [Option<String>] - The symbol of the token
    /// * `decimals`: [Option<u8>] - The number of decimals of the token
    /// * `total_supply`: [Option<u64>] - The total supply of the token
    /// * `asset_id`: [Option<AssetId>] - The asset ID of the token
    /// * `asset_contract_id`: [Option<b256>] - The asset contract ID of the token
    #[storage(read, write)]
    fn initialize(
        owner: Identity,
        mailbox_address: b256,
        mode: WarpRouteTokenMode,
        hook: b256,
        ism: b256,
        //Token Details
        token_name: Option<String>,
        token_symbol: Option<String>,
        decimals: Option<u8>,
        total_supply: Option<u64>,
        asset_id: Option<AssetId>,
        asset_contract_id: Option<b256>,
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
    /// * [ContractId] - The mailbox contract ID
    #[storage(read)]
    fn get_mailbox() -> ContractId;

    /// Gets the post dispatch hook contract ID that the WarpRoute contract is using
    ///
    /// ### Returns
    ///
    /// * [ContractId] - The post dispatch hook contract ID
    #[storage(read)]
    fn get_hook() -> ContractId;

    /// Sets the mailbox contract ID that the WarpRoute contract is using for transfers
    ///
    /// ### Arguments
    ///
    /// * `mailbox_address`: [ContractId] - The mailbox contract ID
    #[storage(write)]
    fn set_mailbox(mailbox_address: ContractId);

    /// Sets the post dispatch hook contract ID that the WarpRoute contract is using
    ///
    /// ### Arguments
    ///
    /// * `hook`: [ContractId] - The post dispatch hook contract ID
    #[storage(write)]
    fn set_hook(hook: ContractId);

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

    /// Gets the quote for gas payment
    ///
    /// ### Arguments
    ///
    /// * `destination_domain`: [u32] - The destination domain
    #[storage(read)]
    fn quote_gas_payment(destination_domain: u32) -> u64;
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
