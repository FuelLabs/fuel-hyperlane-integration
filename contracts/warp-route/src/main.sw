contract;

use sway_libs::{
    asset::{
        base::{
            _decimals,
            _name,
            _set_decimals,
            _set_name,
            _set_symbol,
            _symbol,
            _total_assets,
            _total_supply,
        },
        supply::{
            _burn,
            _mint,
        },
    },
    ownership::*,
    pausable::*,
    reentrancy::reentrancy_guard,
};

use std::{
    asset::transfer,
    bytes::Bytes,
    call_frames::msg_asset_id,
    constants::ZERO_B256,
    context::{
        balance_of,
        msg_amount,
        this_balance,
    },
    contract_id::ContractId,
    convert::Into,
    hash::*,
    revert::revert,
    storage::storage_map::*,
    storage::storage_string::*,
    storage::storage_vec::*,
    string::String,
    u128::U128,
};

use interfaces::{
    claimable::*,
    mailbox::mailbox::*,
    message_recipient::MessageRecipient,
    ownable::Ownable,
    token_router::*,
    warp_route::*,
};
use standards::{src20::SRC20, src5::State};
use message::{EncodedMessage, Message};

storage {
    /// The mode of the WarpRoute contract
    token_mode: WarpRouteTokenMode = WarpRouteTokenMode::SYNTHETIC, // Default mode is SYNTHETIC
    /// The address of the mailbox contract to use for message dispatch
    mailbox: ContractId = ContractId::zero(),
    /// The address of the default hook contract to use for message dispatch
    default_hook: ContractId = ContractId::zero(),
    /// The address of the beneficiary
    beneficiary: Identity = Identity::ContractId(ContractId::zero()),
    /// The address of the default ISM contract to use for message dispatch
    default_ism: ContractId = ContractId::zero(),
    /// Mapping of domain identifiers to their corresponding router addresses
    /// Each domain has a unique router that handles token transfers
    routers: StorageMap<u32, b256> = StorageMap {},
    ///List of unique domains
    domains: StorageVec<u32> = StorageVec {},
    /// Mapping of remote router decimals
    remote_router_decimals: StorageMap<b256, u8> = StorageMap {},
    /// Asset
    /// The asset ID of the token managed by the WarpRoute contract
    asset_id: AssetId = AssetId::zero(),
    /// The sub ID of the token managed by the WarpRoute contract
    sub_id: SubId = SubId::zero(),
    /// The total number of unique assets minted by this contract.
    total_assets: u64 = 0,
    /// The current total number of coins minted for a particular asset.
    total_supply: StorageMap<AssetId, u64> = StorageMap {},
    /// The mapping of asset ID to the name of the token
    name: StorageMap<AssetId, StorageString> = StorageMap {},
    /// The mapping of asset ID to the symbol of the token
    symbol: StorageMap<AssetId, StorageString> = StorageMap {},
    /// The mapping of asset ID to the number of decimals of the token
    decimals: StorageMap<AssetId, u8> = StorageMap {},
    /// The total number of coins ever minted for an asset.
    cumulative_supply: StorageMap<AssetId, u64> = StorageMap {},
}

configurable {
    /// The maximum supply allowed for any single asset.
    MAX_SUPPLY: u64 = 100_000_000_000_000,
    /// The default number of decimals for the base asset
    DEFAULT_DECIMALS: u8 = 9,
}

impl WarpRoute for Contract {
    /// Initializes the WarpRoute contract
    ///
    /// ### Arguments
    ///
    /// * `owner`: [b256] - The address of the owner of the contract
    /// * `mailbox_address`: [b256] - The address of the mailbox contract to use
    /// * `mode`: [WarpRouteTokenMode] - The mode of the WarpRoute contract
    /// * `hook`: [b256] - The address of the post dispatch hook contract to use
    /// * `ism`: [b256] - The address of the ISM contract to use
    /// * `token_name`: [Option<String>] - The name of the token
    /// * `token_symbol`: [Option<String>] - The symbol of the token
    /// * `decimals`: [Option<u8>] - The number of decimals of the token
    /// * `total_supply`: [Option<u64>] - The total supply of the token
    /// * `asset_id`: [Option<AssetId>] - The asset ID of the token - only required in collateral/native mode
    /// * `asset_contract_id`: [Option<b256>] - The asset contract ID of the token - only required in collateral mode
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized
    /// * If the asset ID is not provided in collateral mode
    #[storage(read, write)]
    fn initialize(
        owner: b256,
        mailbox_address: b256,
        mode: WarpRouteTokenMode,
        hook: b256,
        ism: b256,
        //Token
        token_name: Option<String>,
        token_symbol: Option<String>,
        decimals: Option<u8>,
        total_supply: Option<u64>,
        asset_id: Option<AssetId>,
        asset_contract_id: Option<b256>,
    ) {
        require(
            _owner() == State::Uninitialized,
            WarpRouteError::AlreadyInitialized,
        );

        let owner_id = Identity::Address(Address::from(owner));
        initialize_ownership(owner_id);
        storage.beneficiary.write(owner_id);
        storage.mailbox.write(ContractId::from(mailbox_address));
        storage.default_hook.write(ContractId::from(hook));
        storage.default_ism.write(ContractId::from(ism));
        storage.token_mode.write(mode);

        let sub_id = SubId::zero();
        storage.sub_id.write(sub_id);

        match mode {
            WarpRouteTokenMode::NATIVE => {
                let asset = asset_id.unwrap_or(AssetId::base());
                storage.asset_id.write(asset);

                let decimals = decimals.unwrap_or(DEFAULT_DECIMALS);
                _set_decimals(storage.decimals, asset, decimals);
                _set_name(storage.name, asset, String::from_ascii_str("Ethereum"));
                _set_symbol(storage.symbol, asset, String::from_ascii_str("ETH"));
            }
            WarpRouteTokenMode::SYNTHETIC => {
                // Derive asset_id based on contract_id and sub_id for synthetic mode
                let asset_id = AssetId::new(ContractId::this(), sub_id);

                save_token_details_to_state(
                    asset_id,
                    token_name
                        .unwrap(),
                    token_symbol
                        .unwrap(),
                    decimals
                        .unwrap(),
                    total_supply
                        .unwrap(),
                );
                storage.cumulative_supply.insert(asset_id, 0);
            }
            WarpRouteTokenMode::COLLATERAL => {
                // Require asset_id and asset_contract_id as input in collateral mode
                require(
                    asset_id
                        .is_some() && asset_contract_id
                        .is_some(),
                    WarpRouteError::AssetIdRequiredForCollateral,
                );
                let asset_id = asset_id.unwrap();
                let asset_contract_id = asset_contract_id.unwrap();
                let collateral_asset_contract = abi(SRC20, asset_contract_id);

                let name = collateral_asset_contract.name(asset_id).unwrap();
                let symbol = collateral_asset_contract.symbol(asset_id).unwrap();
                let decimals = collateral_asset_contract.decimals(asset_id).unwrap();
                let total_supply = collateral_asset_contract.total_supply(asset_id).unwrap();

                save_token_details_to_state(asset_id, name, symbol, decimals, total_supply);
            }
        };
    }

    /// Transfers tokens to a remote domain
    ///
    /// ### Arguments
    ///
    /// * `destination_domain`: [u32] - The domain to transfer the tokens to
    /// * `recipient`: [b256] - The address of the recipient
    /// * `amount`: [u64] - The amount of tokens to transfer
    ///
    /// ### Reverts
    ///
    /// * If the contract is paused
    /// * If reentrancy is detected
    /// * If the amount provided is greater than amount sent
    /// * If the asset ID of the asset being transferred is not the same as the asset ID set on the contract
    /// * If any external call fails
    #[payable]
    #[storage(read, write)]
    fn transfer_remote(
        destination_domain: u32,
        recipient: b256,
        amount: u64,
        metadata: Option<Bytes>,
        hook: Option<ContractId>,
    ) -> b256 {
        reentrancy_guard();
        require_not_paused();

        let remote_domain_router = _get_router(destination_domain);
        require(
            remote_domain_router != b256::zero(),
            TokenRouterError::RouterNotSet,
        );

        let remote_decimals = _get_remote_router_decimals(remote_domain_router);
        require(remote_decimals != 0, WarpRouteError::RemoteDecimalsNotSet);

        let asset = storage.asset_id.read();
        let mailbox = abi(Mailbox, b256::from(storage.mailbox.read()));
        let default_hook = storage.default_hook.read();
        let hook_contract = hook.unwrap_or(default_hook);

        let local_decimals = _decimals(storage.decimals, asset).unwrap_or(0);
        let adjusted_amount = _adjust_decimals(amount, local_decimals, remote_decimals);
        let message_body = _build_token_metadata_bytes(recipient, adjusted_amount);

        let token_mode = storage.token_mode.read();

        let quote = _get_quote_for_gas_payment(
            destination_domain,
            remote_domain_router,
            message_body,
            hook_contract,
        );

        let required_payment = match token_mode {
            WarpRouteTokenMode::SYNTHETIC => quote,
            WarpRouteTokenMode::COLLATERAL => quote,
            WarpRouteTokenMode::NATIVE => amount + quote,
        };

        require(
            msg_amount() == required_payment,
            WarpRouteError::PaymentNotEqualToRequired,
        );

        require(
            msg_asset_id() == AssetId::base(),
            WarpRouteError::InvalidAssetSend,
        );

        match token_mode {
            WarpRouteTokenMode::SYNTHETIC => {
                //Burn has checks inside along with decreasing total supply
                _burn(storage.total_supply, storage.sub_id.read(), amount);
            },
            WarpRouteTokenMode::NATIVE | WarpRouteTokenMode::COLLATERAL => {
                //Locked in the contract
                transfer(Identity::ContractId(ContractId::this()), asset, amount);
            },
        }

        let metadata = metadata.unwrap_or(Bytes::new()); // send empty metadata if not provided

        //Dispatch the message to the destination domain
        let message_id = mailbox.dispatch {
            coins: quote,
            asset_id: b256::from(AssetId::base()),
        }(
            destination_domain,
            remote_domain_router,
            message_body,
            metadata,
            hook_contract,
        );

        log(SentTransferRemoteEvent {
            destination: destination_domain,
            recipient,
            amount: adjusted_amount,
        });

        message_id
    }

    /// Gets the token mode of the WarpRoute contract
    ///
    /// ### Returns
    ///
    /// * [WarpRouteTokenMode] - The token mode
    #[storage(read)]
    fn get_token_mode() -> WarpRouteTokenMode {
        storage.token_mode.read()
    }

    /// Gets the token metadata of the WarpRoute contract
    ///
    /// ### Returns
    ///
    /// * [TokenMetadata] - The token metadata
    #[storage(read)]
    fn get_token_info() -> TokenMetadata {
        let asset = storage.asset_id.read();
        let res = _get_metadata_of_asset(asset);
        res
    }

    /// Gets the mailbox contract ID that the WarpRoute contract is using for transfers
    ///
    /// ### Returns
    ///
    /// * [ContractId] - The mailbox contract ID
    #[storage(read)]
    fn get_mailbox() -> ContractId {
        storage.mailbox.read()
    }

    /// Gets the total number of coins ever minted for an asset.
    ///
    /// ### Returns
    ///
    /// * [u64] - The total number of coins ever minted for an asset.
    #[storage(read)]
    fn get_cumulative_supply() -> u64 {
        let asset = storage.asset_id.read();
        storage.cumulative_supply.get(asset).try_read().unwrap_or(0)
    }

    /// Gets the post dispatch hook contract ID that the WarpRoute contract is using
    ///
    /// ### Returns
    ///
    /// * [ContractId] - The post dispatch hook contract ID
    #[storage(read)]
    fn get_hook() -> ContractId {
        storage.default_hook.read()
    }

    /// Sets the mailbox contract ID that the WarpRoute contract is using for transfers
    ///
    /// ### Arguments
    ///
    /// * `mailbox_address`: [ContractId] - The mailbox contract ID
    ///
    /// ### Reverts
    ///
    /// * If the caller is not the owner
    /// * If the mailbox address is zero
    #[storage(write)]
    fn set_mailbox(mailbox_address: ContractId) {
        only_owner();
        require(!mailbox_address.is_zero(), WarpRouteError::InvalidAddress);
        storage.mailbox.write(mailbox_address);
    }

    /// Sets the post dispatch hook contract ID that the WarpRoute contract is using
    ///
    /// ### Arguments
    ///
    /// * `hook`: [ContractId] - The post dispatch hook contract ID
    ///
    /// ### Reverts
    ///
    /// * If the caller is not the owner
    /// * If the hook address is zero
    #[storage(write)]
    fn set_hook(hook: ContractId) {
        only_owner();
        require(!hook.is_zero(), WarpRouteError::InvalidAddress);
        storage.default_hook.write(hook);
    }

    /// Sets the default ISM
    ///
    /// ### Arguments
    ///
    /// * `module`: [ContractId] - The ISM contract ID
    #[storage(read, write)]
    fn set_ism(module: ContractId) {
        storage.default_ism.write(module)
    }

    /// Gets the quote for gas payment
    ///
    /// ### Arguments
    ///
    /// * `destination_domain`: [u32] - The destination domain
    #[storage(read)]
    fn quote_gas_payment(destination_domain: u32) -> u64 {
        _get_quote_for_gas_payment(
            destination_domain,
            b256::zero(),
            Bytes::new(),
            storage
                .default_hook
                .read(),
        )
    }
}

impl TokenRouter for Contract {
    /// Gets the router address for a specific domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to query
    ///
    /// ### Returns
    ///
    /// * [b256] - The router address (zero address if not set)
    #[storage(read)]
    fn router(domain: u32) -> b256 {
        _get_router(domain)
    }

    /// Gets all routers enrolled in the contract
    ///
    /// ### Returns
    ///
    /// * [Vec<b256>] - The routers enrolled in the contract
    #[storage(read)]
    fn all_routers() -> Vec<b256> {
        let count = storage.domains.len();
        let mut i = 0;
        let mut routers = Vec::new();
        while i < count {
            let domain = storage.domains.get(i).unwrap().read();
            let router = storage.routers.get(domain).try_read().unwrap();
            routers.push(router);
            i += 1;
        }
        routers
    }

    /// Gets all domains enrolled in the contract
    ///
    /// ### Returns
    ///
    /// * [Vec<u32>] - The domains enrolled in the contract
    #[storage(read)]
    fn all_domains() -> Vec<u32> {
        storage.domains.load_vec()
    }

    /// Removes a router for a specific domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to remove the router for
    #[storage(write)]
    fn unenroll_remote_router(domain: u32) -> bool {
        let removed = storage.routers.remove(domain);
        if removed {
            let count = storage.domains.len();
            let mut i = 0;
            while i < count {
                if let Some(domain_key) = storage.domains.get(i) {
                    if domain_key.read() == domain {
                        let _ = storage.domains.remove(i);
                        return true;
                    }
                }
                i += 1;
            }
        }
        false
    }

    /// Enrolls a new router for a specific domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to enroll
    /// * `router`: [b256] - The router address to enroll
    #[storage(read, write)]
    fn enroll_remote_router(domain: u32, router: b256) {
        _insert_route_to_state(domain, router);
    }

    /// Batch enrolls multiple routers for multiple domains
    ///
    /// ### Arguments
    ///
    /// * `domains`: [Vec<u32>] - The domains to enroll
    /// * `routers`: [Vec<b256>] - The router addresses to enroll
    ///
    /// ### Reverts
    ///
    /// * If the lengths of domains and routers arrays don't match
    #[storage(read, write)]
    fn enroll_remote_routers(domains: Vec<u32>, routers: Vec<b256>) {
        require(
            domains
                .len() == routers
                .len(),
            TokenRouterError::RouterLengthMismatch,
        );

        let mut domains = domains;
        let mut routers = routers;

        while true {
            let domain = domains.pop();
            let router = routers.pop();
            if domain.is_some() && router.is_some() {
                _insert_route_to_state(domain.unwrap(), router.unwrap());
            } else {
                break;
            }
        }
    }

    /// Gets the decimals for a specific remote router
    ///
    /// ### Arguments
    ///
    /// * `router`: [b256] - The router to query
    #[storage(read)]
    fn remote_router_decimals(router: b256) -> u8 {
        _get_remote_router_decimals(router)
    }

    /// Sets the decimals for a specific remote router
    ///
    /// ### Arguments
    ///
    /// * `router`: [b256] - The router to set
    /// * `decimals`: [u8] - The decimals to set
    #[storage(write)]
    fn set_remote_router_decimals(router: b256, decimals: u8) {
        storage.remote_router_decimals.insert(router, decimals);
    }
}

impl MessageRecipient for Contract {
    /// Handles a transfer from a remote domain
    ///
    /// ### Arguments
    ///
    /// * `origin`: [u32] - The domain of the origin
    /// * `sender`: [b256] - The address of the sender
    /// * `message_body`: [bytes] - The message body
    ///
    /// ### Reverts
    ///
    /// * If the contract is paused
    /// * If the message has already been delivered
    /// * If the sender is not the mailbox
    /// * If the cumulative supply exceeds the maximum supply
    #[storage(read, write)]
    fn handle(origin: u32, sender: b256, message_body: Bytes) {
        reentrancy_guard();
        require_not_paused();

        require(
            msg_sender()
                .unwrap() == Identity::ContractId(storage.mailbox.read()),
            WarpRouteError::SenderNotMailbox,
        );

        let asset = storage.asset_id.read();
        let (recipient, amount) = _extract_asset_data_from_body(message_body);
        let recipient_identity = Identity::Address(Address::from(recipient));

        let remote_decimals = _get_remote_router_decimals(sender);
        require(remote_decimals != 0, WarpRouteError::RemoteDecimalsNotSet);

        let local_decimals = _decimals(storage.decimals, asset).unwrap_or(0);
        let adjusted_amount = _adjust_decimals(amount, remote_decimals, local_decimals);
        let asset = storage.asset_id.read();

        match storage.token_mode.read() {
            WarpRouteTokenMode::SYNTHETIC => {
                let cumulative_supply = storage.cumulative_supply.get(asset).read();

                require(
                    cumulative_supply + adjusted_amount <= MAX_SUPPLY,
                    WarpRouteError::MaxMinted,
                );
                storage
                    .cumulative_supply
                    .insert(asset, cumulative_supply + adjusted_amount);
                let _ = _mint(
                    storage
                        .total_assets,
                    storage
                        .total_supply,
                    recipient_identity,
                    storage
                        .sub_id
                        .read(),
                    adjusted_amount,
                );
            }
            WarpRouteTokenMode::NATIVE | WarpRouteTokenMode::COLLATERAL => {
                transfer(recipient_identity, asset, adjusted_amount);
            }
        }

        log(ReceivedTransferRemoteEvent {
            origin,
            recipient,
            amount: adjusted_amount,
        });
    }

    #[storage(read)]
    fn interchain_security_module() -> ContractId {
        storage.default_ism.read()
    }
}

// ---------------  Pausable, Claimable and Ownable  ---------------

impl Claimable for Contract {
    #[storage(read)]
    fn beneficiary() -> Identity {
        storage.beneficiary.read()
    }

    #[storage(read, write)]
    fn set_beneficiary(beneficiary: Identity) {
        only_owner();
        storage.beneficiary.write(beneficiary);
        log(BeneficiarySetEvent {
            beneficiary: beneficiary.bits(),
        });
    }

    #[storage(read)]
    fn claim(asset: Option<AssetId>) {
        let beneficiary = storage.beneficiary.read();
        let asset = asset.unwrap_or(storage.asset_id.read());
        let balance = this_balance(asset);

        transfer(beneficiary, asset, balance);

        log(ClaimEvent {
            beneficiary: beneficiary.bits(),
            amount: balance,
        });
    }
}

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

// ------------------------------------------------------------
// ------------------ Internal Functions ----------------------
// ------------------------------------------------------------

#[storage(read)]
fn _get_metadata_of_asset(asset: AssetId) -> TokenMetadata {
    TokenMetadata {
        name: _name(storage.name, asset).unwrap_or(String::new()),
        symbol: _symbol(storage.symbol, asset).unwrap_or(String::new()),
        decimals: _decimals(storage.decimals, asset).unwrap_or(0),
        total_supply: storage.total_supply.get(asset).try_read().unwrap_or(0),
        asset_id: storage.asset_id.read(),
        sub_id: storage.sub_id.read(),
    }
}

fn _build_token_metadata_bytes(recipient: b256, amount: u64) -> Bytes {
    let mut buffer = Buffer::new();

    buffer = recipient.abi_encode(buffer);
    let amount_u256 = u256::from(amount); // Convert `u64` to `U256` for 32-byte padding
    buffer = amount_u256.abi_encode(buffer);
    let bytes = Bytes::from(buffer.as_raw_slice());
    bytes
}

fn _extract_asset_data_from_body(body: Bytes) -> (b256, u64) {
    let mut buffer_reader = BufferReader::from_parts(body.ptr(), body.len());

    let recipient = buffer_reader.read::<b256>();
    let amount_u256 = buffer_reader.read::<u256>();

    let amount = <u64 as TryFrom<u256>>::try_from(amount_u256).expect("Amount exceeds u64 range");
    (recipient, amount)
}

#[storage(read)]
fn _get_router(domain: u32) -> b256 {
    storage.routers.get(domain).try_read().unwrap_or(b256::zero())
}

#[storage(read, write)]
fn _insert_route_to_state(domain: u32, router: b256) {
    storage.routers.insert(domain, router);
    storage.domains.push(domain);
}

#[storage(read)]
fn _get_remote_router_decimals(router: b256) -> u8 {
    storage.remote_router_decimals.get(router).try_read().unwrap_or(0)
}

fn _adjust_decimals(amount: u64, from_decimals: u8, to_decimals: u8) -> u64 {
    if from_decimals == to_decimals {
        return amount;
    }

    let difference = if from_decimals > to_decimals {
        from_decimals - to_decimals
    } else {
        to_decimals - from_decimals
    };

    let factor = 10u64.pow(difference.as_u32());

    if from_decimals > to_decimals {
        require(amount >= factor, WarpRouteError::AmountNotConvertible);
        amount / factor
    } else {
        amount * factor
    }
}

#[storage(read)]
fn _get_quote_for_gas_payment(
    destination_domain: u32,
    recipient: b256,
    message_body: Bytes,
    hook: ContractId,
) -> u64 {
    let mailbox = abi(Mailbox, b256::from(storage.mailbox.read()));
    mailbox.quote_dispatch(
        destination_domain,
        recipient,
        message_body,
        Bytes::new(),
        hook,
    )
}

#[storage(read, write)]
fn save_token_details_to_state(
    asset_id: AssetId,
    name: String,
    symbol: String,
    decimals: u8,
    total_supply: u64,
) {
    storage.asset_id.write(asset_id);
    _set_name(storage.name, asset_id, name);
    _set_symbol(storage.symbol, asset_id, symbol);
    _set_decimals(storage.decimals, asset_id, decimals);
    storage.total_supply.insert(asset_id, total_supply);
}
