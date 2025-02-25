contract;

use sway_libs::ownership::*;
use standards::src5::State;

use interfaces::{hooks::{igp::*, gas_oracle::*, post_dispatch_hook::*}, ownable::Ownable };
use message::{EncodedMessage, Message};
use std_hook_metadata::*;

use std::{
    asset::transfer,
    bytes::Bytes,
    call_frames::msg_asset_id,
    constants::ZERO_B256,
    context::{
        msg_amount,
        this_balance,
    },
    contract_id::ContractId,
    convert::Into,
    hash::*,
    revert::revert,
    storage::storage_map::*,
    u128::U128,
};

configurable {
    BASE_ASSET_DECIMALS: u8 = 9,
    TOKEN_EXCHANGE_RATE_SCALE: u64 = 10_000_000_000_000_000_000,
    DEFAULT_GAS_AMOUNT: u64 = 500,
}

storage {
    /// The address of the beneficiary who can claim the collected gas payments
    beneficiary: Identity = Identity::ContractId(ContractId::zero()),
    /// The mapping of domain identifiers to their corresponding gas oracle addresses
    gas_oracles: StorageMap<u32, b256> = StorageMap {},
    /// The intended use is for applications to not need to worry about ISM gas costs themselves.
    gas_overheads: StorageMap<u32, u64> = StorageMap {},
}

impl IGP for Contract {
    /// Initializes the contract.
    ///
    /// ### Arguments
    ///
    /// * `owner`: [Identity] - The owner of the contract.
    /// * `beneficiary`: [Identity] - The beneficiary of the contract.
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized.
    #[storage(write)]
    fn initialize(owner: Identity, beneficiary: Identity) {
        initialize_ownership(owner);
        storage.beneficiary.write(beneficiary);
    }

    /// Quotes the required interchain gas payment to be paid in the base asset.
    ///
    /// ### Arguments
    ///
    /// * `destination_domain`: [u32] - The destination domain of the message.
    /// * `gas_amount`: [u64] - The amount of destination gas to pay for.
    ///
    /// ### Returns
    ///
    /// * [u64] - The total payment for the gas amount.
    #[storage(read)]
    fn quote_gas_payment(destination_domain: u32, gas_amount: u64) -> u64 {
        quote_gas(destination_domain, gas_amount)
    }

    /// Allows the caller to pay for gas.
    ///
    /// ### Arguments
    ///
    /// * `message_id`: [b256] - The message ID.
    /// * `destination_domain`: [u32] - The domain to pay for.
    /// * `gas_amount`: [u64] - The amount of gas.
    /// * `refund_address`: [Identity] - The address to refund the excess payment to.
    ///
    /// ### Reverts
    ///
    /// * If asset sent is not the base asset.
    /// * If the payment is less than the required amount.
    /// * If the metadata is invalid.
    #[payable]
    #[storage(read)]
    fn pay_for_gas(
        message_id: b256,
        destination_domain: u32,
        gas_amount: u64,
        refund_address: Identity,
    ) {
        let BASE_ASSET_ID = AssetId::base();
        require(
            msg_asset_id() == BASE_ASSET_ID,
            IgpError::InterchainGasPaymentInBaseAsset,
        );

        let required_payment = quote_gas(destination_domain, gas_amount);
        let payment_amount = msg_amount();

        require(
            payment_amount >= required_payment,
            IgpError::InsufficientGasPayment,
        );

        // Refund any overpaymen to caller
        let overpayment = payment_amount - required_payment;
        if (overpayment > 0) {
            transfer(refund_address, BASE_ASSET_ID, overpayment);
        }

        log(GasPaymentEvent {
            message_id,
            destination_domain,
            gas_amount,
            payment: required_payment,
        });
    }

    /// Returns the gas oracle for a domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to get the gas oracle for.
    #[storage(read)]
    fn gas_oracle(domain: u32) -> Option<b256> {
        storage.gas_oracles.get(domain).try_read()
    }

    /// Sets the gas oracle for a domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to set the gas oracle for.
    /// * `gas_oracle`: [b256] - The gas oracle.
    ///
    /// ### Reverts
    ///
    /// * If the caller is not the owner.
    #[storage(read, write)]
    fn set_gas_oracle(domain: u32, gas_oracle: b256) {
        only_owner();
        storage.gas_oracles.insert(domain, gas_oracle);
        log(GasOracleSetEvent {
            domain,
            gas_oracle,
        });
    }

    /// Gets the gas amount for the current domain.
    ///
    /// ### Returns
    ///
    /// * [u64] - The gas amount for the current domain.
    fn get_current_domain_gas() -> u64 {
        DEFAULT_GAS_AMOUNT
    }

    /// Gets the gas config for a domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to get the gas config for.
    ///
    /// ### Returns
    ///
    /// * [DomainGasConfig] - The gas config for the domain (gas overhead and oracle address).
    #[storage(read)]
    fn get_domain_gas_config(domain: u32) -> DomainGasConfig {
        DomainGasConfig {
            gas_overhead: storage.gas_overheads.get(domain).try_read().unwrap_or(0),
            gas_oracle: storage.gas_oracles.get(domain).try_read().unwrap_or(b256::zero()),
        }
    }

    /// Sets the gas configs for a destination domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [Vec<u32>] - The domains to set the gas config for.
    /// * `config`: [Vec<DomainGasConfig>] - The gas config to set.
    #[storage(read, write)]
    fn set_destination_gas_config(domain: Vec<u32>, config: Vec<DomainGasConfig>) {
        only_owner();
        require(
            domain
                .len() == config
                .len(),
            IgpError::InvalidDomainConfigLength,
        );

        let mut i = 0;
        while i < domain.len() {
            let current_domain = domain.get(i).unwrap();
            let current_config = config.get(i).unwrap();

            storage
                .gas_overheads
                .insert(current_domain, current_config.gas_overhead);
            storage
                .gas_oracles
                .insert(current_domain, current_config.gas_oracle);

            log(DestinationGasConfigSetEvent {
                domain: current_domain,
                oracle: current_config.gas_oracle,
                overhead: current_config.gas_overhead,
            });

            i += 1;
        }
    }

    /// Gets the exchange rate and gas price for a given domain using the
    /// configured gas oracle.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to get the gas data for.
    ///
    /// ### Returns
    ///
    /// * [RemoteGasData] - Remote gas data for the domain from the oracle.
    ///
    /// ### Reverts
    ///
    /// * If no gas oracle is set.
    #[storage(read)]
    fn get_remote_gas_data(destination_domain: u32) -> RemoteGasData {
        _get_remote_oracle_gas_data(destination_domain)
    }

    /// Gets the current beneficiary.
    ///
    /// ### Returns
    ///
    /// * [Identity] - The beneficiary.
    #[storage(read)]
    fn beneficiary() -> Identity {
        storage.beneficiary.read()
    }

    /// Sets the beneficiary to `beneficiary`. Only callable by the owner.
    ///
    /// ### Arguments
    ///
    /// * `beneficiary`: [Identity] - The new beneficiary.
    ///
    /// ### Reverts
    ///
    /// * If the caller is not the owner.
    #[storage(read, write)]
    fn set_beneficiary(beneficiary: Identity) {
        only_owner();
        storage.beneficiary.write(beneficiary);
        log(BeneficiarySetEvent {
            beneficiary: beneficiary,
        });
    }

    /// Sends all base asset funds to the beneficiary. Callable by anyone.
    #[storage(read)]
    fn claim(asset: Option<AssetId>) {
        let beneficiary = storage.beneficiary.read();
        let balance = this_balance(asset.unwrap_or(AssetId::base()));

        transfer(beneficiary, asset.unwrap_or(AssetId::base()), balance);

        log(ClaimEvent {
            beneficiary,
            amount: balance,
        });
    }
}

// --------------------------------------------
// --------- Ownable Implementation -----------
// --------------------------------------------

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

impl IGPWithOverhead for Contract {
    /// Gets the gas overhead for a given domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to get the gas overhead for.
    ///
    /// ### Returns
    ///
    /// * [u64] - The gas overhead.
    #[storage(read)]
    fn gas_overhead(domain: u32) -> Option<u64> {
        storage.gas_overheads.get(domain).try_read()
    }

    /// Sets the gas overhead for a given domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to set the gas overhead for.
    /// * `gas_overhead`: [u64] - The gas overhead.
    ///
    /// ### Reverts
    ///
    /// * If the caller is not the owner.
    #[storage(read, write)]
    fn set_gas_overhead(domain: u32, gas_overhead: u64) {
        only_owner();
        storage.gas_overheads.insert(domain, gas_overhead);
    }
}

impl PostDispatchHook for Contract {
    /// Returns an enum that represents the type of hook
    ///
    /// ### Returns
    ///
    /// * [PostDispatchHookType] - The type of the hook.
    fn hook_type() -> PostDispatchHookType {
        PostDispatchHookType::INTERCHAIN_GAS_PAYMASTER
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
    fn supports_metadata(metadata: Bytes) -> bool {
        StandardHookMetadata::is_valid(metadata)
    }

    /// Manages payments on a source chain to cover gas costs of relaying
    /// messages to destination chains and includes the gas overhead per destination
    ///
    /// The intended use of this contract is to store overhead gas amounts for destination
    /// domains, e.g. Mailbox and ISM gas usage, such that users of this IGP are only required
    /// to specify the gas amount used by their own applications.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata required for the hook.
    /// * `message`: [Bytes] - The message being dispatched.
    ///
    /// ### Reverts
    ///
    /// * If the contract is not initialized.
    /// * If the message is invalid
    /// * If IGP call fails
    /// * If metadata is invalid
    #[payable]
    #[storage(read, write)]
    fn post_dispatch(metadata: Bytes, message: Bytes) {
        let metadata_valid = StandardHookMetadata::is_valid(metadata);
        require(metadata_valid, IgpError::UnsupportedMetadataFormat);

        let message = EncodedMessage::from_bytes(message);

        let message_id = message.id();
        let destination_domain = message.destination();
        let sender = message.sender();

        let gas_limit = u256_to_u64(StandardHookMetadata::get_gas_limit(metadata, DEFAULT_GAS_AMOUNT.as_u256())).unwrap();

        let refund_address = StandardHookMetadata::get_refund_address(metadata, sender);
        let refund_identity = Identity::Address(Address::from(refund_address));

        let igp_contract = abi(IGP, ContractId::this().bits());

        igp_contract
            .pay_for_gas {
                asset_id: b256::from(AssetId::base()),
                coins: msg_amount(),
            }(message_id, destination_domain, gas_limit, refund_identity);
    }

    /// Compute the payment required by the postDispatch call
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata required for the hook.
    /// * `message`: [Bytes] - The message being dispatched.
    ///
    /// ### Returns
    ///
    /// * [u64] - The payment required for the postDispatch call.
    ///
    /// ### Reverts
    ///
    /// * If the contract is not initialized.
    /// * If the message is invalid
    /// * If IGP call fails
    /// * If metadata is invalid
    #[storage(read)]
    fn quote_dispatch(metadata: Bytes, message: Bytes) -> u64 {
        let metadata_valid = StandardHookMetadata::is_valid(metadata);
        require(metadata_valid, IgpError::UnsupportedMetadataFormat);

        let message = EncodedMessage::from_bytes(message);
        let domain = message.destination();
        let gas_limit = u256_to_u64(StandardHookMetadata::get_gas_limit(metadata, DEFAULT_GAS_AMOUNT.as_u256())).unwrap();

        quote_gas(domain, gas_limit)
    }
}

// --------------------------------------------
// --------- Internal Functions ---------------
// --------------------------------------------

/// Converts a `u256` to `u64`, returning `None` if the value overflows `u64`.
fn u256_to_u64(value: u256) -> Option<u64> {
    <u64 as TryFrom<u256>>::try_from(value)
}

#[storage(read)]
fn _get_remote_oracle_gas_data(destination_domain: u32) -> RemoteGasData {
    let gas_oracle_id = storage.gas_oracles.get(destination_domain).read();
    let gas_oracle = abi(GasOracle, gas_oracle_id);
    gas_oracle.get_remote_gas_data(destination_domain)
}

/// Quotes the required interchain gas payment to be paid in the base asset.
/// Reverts if no gas oracle is set.
#[storage(read)]
fn quote_gas(destination_domain: u32, gas_amount: u64) -> u64 {
    let overhead = storage.gas_overheads.get(destination_domain).try_read().unwrap_or(0);
    let total_gas_amount = gas_amount + overhead;

    // Get the gas data for the destination domain.
    let RemoteGasData {
        domain: _,
        token_exchange_rate,
        gas_price,
        token_decimals,
    } = _get_remote_oracle_gas_data(destination_domain);

    // All arithmetic is done using u256 to avoid overflows.
    // The total cost quoted in destination chain's native token.
    let destination_gas_cost = u256::from(total_gas_amount) * u256::from(gas_price);

    // Convert to the local native token.
    let numerator = destination_gas_cost * u256::from(token_exchange_rate);
    let origin_cost = (numerator + u256::from(TOKEN_EXCHANGE_RATE_SCALE) - 1) 
                      / u256::from(TOKEN_EXCHANGE_RATE_SCALE);

    // Convert from the remote token's decimals to the local token's decimals.
    let origin_cost = convert_decimals(origin_cost, token_decimals, BASE_ASSET_DECIMALS);

    u256_to_u64(origin_cost).expect("quote_gas_payment overflow")
}

/// Converts `num` from `from_decimals` to `to_decimals`.
fn convert_decimals(num: u256, from_decimals: u8, to_decimals: u8) -> u256 {
    if from_decimals == to_decimals {
        return num;
    }

    if from_decimals > to_decimals {
        let diff: u64 = (from_decimals - to_decimals).as_u64();
        let diff_u32 = diff.try_as_u32().expect("Conversion to u32 failed");
        let divisor = u256::from(10u64).pow(diff_u32);

        require(divisor != 0, "Divisor cannot be zero");
        (num + divisor - 1) / divisor
    } else {
        let diff: u64 = (to_decimals - from_decimals).as_u64();
        let diff_u32 = diff.try_as_u32().expect("Conversion to u32 failed");
        let multiplier = u256::from(10u64).pow(diff_u32);

        require(multiplier != 0, "Multiplier cannot be zero");
        num * multiplier
    }
}

#[test()]
fn test_convert_decimals() {
    let num = u256::from((0, 0, 0, 1000000));
    let from_decimals = 9;
    let to_decimals = 9;
    let result = convert_decimals(num, from_decimals, to_decimals);
    assert(result == num);

    let num = u256::from((0, 0, 0, 1000000000000000));
    let from_decimals = 18;
    let to_decimals = 9;
    let result = convert_decimals(num, from_decimals, to_decimals);
    assert(result == u256::from((0, 0, 0, 1000000)));

    let num = u256::from((0, 0, 0, 1000000));
    let from_decimals = 4;
    let to_decimals = 9;
    let result = convert_decimals(num, from_decimals, to_decimals);
    assert(result == u256::from((0, 0, 0, 100000000000)));

    // Some loss of precision
    let num = u256::from((0, 0, 0, 9999999));
    let from_decimals = 9;
    let to_decimals = 4;
    let result = convert_decimals(num, from_decimals, to_decimals);
    assert(result == u256::from((0, 0, 0, 99)));

    // Total loss of precision
    let num = u256::from((0, 0, 0, 999));
    let from_decimals = 9;
    let to_decimals = 4;
    let result = convert_decimals(num, from_decimals, to_decimals);
    assert(result == u256::from((0, 0, 0, 0)));

    // Edge decimal cases
    let num = u256::from(18u64);
    let from_decimals = 6;
    let to_decimals = 24;
    let result = convert_decimals(num, from_decimals, to_decimals);
    assert(u256_to_u64(result).is_some());

    let num = u256::from(19u64);
    let from_decimals = 6;
    let to_decimals = 24;
    let result = convert_decimals(num, from_decimals, to_decimals);
    assert(u256_to_u64(result).is_none());

    // Expected max `to_decimals`
    let num = u256::from(18_446_744u64);
    let from_decimals = 6;
    let to_decimals = 18;
    let result = convert_decimals(num, from_decimals, to_decimals);
    assert(u256_to_u64(result).is_some());

    let num = u256::from(18_446_745u64);
    let from_decimals = 6;
    let to_decimals = 18;
    let result = convert_decimals(num, from_decimals, to_decimals);
    assert(u256_to_u64(result).is_none());

    // going from very large numbers to low precision is not problematic
    // 18_446_744_073_709_551_615_999_999_999_999_999_999
    let num = u256::from((0u64, 0u64, 0x0DE0B6B3A763FFFFu64, 0xFFFFFFFFFFFFFFFFu64));
    let from_decimals = 24;
    let to_decimals = 6;
    let result = convert_decimals(num, from_decimals, to_decimals);
    assert(u256_to_u64(result).is_some());
}
