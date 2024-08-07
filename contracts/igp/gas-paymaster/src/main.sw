contract;

use sway_libs::ownership::*;
use standards::src5::State;

use interfaces::{igp::*, ownable::Ownable, post_dispatch_hook::*,};

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
enum IgpError {
    InsufficientGasPayment: (),
    InvalidGasOracle: (),
    QuoteGasPaymentOverflow: (),
    InterchainGasPaymentInBaseAsset: (),
}
/// The scale of a token exchange rate. 1e19.
const TOKEN_EXCHANGE_RATE_SCALE: u64 = 10_000_000_000_000_000_000;

const BASE_ASSET_DECIMALS: u8 = 9;

storage {
    // TODO: set this at compile / deploy time.
    // NOTE for now this is temporarily set to the address of a PUBLICLY KNOWN
    // PRIVATE KEY, which is the first default account when running fuel-client locally.
    beneficiary: Identity = Identity::Address(Address::from(0x6b63804cfbf9856e68e5b6e7aef238dc8311ec55bec04df774003a2c96e0418e)),
    gas_oracles: StorageMap<u32, b256> = StorageMap {},
    /// The intended use is for applications to not need to worry about ISM gas costs themselves.
    gas_overheads: StorageMap<u32, u64> = StorageMap {},
}

impl IGP for Contract {
    /// Quotes the required interchain gas payment to be paid in the base asset.
    /// ### Arguments
    ///
    /// * `destination_domain` - The destination domain of the message.
    /// * `gas_amount` - The amount of destination gas to pay for.
    #[storage(read)]
    fn quote_gas_payment(destination_domain: u32, gas_amount: u64) -> u64 {
        quote_gas(destination_domain, gas_amount)
    }

    #[storage(read)]
    #[payable]
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
            gas_amount,
            payment: required_payment,
        });
    }
    #[storage(read)]
    fn gas_oracle(domain: u32) -> Option<b256> {
        storage.gas_oracles.get(domain).try_read()
    }
    #[storage(read, write)]
    fn set_gas_oracle(domain: u32, gas_oracle: b256) {
        only_owner();
        storage.gas_oracles.insert(domain, gas_oracle);
        log(GasOracleSetEvent {
            domain,
            gas_oracle,
        });
    }
    #[storage(read)]
    fn gas_overhead(domain: u32) -> Option<u64> {
        storage.gas_overheads.get(domain).try_read()
    }
    #[storage(read, write)]
    fn set_gas_overhead(domain: u32, gas_overhead: u64) {
        only_owner();
        storage.gas_overheads.insert(domain, gas_overhead);
    }
}

impl Claimable for Contract {
    /// Gets the current beneficiary.
    #[storage(read)]
    fn beneficiary() -> Identity {
        storage.beneficiary.read()
    }
    // Sets the beneficiary to `beneficiary`. Only callable by the owner.
    #[storage(read, write)]
    fn set_beneficiary(beneficiary: Identity) {
        only_owner();
        storage.beneficiary.write(beneficiary);
        log(BeneficiarySetEvent { beneficiary });
    }
    // Sends all base asset funds to the beneficiary. Callable by anyone.
    #[storage(read)]
    fn claim() {
        let BASE_ASSET_ID = AssetId::base();

        let beneficiary = storage.beneficiary.read();
        let balance = this_balance(BASE_ASSET_ID);

        transfer(beneficiary, BASE_ASSET_ID, balance);

        log(ClaimEvent {
            beneficiary,
            amount: balance,
        });
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

impl OracleContractWrapper for Contract {
    /// Sets the gas oracle for a given domain.
    #[storage(read, write)]
    fn set_gas_from_oracle(domain: u32, gas_oracle: b256) {
        only_owner();

        storage.gas_oracles.insert(domain, gas_oracle);
        log(GasOracleSetEvent {
            domain,
            gas_oracle,
        });
    }

    /// Gets the gas oracle for a given domain.
    #[storage(read)]
    fn get_gas_oracle(domain: u32) -> Option<b256> {
        storage.gas_oracles.get(domain).try_read()
    }
}

/// Converts a `u256` to `u64`, returning `None` if the value overflows `u64`.
fn u256_to_u64(value: u256) -> Option<u64> {
    <u64 as TryFrom<u256>>::try_from(value)
}

/// Gets the exchange rate and gas price for a given domain using the
/// configured gas oracle.
/// Reverts if no gas oracle is set.
#[storage(read)]
pub fn get_remote_gas_data(destination_domain: u32) -> RemoteGasData {
    let gas_oracle_id = storage.gas_oracles.get(destination_domain).read();

    let gas_oracle = abi(GasOracle, gas_oracle_id);
    gas_oracle.get_remote_gas_data(destination_domain)
}

/// Quotes the required interchain gas payment to be paid in the base asset.
/// Reverts if no gas oracle is set.
#[storage(read)]
fn quote_gas(destination_domain: u32, gas_amount: u64) -> u64 {
    // Get the gas data for the destination domain.
    let RemoteGasData {
        token_exchange_rate,
        gas_price,
        token_decimals,
    } = get_remote_gas_data(destination_domain);

    // All arithmetic is done using u256 to avoid overflows.

    // The total cost quoted in destination chain's native token.
    let destination_gas_cost = u256::from(gas_amount) * u256::from(gas_price);

    // Convert to the local native token.
    let origin_cost = (destination_gas_cost * u256::from(token_exchange_rate)) / u256::from(TOKEN_EXCHANGE_RATE_SCALE);

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
        let divisor = 10u64.pow(diff_u32).as_u256();

        require(divisor != 0, "Divisor cannot be zero");
        num / divisor
    } else {
        let diff: u64 = (to_decimals - from_decimals).as_u64();
        let diff_u32 = diff.try_as_u32().expect("Conversion to u32 failed");
        let multiplier = 10u64.pow(diff_u32).as_u256();

        require(multiplier != 0, "Multiplier cannot be zero");
        num * multiplier
    }
}
