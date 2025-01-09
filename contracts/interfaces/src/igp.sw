library;

use std::u128::U128;

/// Default to the same number of decimals as the local base asset.
const DEFAULT_TOKEN_DECIMALS: u8 = 9u8;

abi IGP {
    /// Initializes the contract with the given parameters.
    ///
    /// ### Arguments
    ///
    /// * `owner`: [b256] - The address of the owner of the contract.
    /// * `beneficiary`: [b256] - The address of the beneficiary to receive gas payments.
    /// * `token_exchange_rate`: [u64] - The exchange rate of the token.
    /// * `base_asset_decimal`: [u8] - The number of decimals for the base asset.
    /// * `default_gas_amount`: [u64] - The default gas amount for the current domain.
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized.
    #[storage(write)]
    fn initialize(
        owner: b256,
        beneficiary: b256,
        token_exchange_rate: u64,
        default_gas_amount: u64,
    );
    /// Qupote payment total payment for a given gas amount.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to get the gas price for.
    /// * `gas_amount`: [u64] - The amount of gas.
    ///
    /// ### Returns
    ///
    /// * [u64] - The total payment for the gas amount.
    #[storage(read)]
    fn quote_gas_payment(destination_domain: u32, gas_amount: u64) -> u64;

    /// Allows the caller to pay for gas.
    ///
    /// ### Arguments
    ///
    /// * `message_id`: [b256] - The message ID.
    /// * `destination_domain`: [u32] - The domain to pay for.
    /// * `gas_amount`: [u64] - The amount of gas.
    /// * `refund_address`: [Identity] - The address to refund the excess payment to.
    #[payable]
    #[storage(read)]
    fn pay_for_gas(
        message_id: b256,
        destination_domain: u32,
        gas_amount: u64,
        refund_address: Identity,
    );

    /// Returns the gas oracle for a domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to get the gas oracle for.
    ///
    /// ### Returns
    ///
    /// * [b256] - The gas oracle.
    #[storage(read)]
    fn gas_oracle(domain: u32) -> Option<b256>;

    /// Sets the gas oracle for a domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to set the gas oracle for.
    /// * `gas_oracle`: [b256] - The gas oracle.
    #[storage(read, write)]
    fn set_gas_oracle(domain: u32, gas_oracle: b256);

    /// Gets the gas amount for the current domain.
    ///
    /// ### Returns
    ///
    /// * [u64] - The gas amount for the current domain.
    #[storage(read)]
    fn get_current_domain_gas() -> u64;

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
    fn get_domain_gas_config(domain: u32) -> DomainGasConfig;
}

/// Functions required for calculation of overheads
/// Can be needed for specific domains in the future
abi IGPWithOverhead {
    #[storage(read)]
    fn gas_overhead(domain: u32) -> Option<u64>;

    #[storage(read, write)]
    fn set_gas_overhead(domain: u32, gas_overhead: u64);
}

/// Gas data for a remote domain.
pub struct RemoteGasData {
    pub token_exchange_rate: U128,
    pub gas_price: U128,
    pub token_decimals: u8,
}

/// Gas data for a remote domain.
pub struct ExchangeRateAndGasData {
    pub token_exchange_rate: U128,
    pub gas_price: U128,
}

/// Gas config for a domain.
pub struct DomainGasConfig {
    pub gas_oracle: b256,
    pub gas_overhead: u64,
}

impl RemoteGasData {
    pub fn default() -> Self {
        Self {
            token_exchange_rate: U128::new(),
            gas_price: U128::new(),
            token_decimals: DEFAULT_TOKEN_DECIMALS,
        }
    }
}

/// An oracle that provides gas data for a remote domain.
abi GasOracle {
    /// Gets the gas data for a remote domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to get the gas data for.
    ///
    /// ### Returns
    ///
    /// * [RemoteGasData] - The gas data for the remote domain.
    #[storage(read)]
    fn get_remote_gas_data(domain: u32) -> RemoteGasData;

    /// Gets the exchange rate and gas price for a remote domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to get the gas data for.
    ///
    /// ### Returns
    ///
    /// * [ExchangeRateAndGasData] - The exchange rate and gas price for the remote domain.
    #[storage(read)]
    fn get_exchange_rate_and_gas_price(domain: u32) -> ExchangeRateAndGasData;
}

///ORACLE STORAGE CONTRACT INTERFACE
/// A config for setting remote gas data.
pub struct RemoteGasDataConfig {
    pub domain: u32,
    pub remote_gas_data: RemoteGasData,
}

/// Logged when a remote gas data config is set.
pub struct RemoteGasDataSetEvent {
    pub config: RemoteGasDataConfig,
}

/// A gas oracle with remote gas data in storage.
abi StorageGasOracle {
    #[storage(read, write)]
    fn set_remote_gas_data_configs(configs: Vec<RemoteGasDataConfig>);
}

//  ----------------- Events -----------------

/// Logged when the gas oracle is set for a domain.
pub struct GasOracleSetEvent {
    pub domain: u32,
    pub gas_oracle: b256,
}

/// Logged when a gas payment is made.
pub struct GasPaymentEvent {
    pub message_id: b256,
    pub destination_domain: u32,
    pub gas_amount: u64,
    pub payment: u64,
}
