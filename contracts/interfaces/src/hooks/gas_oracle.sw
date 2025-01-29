library;

use std::u128::U128;

/// Default to the same number of decimals as the local base asset.
const DEFAULT_TOKEN_DECIMALS: u8 = 9u8;

/// Gas data for a remote domain.
pub struct RemoteGasData {
    pub domain: u32,
    pub token_exchange_rate: U128,
    pub gas_price: U128,
    pub token_decimals: u8,
}

impl RemoteGasData {
    pub fn default() -> Self {
        Self {
            domain: 0,
            token_exchange_rate: U128::new(),
            gas_price: U128::new(),
            token_decimals: DEFAULT_TOKEN_DECIMALS,
        }
    }
}

/// Gas data for a remote domain.
pub struct ExchangeRateAndGasData {
    pub token_exchange_rate: U128,
    pub gas_price: U128,
}

/// A config for setting remote gas data.
pub struct RemoteGasDataConfig {
    pub domain: u32,
    pub remote_gas_data: RemoteGasData,
}

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

/// A gas oracle with remote gas data in storage.
abi StorageGasOracle {
    #[storage(read, write)]
    fn set_remote_gas_data_configs(configs: Vec<RemoteGasDataConfig>);
}

