library;

use std::u128::U128;

/// Default to the same number of decimals as the local base asset.
const DEFAULT_TOKEN_DECIMALS: u8 = 9u8;

abi IGP {
    #[storage(read)]
    fn quote_gas_payment(destination_domain: u32, gas_amount: u64) -> u64;

    #[storage(read)]
    #[payable]
    fn pay_for_gas(
        message_id: b256,
        destination_domain: u32,
        gas_amount: u64,
        refund_address: Identity,
    );

    #[storage(read)]
    fn gas_oracle(domain: u32) -> Option<b256>;

    #[storage(read, write)]
    fn set_gas_oracle(domain: u32, gas_oracle: b256);

    #[storage(read)]
    fn gas_overhead(domain: u32) -> Option<u64>;

    #[storage(read, write)]
    fn set_gas_overhead(domain: u32, gas_overhead: u64);
}

// Allows the beneficiary to claim the contract's balance.
abi Claimable {
    #[storage(read)]
    fn beneficiary() -> Identity;
    #[storage(read, write)]
    fn set_beneficiary(beneficiary: Identity);
    #[storage(read)]
    fn claim();
}

/// Functions specific to on chain fee quoting.
abi OracleContractWrapper {
    #[storage(read, write)]
    fn set_gas_from_oracle(domain: u32, oracle: b256);

    #[storage(read)]
    fn get_gas_oracle(domain: u32) -> Option<b256>;
}

/// Gas data for a remote domain.
/// TODO: consider packing data to reduce storage costs.
pub struct RemoteGasData {
    pub token_exchange_rate: U128,
    pub gas_price: U128,
    pub token_decimals: u8,
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
    #[storage(read)]
    fn get_remote_gas_data(domain: u32) -> RemoteGasData;
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

// EVENTS

// Logged when the benficiary is set.
pub struct BeneficiarySetEvent {
    pub beneficiary: Identity,
}

// Logged when the balance is claimed and sent to the beneficiary.
pub struct ClaimEvent {
    pub beneficiary: Identity,
    pub amount: u64,
}

// Logged when the gas oracle is set for a domain.
pub struct GasOracleSetEvent {
    pub domain: u32,
    pub gas_oracle: b256,
}

/// Logged when a gas payment is made.
pub struct GasPaymentEvent {
    pub message_id: b256,
    pub gas_amount: u64,
    pub payment: u64,
}

/// ERROR FOR HOOK
pub enum IGPHookError {
    ContractNotInitialized: (),
    ContractAlreadyInitialized: (),
    NoValueExpected: (),
}
