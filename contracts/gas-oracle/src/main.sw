contract;

use sway_libs::ownership::*;
use standards::src5::State;
use interfaces::{hooks::gas_oracle::*, ownable::*};
use std::hash::*;

configurable {
    EXPECTED_OWNER: b256 = b256::zero(),
}

storage {
    /// Mapping of the domain to the remote gas data.
    remote_gas_data: StorageMap<u32, RemoteGasData> = StorageMap {},
}

impl GasOracle for Contract {
    /// Gets the gas data from storage.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to get the gas data for.
    ///
    /// ### Returns
    ///
    /// * [RemoteGasData] - The gas data for the remote domain.
    #[storage(read)]
    fn get_remote_gas_data(domain: u32) -> RemoteGasData {
        storage.remote_gas_data.get(domain).try_read().unwrap_or(RemoteGasData::default())
    }

    /// Gets the token exchange rate and gas price for a given domain.
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The domain to get the gas data for.
    ///
    /// ### Returns
    ///
    /// * [ExchangeRateAndGasData] - The exchange rate and gas price for the remote domain.
    #[storage(read)]
    fn get_exchange_rate_and_gas_price(domain: u32) -> ExchangeRateAndGasData {
        let gas_data = storage.remote_gas_data.get(domain).try_read().unwrap_or(RemoteGasData::default());
        ExchangeRateAndGasData {
            token_exchange_rate: gas_data.token_exchange_rate,
            gas_price: gas_data.gas_price,
        }
    }
}

impl StorageGasOracle for Contract {
    /// Sets the gas data for a given domain. Only callable by the owner.
    ///
    /// ### Arguments
    ///
    /// * `configs`: [Vec]<[RemoteGasDataConfig]> - The remote gas data configs to set.
    ///
    /// ### Reverts
    ///
    /// * If the caller is not the owner.
    #[storage(read, write)]
    fn set_remote_gas_data_configs(configs: Vec<RemoteGasDataConfig>) {
        only_owner();
        let count = configs.len();
        let mut i = 0;
        while i < count {
            let config = configs.get(i).unwrap();
            storage
                .remote_gas_data
                .insert(config.domain, config.remote_gas_data);
            i += 1;
        }
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
        _is_expected_owner(new_owner);
        initialize_ownership(new_owner);
    }
    #[storage(read, write)]
    fn renounce_ownership() {
        renounce_ownership();
    }
}


// Front-run guard
fn _is_expected_owner(owner: Identity) {
    let raw_owner: b256 = match owner {
        Identity::Address(address) => address.bits(),
        Identity::ContractId(contract_id) => contract_id.bits(),
    };
    require(raw_owner == EXPECTED_OWNER, OwnableError::UnexpectedOwner);
}
