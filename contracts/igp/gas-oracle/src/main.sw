contract;

use sway_libs::ownership::*;
use standards::src5::State;

use interfaces::{igp::*, ownable::Ownable, post_dispatch_hook::*,};
use std::hash::*;

storage {
    remote_gas_data: StorageMap<u32, RemoteGasData> = StorageMap {},
}
impl GasOracle for Contract {
    /// Gets the gas data from storage.
    #[storage(read)]
    fn get_remote_gas_data(domain: u32) -> RemoteGasData {
        storage.remote_gas_data.get(domain).try_read().unwrap_or(RemoteGasData::default())
    }
}
impl StorageGasOracle for Contract {
    /// Sets the gas data for a given domain. Only callable by the owner.
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
