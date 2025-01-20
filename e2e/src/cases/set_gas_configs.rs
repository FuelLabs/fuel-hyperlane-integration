use crate::{
    cases::TestCase,
    setup::{
        abis::{GasOracle, InterchainGasPaymaster, RemoteGasData, RemoteGasDataConfig},
        get_loaded_wallet,
    },
    utils::{
        get_remote_domain,
        local_contracts::{get_contract_address_from_yaml, get_value_from_agent_config_json},
    },
};
use fuels::types::{Address, Bits256};
use tokio::time::Instant;

async fn set_gas_configs() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;

    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let gas_oracle_id = get_contract_address_from_yaml("gasOracle");

    let igp = InterchainGasPaymaster::new(igp_id, wallet.clone());
    let gas_oracle = GasOracle::new(gas_oracle_id, wallet.clone());

    let owner = Bits256(Address::from(wallet.address()).into());

    let _ = igp
        .methods()
        .initialize(owner, owner)
        .call()
        .await
        .map_err(|e| format!("Failed to initialize IGP: {:?}", e));

    let remote_domain = get_remote_domain();

    let default_remote_gas = get_value_from_agent_config_json("test1", "defaultGas")
        .and_then(|v| v.as_u64())
        .unwrap_or(37999464941);

    let remote_decimals = get_value_from_agent_config_json("test1", "nativeToken.decimals")
        .and_then(|v| v.as_u64())
        .map(|v| v as u8)
        .unwrap_or(18);

    //No error mapping since it can be executed only once
    let _ = gas_oracle
        .methods()
        .initialize_ownership(wallet.address().into())
        .call()
        .await;

    let configs = vec![RemoteGasDataConfig {
        domain: remote_domain,
        remote_gas_data: RemoteGasData {
            domain: remote_domain,
            token_exchange_rate: 15000000000,
            gas_price: default_remote_gas.into(),
            token_decimals: remote_decimals,
        },
    }];

    gas_oracle
        .methods()
        .set_remote_gas_data_configs(configs)
        .call()
        .await
        .map_err(|e| format!("Failed to set remote gas data configs: {:?}", e))?;

    igp.methods()
        .set_gas_oracle(remote_domain, Bits256(gas_oracle_id.into()))
        .call()
        .await
        .map_err(|e| format!("Failed to set gas oracle to igp: {:?}", e))?;

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("set_gas_configs", set_gas_configs)
}
