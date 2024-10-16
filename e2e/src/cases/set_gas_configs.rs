use crate::{
    cases::TestCase,
    setup::{
        abis::{GasOracle, IGPHook, InterchainGasPaymaster, RemoteGasData, RemoteGasDataConfig},
        get_loaded_wallet,
    },
    utils::local_contracts::{get_contract_address_from_yaml, get_value_from_agent_config_json},
};
use fuels::types::{Address, Bits256};
use tokio::time::Instant;

async fn set_gas_configs() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;

    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let gas_oracle_id = get_contract_address_from_yaml("interchainGasPaymasterOracle");
    let igp_hook_id = get_contract_address_from_yaml("interchainGasPaymasterHook");

    let igp = InterchainGasPaymaster::new(igp_id, wallet.clone());
    let _igp_hook = IGPHook::new(igp_hook_id, wallet.clone());
    let gas_oracle = GasOracle::new(gas_oracle_id, wallet.clone());

    let owner = Bits256(Address::from(wallet.address()).into());
    let base_asset_decimals = get_value_from_agent_config_json("fueltest1", "nativeToken.decimals")
        .and_then(|v| v.as_u64())
        .map(|v| v as u8)
        .unwrap_or(18);

    let default_gas = get_value_from_agent_config_json("fueltest1", "defaultGas")
        .and_then(|v| v.as_u64())
        .unwrap_or(500);

    let _ = igp
        .methods()
        .initialize(owner, owner, 1, base_asset_decimals, default_gas)
        .call()
        .await
        .map_err(|e| format!("Failed to initialize IGP: {:?}", e));

    let remote_domain = get_value_from_agent_config_json("test1", "domainId")
        .unwrap()
        .as_u64()
        .map(|v| v as u32)
        .unwrap_or(9913371);

    let default_remote_gas = get_value_from_agent_config_json("test1", "defaultGas")
        .and_then(|v| v.as_u64())
        .unwrap_or(500);

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
        domain: remote_domain as u32,
        remote_gas_data: RemoteGasData {
            token_exchange_rate: 1_u128,
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
        .set_gas_oracle(remote_domain as u32, Bits256(gas_oracle_id.into()))
        .call()
        .await
        .map_err(|e| format!("Failed to set gas oracle to igp: {:?}", e))?;

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("set_gas_configs", set_gas_configs)
}
