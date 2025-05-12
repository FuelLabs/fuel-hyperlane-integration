use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use fuel_core_chain_config::coin_config_helpers::CoinConfigGenerator;
use fuels::{
    crypto::SecretKey,
    test_helpers::{ChainConfig, FuelService, NodeConfig, StateConfig},
};

const DEFAULT_PORT: u16 = 4000;
const FUEL_ACCOUNT_TO_FUND: &str =
    "0xde97d8624a438121b86a1956544bd72ed68cd69f2c99555b08b1e8c51ffd511c";
const FUND_AMOUNT: u64 = 100000000000000;

#[tokio::main]
async fn main() {
    let fuel_node = launch_fuel_node(DEFAULT_PORT).await;

    println!(
        "Fuel node started on port {}, sleeping for 1 hour",
        DEFAULT_PORT
    );

    println!("Bound address {:?}", fuel_node.bound_address());

    tokio::time::sleep(Duration::from_secs(60 * 60)).await;

    fuel_node.stop().await.unwrap();
}

pub async fn launch_fuel_node(port: u16) -> FuelService {
    let node_config = NodeConfig {
        addr: SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port),
        ..Default::default()
    };
    let mut state_config = StateConfig::local_testnet();
    let mut coin_generator = CoinConfigGenerator::new();
    let secret = SecretKey::from_str(FUEL_ACCOUNT_TO_FUND).expect("Expected valid secret");
    state_config.coins.remove(0);

    state_config
        .coins
        .push(coin_generator.generate_with(secret, FUND_AMOUNT));

    FuelService::start(node_config, ChainConfig::local_testnet(), state_config)
        .await
        .unwrap()
}
