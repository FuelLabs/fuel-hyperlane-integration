use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use fuels::test_helpers::{ChainConfig, FuelService, NodeConfig, StateConfig};

const DEFAULT_PORT: u16 = 4000;

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
    FuelService::start(
        node_config,
        ChainConfig::local_testnet(),
        StateConfig::local_testnet(),
    )
    .await
    .unwrap()
}
