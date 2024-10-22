use std::str::FromStr;

use alloy::providers::{Provider as EthProvider, ProviderBuilder};
use alloy::{
    primitives::address,
    rpc::types::{BlockNumberOrTag, Filter},
};

use fuels::{
    accounts::{provider::Provider as FuelProvider, wallet::WalletUnlocked},
    crypto::SecretKey,
};

use futures_util::stream::StreamExt;
mod contracts;
mod helper;

use crate::contracts::load_contracts;
use std::env;

// 1. Bidirectional message sending - fuel to sepolia done
// 2. Bidirectional token sending
// 3. Receive IGP payments
// 4. All ISMS working

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let sepolia_http_url =
        env::var("SEPOLIA_HTTP_RPC_URL").expect("SEPOLIA_HTTP_RPC_URL must be set");
    let fuel_provider = FuelProvider::connect("testnet.fuel.network").await.unwrap();
    let sepolia_provider = ProviderBuilder::new().on_builtin(&sepolia_http_url).await?;

    let fuel_block_number = fuel_provider.latest_block_height().await.unwrap();
    let sepolia_block_number = sepolia_provider.get_block_number().await.unwrap();
    println!("Latest fuel block number: {}", fuel_block_number);
    println!("Latest sepolia block number: {}", sepolia_block_number);

    let secret_key =
        SecretKey::from_str("0x5d80cd4fdacb3f5099311a197bb0dc6eb311dfd08e2c8ac3d901ff78629e2e28")
            .unwrap();
    let wallet = WalletUnlocked::new_from_private_key(secret_key, Some(fuel_provider.clone()));

    let contracts = load_contracts(wallet.clone());

    contracts.fuel_send_dispatch().await;

    let sepolia_ws_url = env::var("SEPOLIA_WS_RPC_URL").expect("SEPOLIA_WS_RPC_URL must be set");
    let sepolia_provider = ProviderBuilder::new().on_builtin(&sepolia_ws_url).await?;

    let mailbox_address = address!("c2E0b1526E677EA0a856Ec6F50E708502F7fefa9");
    let filter = Filter::new()
        .address(mailbox_address)
        .event("ReceivedMessage(uint32,bytes32,uint256,string)")
        .from_block(BlockNumberOrTag::Latest);

    let sub = sepolia_provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();

    while let Some(log) = stream.next().await {
        println!("Mailbox logs: {log:?}");
    }

    Ok(())
}
