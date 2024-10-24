use std::str::FromStr;

use alloy::{
    network::EthereumWallet,
    providers::{Provider as EthProvider, ProviderBuilder},
    signers::{
        k256::{ecdsa::SigningKey, SecretKey as SepoliaPrivateKey},
        local::PrivateKeySigner,
    },
};
use fuels::{
    accounts::{provider::Provider as FuelProvider, wallet::WalletUnlocked},
    crypto::SecretKey as FuelPrivateKey,
};

mod contracts;
mod helper;

use crate::contracts::load_contracts;

// 1. Bidirectional message sending - done
// 2. Bidirectional token sending
// 3. Receive IGP payments
// 4. All ISMS working

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fuel_provider = FuelProvider::connect("testnet.fuel.network").await.unwrap();

    let sepolia_pk = SepoliaPrivateKey::from_slice(
        &hex::decode(" ").unwrap(), // Todo from env
    )
    .unwrap();
    let sepolia_pk = SigningKey::from(sepolia_pk);
    let signer = PrivateKeySigner::from_signing_key(sepolia_pk);
    let eth_wallet = EthereumWallet::from(signer);
    let sepolia_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(eth_wallet)
        .on_builtin("") // https://11155111.rpc.thirdweb.com
        .await?;

    let fuel_block_number = fuel_provider.latest_block_height().await.unwrap();
    let sepolia_block_number = sepolia_provider.get_block_number().await.unwrap();
    println!("Latest fuel block number: {}", fuel_block_number);
    println!("Latest sepolia block number: {}", sepolia_block_number);

    let secret_key = FuelPrivateKey::from_str(
        "", // todo from env
    )
    .unwrap();
    let fuel_wallet = WalletUnlocked::new_from_private_key(secret_key, Some(fuel_provider.clone()));

    let contracts = load_contracts(fuel_wallet.clone(), sepolia_provider.clone()).await;

    ///////////////////////////////////////////////
    // Case 1: Send message from Sepolia to Fuel //
    ///////////////////////////////////////////////

    let message_id = contracts.sepolia_send_dispatch().await;
    println!("Message ID: {:?}", message_id);

    contracts.monitor_fuel_for_delivery(message_id).await;

    ///////////////////////////////////////////////
    // Case 2: Send message from Fuel to Sepolia //
    ///////////////////////////////////////////////

    contracts.fuel_send_dispatch().await;

    contracts.monitor_sepolia_for_delivery().await;

    Ok(())
}
