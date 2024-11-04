mod contracts;
mod helper;

use std::{env, str::FromStr};

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

use crate::contracts::load_contracts;
use helper::*;

// 1. Bidirectional message sending - done
// 2. Bidirectional token sending
// 3. Receive IGP payments
// 4. All ISMS working

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let sepolia_http_url =
        env::var("SEPOLIA_HTTP_RPC_URL").expect("SEPOLIA_HTTP_RPC_URL must be set");
    let fuel_provider = FuelProvider::connect("testnet.fuel.network").await.unwrap();

    let sepolia_pk = SepoliaPrivateKey::from_slice(
        &hex::decode(env::var("SEPOLIA_PRIVATE_KEY").expect("SEPOLIA_HTTP_RPC_URL must be set"))
            .unwrap(),
    )
    .unwrap();
    let sepolia_pk = SigningKey::from(sepolia_pk);
    let signer = PrivateKeySigner::from_signing_key(sepolia_pk);
    let eth_wallet = EthereumWallet::from(signer);
    let sepolia_provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(eth_wallet)
        .on_builtin(&sepolia_http_url)
        .await?;

    let fuel_block_number = fuel_provider.latest_block_height().await.unwrap();
    let sepolia_block_number = sepolia_provider.get_block_number().await.unwrap();
    println!("Latest fuel block number: {}", fuel_block_number);
    println!("Latest sepolia block number: {}", sepolia_block_number);
    println!("-----------------------------------------------------------");

    let secret_key = FuelPrivateKey::from_str(
        &env::var("FUEL_PRIVATE_KEY").expect("FUEL_PRIVATE_KEY must be set"),
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

    contracts.fuel_send_dispatch(false).await;

    contracts.monitor_sepolia_for_delivery().await;

    ////////////////////////////////////////////////////
    // Case 3: Collateral Sepolia (USDC) -> Fuel (ETH)//
    ////////////////////////////////////////////////////

    println!("Case: Exchange Collateral USDC from Sepolia with Fuel ETH");

    let amount = 6;
    println!("transfer amount is {}", amount);

    send_token_to_contract(
        fuel_wallet.clone(),
        contracts.fuel.warp_route_collateral.contract_id(),
        amount,
    )
    .await;

    let initial_balance = get_native_balance(&fuel_provider).await;
    println!("Initial recipient balance: {}", initial_balance);

    let message_id = contracts.sepolia_transfer_remote_collateral(amount).await;
    contracts.monitor_fuel_for_delivery(message_id).await;

    let final_balance = get_native_balance(&fuel_provider).await;
    println!("Final recipient balance: {}", final_balance);
    println!("Difference: {}", final_balance - initial_balance);
    println!(
        "Recipient transactions can be verified from: https://app-testnet.fuel.network/contract/0x45eef0a12f9bd3590ca07f81f32bc6e15e6b5e6c2440451c8b4af2126adf718b/transactions",
    );
    println!("-----------------------------------------------------------");

    ////////////////////////////////////////////////////
    // Case 4: Bridged Fuel (FST) to Sepolia (FST) //
    ////////////////////////////////////////////////////

    let amount = 300_000;
    println!("Case: Transferring Custom (FST) Token from Fuel to Sepolia");
    println!("-----------------------------------------------------------");
    println!("transfer amount is {}", amount);

    contracts
        .fuel_transfer_remote_bridged(fuel_wallet.clone(), amount)
        .await;

    contracts.monitor_sepolio_for_asset_delivery(true).await;
    println!("-----------------------------------------------------------");

    ////////////////////////////////////////////////////
    // Case 5: Bridged Sepolia (FST) to Fuel (FST) //
    ////////////////////////////////////////////////////

    println!("Case: Transferring Sepolia (FST) to Fuel (FST)");

    let amount = 470;
    println!("transfer amount is {}", amount);
    let asset_id = contracts.fuel_get_minted_asset_id().await;

    let balance_before: u64 = get_bridged_balance(&fuel_provider, asset_id).await;
    println!("Balance before: {}", balance_before);

    let message_id = contracts.sepolia_transfer_remote_bridged(amount).await;
    contracts.monitor_fuel_for_delivery(message_id).await;

    let balance_after = get_bridged_balance(&fuel_provider, asset_id).await;
    println!("Balance after: {}", balance_after);
    println!(
        "Recipient transactions can be verified from: https://app-testnet.fuel.network/contract/0x{}/transactions",
        TEST_RECIPIENT_IN_FUEL
    );
    println!("-----------------------------------------------------------");

    ////////////////////////////////////////////////////
    // Case 6: Collateral Fuel (ETH) to Sepolia (USDC)//
    ////////////////////////////////////////////////////

    println!("Case: Transferring Fuel (ETH) to Sepolia (USDC)");

    let amount = 1;
    println!("transfer amount is {}", amount);

    contracts.fuel_transfer_remote_collateral(amount).await;
    contracts.monitor_sepolio_for_asset_delivery(false).await;

    Ok(())
}
