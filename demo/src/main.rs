use std::str::FromStr;

use alloy::{
    network::EthereumWallet,
    primitives::address,
    providers::{Provider as EthProvider, ProviderBuilder},
    signers::{
        k256::{ecdsa::SigningKey, SecretKey as SepoliaPrivateKey},
        local::PrivateKeySigner,
    },
};
use alloy_rpc_types::{BlockNumberOrTag, Filter};
use fuels::{
    accounts::{provider::Provider as FuelProvider, wallet::WalletUnlocked},
    crypto::SecretKey as FuelPrivateKey,
    types::{
        bech32::{Bech32Address, Bech32ContractId},
        Address,
    },
};

use futures_util::stream::StreamExt;
use helper::*;
mod contracts;
mod helper;

use crate::contracts::load_contracts;
use std::env;

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

    let secret_key = FuelPrivateKey::from_str(
        &env::var("FUEL_PRIVATE_KEY").expect("FUEL_PRIVATE_KEY must be set"),
    )
    .unwrap();
    let fuel_wallet = WalletUnlocked::new_from_private_key(secret_key, Some(fuel_provider.clone()));

    let contracts = load_contracts(fuel_wallet.clone(), sepolia_provider.clone()).await;

    ///////////////////////////////////////////////
    // Case 1: Send message from Sepolia to Fuel //
    ///////////////////////////////////////////////

    // let message_id = contracts.sepolia_send_dispatch().await;
    // println!("Message ID: {:?}", message_id);

    // contracts.monitor_fuel_for_delivery(message_id).await;

    ///////////////////////////////////////////////
    // Case 2: Send message from Fuel to Sepolia //
    ///////////////////////////////////////////////

    // contracts.fuel_send_dispatch(false).await;

    // contracts.monitor_sepolia_for_delivery().await;

    // panic!("Done");

    ////////////////////////////////////////////////////
    // Case 3: Send native token from Fuel to Sepolia //
    ////////////////////////////////////////////////////

    //contracts.sepolia_transfer_remote_collateral().await; // need update in hyperlane-monorepo

    //println!("Transferring remote collateral");
    //contracts.fuel_transfer_remote_collateral().await;
    // println!("Transferring remote bridged");
    contracts
        .fuel_transfer_remote_bridged(fuel_wallet.clone())
        .await;

    ////////////////////////////////////////////////////
    // Case 4: Send native token from Sepolia to Fuel //
    ////////////////////////////////////////////////////

    // let recipient_address = contracts.fuel.recipient;

    // let balance_before: u64 = get_contract_balance(&fuel_provider, recipient_address).await;
    // println!("Balance before: {}", balance_before);

    // contracts.sepolia_transfer_remote_bridged().await;

    // let balance_after = get_contract_balance(&fuel_provider, recipient_address).await;
    // println!("Balance after: {}", balance_after);

    // println!("Difference: {}", balance_after - balance_before);

    ////////////////////////////////////////////////////////////////////////////////////
    // ⬇️ TODO move to clean case, actually check if we send/claim the right amount ⬇️ //
    ////////////////////////////////////////////////////////////////////////////////////

    panic!("Done");

    let gas_payment_quote = contracts.fuel_quote_dispatch().await;
    let wallet_balance_before = get_native_balance(&fuel_provider, fuel_wallet.address()).await;
    let wallet_balance_after = get_native_balance(&fuel_provider, fuel_wallet.address()).await;

    // Wallet balance after should be more than gas_payment_quote
    if wallet_balance_before - wallet_balance_after < gas_payment_quote {
        panic!("Wallet balance difference is less than gas payment quote");
    }

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
