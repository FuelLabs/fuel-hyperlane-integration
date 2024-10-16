use std::fs;
use std::str::FromStr;

use alloy::providers::{Provider as EthProvider, ProviderBuilder};
use alloy::{
    primitives::address,
    // providers::ws::WsConnect,
    rpc::types::{BlockNumberOrTag, Filter},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{env, path::Path};
use tokio::process::Command;

use futures_util::stream::StreamExt;

use fuels::{
    accounts::{provider::Provider as FuelProvider, wallet::WalletUnlocked},
    crypto::SecretKey,
    macros::abigen,
    types::{Bits256, Bytes, ContractId},
};

abigen!(
    Contract(
        name = "Mailbox",
        abi = "contracts/mailbox/out/debug/mailbox-abi.json",
    ),
    Contract(
        name = "PostDispatch",
        abi = "contracts/mocks/mock-post-dispatch/out/debug/mock-post-dispatch-abi.json",
    ),
    Contract(
        name = "MerkleTreeHook",
        abi = "contracts/hooks/merkle-tree-hook/out/debug/merkle-tree-hook-abi.json",
    ),
    Contract(
        name = "IGPHook",
        abi = "contracts/hooks/igp/out/debug/igp-hook-abi.json",
    ),
    Contract(
        name = "ValidatorAnnounce",
        abi = "contracts/validator-announce/out/debug/validator-announce-abi.json",
    ),
);

// 1. Bidirectional message sending
// 2. Bidirectional token sending
// 3. Receive IGP payments
// 4. All ISMS working

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fuel_provider = FuelProvider::connect("testnet.fuel.network").await.unwrap();
    let sepolia_provider = ProviderBuilder::new()
        .on_builtin("https://11155111.rpc.thirdweb.com")
        .await?;

    let fuel_block_number = fuel_provider.latest_block_height().await.unwrap();
    let sepolia_block_number = sepolia_provider.get_block_number().await.unwrap();
    println!("Latest fuel block number: {}", fuel_block_number);
    println!("Latest sepolia block number: {}", sepolia_block_number);

    let secret_key =
        SecretKey::from_str("0x5d80cd4fdacb3f5099311a197bb0dc6eb311dfd08e2c8ac3d901ff78629e2e28")
            .unwrap();
    let wallet = WalletUnlocked::new_from_private_key(secret_key, Some(fuel_provider.clone()));

    let contracts = load_contracts(wallet.clone());

    contracts.fuel.send_dispatch().await;

    let ws_rpc_url = "wss://11155111.rpc.thirdweb.com"; // TODO: change if doesn't work
    let provider = ProviderBuilder::new().on_builtin(&ws_rpc_url).await?;

    let mailbox_address = address!("c2E0b1526E677EA0a856Ec6F50E708502F7fefa9");
    let filter = Filter::new()
        .address(mailbox_address)
        .event("ReceivedMessage(uint32,bytes32,uint256,string)")
        .from_block(BlockNumberOrTag::Latest);

    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();

    while let Some(log) = stream.next().await {
        println!("Mailbox logs: {log:?}");
    }

    Ok(())
}

struct FuelContracts {
    mailbox: Mailbox<WalletUnlocked>,
    igp: ContractId,
    ism: ContractId,
    merkle_tree_hook: ContractId,
    validator_announce: ContractId,
}

impl FuelContracts {
    async fn send_dispatch(&self) {
        let recipient_address = hex::decode("c2E0b1526E677EA0a856Ec6F50E708502F7fefa9").unwrap();
        let mut address_array = [0u8; 32];
        address_array[12..].copy_from_slice(&recipient_address);

        let body = hex::encode("Hello from Fuel!").into_bytes();
        let res = self
            .mailbox
            .methods()
            .dispatch(
                11155111,
                Bits256(address_array),
                Bytes { 0: body },
                Bytes { 0: vec![0] },
                ContractId::zeroed(),
            )
            .determine_missing_contracts(Some(3))
            .await
            .unwrap()
            .call()
            .await;

        if let Err(e) = res {
            println!("Dispatch error: {:?}", e);
        } else {
            println!("Dispatch Success!");
        }
    }
}

struct SepoliaContracts {
    mailbox: String,
    recipient: String,
}

struct Contracts {
    fuel: FuelContracts,
    sepolia: SepoliaContracts,
}

fn load_contracts(wallet: WalletUnlocked) -> Contracts {
    let mailbox_id =
        ContractId::from_str("0xb8401ae1ffd5d6d719bc5496cd5016761a1f3ac0c363a3762cab84edd5286625")
            .unwrap();
    let mailbox_instance = Mailbox::new(mailbox_id.clone(), wallet.clone());

    Contracts {
        fuel: FuelContracts {
            mailbox: mailbox_instance,
            igp: ContractId::from_str(
                "0x27d8edf61f7eb6b5cea9a17b6abd0189ee99b4fddb661ded7b6738580d65e2c2",
            )
            .unwrap(),
            ism: ContractId::from_str(
                "0x1dd45a465874d8a2524c4507123941d3e76fed18166539ac7d3433a329c9d1ac",
            )
            .unwrap(),
            merkle_tree_hook: ContractId::from_str(
                "0x157cebff4280e815373e6b7f36a957fecb007fcd116f9322302c77ab7eee7853",
            )
            .unwrap(),
            validator_announce: ContractId::from_str(
                "0xe24c8b325fbde1d77b27e3f69dc1f60fcb23340c0249074e977b27f839b53210",
            )
            .unwrap(),
        },
        sepolia: SepoliaContracts {
            mailbox: "sepolia".to_string(),
            recipient: "0xc2E0b1526E677EA0a856Ec6F50E708502F7fefa9".to_string(),
        },
    }
}
