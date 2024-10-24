use std::{str::FromStr, thread::sleep};

use abigen_bindings::mailbox_mod::interfaces::mailbox;
use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{address, Bytes as AlloyBytes, FixedBytes, U256},
    providers::ProviderBuilder,
    sol,
    sol_types::SolCall,
    transports::BoxTransport,
};
use alloy_contract::ContractInstance;
use alloy_provider::{
    fillers::{
        BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
    },
    Identity, Provider, RootProvider,
};
use alloy_rpc_types::{BlockNumberOrTag, Filter};
use fuels::{
    accounts::wallet::WalletUnlocked,
    macros::abigen,
    types::{Bits256, Bytes, ContractId},
};
use futures_util::StreamExt;
use rand::{thread_rng, Rng};
use serde_json::Value;
use SepoliaMailbox::{localDomainCall, SepoliaMailboxInstance};

use crate::helper::{get_contract_id_from_json, get_value_from_json};

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

// Codegen from embedded Solidity code and precompiled bytecode.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SepoliaMailbox,
    "evm-abis/Mailbox.json"
);

pub struct SepoliaContracts {
    pub mailbox: SepoliaMailboxInstance<
        BoxTransport,
        FillProvider<
            JoinFill<
                JoinFill<
                    Identity,
                    JoinFill<
                        GasFiller,
                        JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>,
                    >,
                >,
                WalletFiller<EthereumWallet>,
            >,
            RootProvider<BoxTransport>,
            BoxTransport,
            Ethereum,
        >,
    >,
    pub recipient: String,
}

pub struct FuelContracts {
    pub mailbox: Mailbox<WalletUnlocked>,
    pub igp: ContractId,
    pub ism: ContractId,
    pub merkle_tree_hook: ContractId,
    pub validator_announce: ContractId,
}

pub struct Contracts {
    pub fuel: FuelContracts,
    pub sepolia: SepoliaContracts,
}

pub type EvmProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<BoxTransport>,
    BoxTransport,
    Ethereum,
>;

impl Contracts {
    pub async fn fuel_send_dispatch(&self) {
        let recipient_address = hex::decode("c2E0b1526E677EA0a856Ec6F50E708502F7fefa9").unwrap();
        let mut address_array = [0u8; 32];
        address_array[12..].copy_from_slice(&recipient_address);

        let rnd_number = thread_rng().gen_range(0..10000);
        let body_text = format!("Hello from Fuel! {}", rnd_number);
        let body = hex::encode(body_text).into_bytes();
        let res = self
            .fuel
            .mailbox
            .methods()
            .dispatch(
                11155111,
                Bits256(address_array),
                Bytes(body),
                Bytes(vec![0]),
                ContractId::zeroed(),
            )
            .determine_missing_contracts(Some(3))
            .await
            .unwrap()
            .call()
            .await;

        match res {
            Ok(res) => {
                println!("Dispatch from Fuel successful at: {:?}", res.tx_id);
            }
            Err(e) => {
                println!("Dispatch error: {:?}", e);
            }
        }
    }

    pub async fn sepolia_send_dispatch(&self) -> FixedBytes<32> {
        let recipient_address =
            hex::decode("a347fa1775198aa68fb1a4523a4925f891cca8f4dc79bf18ca71274c49f600c3")
                .unwrap();
        let parsed_address: FixedBytes<32> = FixedBytes::from_slice(&recipient_address.as_slice());
        let rnd_number = thread_rng().gen_range(0..10000);
        let body_text = format!("Hello from sepolia! {}", rnd_number);
        let body = AlloyBytes::copy_from_slice(body_text.as_bytes());

        let res = self
            .sepolia
            .mailbox
            .dispatch_2(1717982312, parsed_address, body)
            .value(U256::from(1))
            .send()
            .await
            .unwrap()
            .watch()
            .await;

        match res {
            Ok(_) => {
                println!("Dispatch from Sepolia successful");
                let message_id = self
                    .sepolia
                    .mailbox
                    .latestDispatchedId()
                    .call()
                    .await
                    .unwrap()
                    ._0;

                message_id
            }
            Err(e) => {
                println!("Dispatch error: {:?}", e);
                panic!();
            }
        }
    }

    pub async fn monitor_fuel_for_delivery(&self, message_id: FixedBytes<32>) {
        println!("Monitoring Fuel for delivery");
        let message_id = Bits256(message_id.0);

        loop {
            let delivered_res = self
                .fuel
                .mailbox
                .methods()
                .delivered(message_id)
                .call()
                .await
                .unwrap();

            println!("Is message delivered: {:?}", delivered_res.value);

            if delivered_res.value {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }

    pub async fn monitor_sepolia_for_delivery(&self) {
        let ws_rpc_url = "";
        let provider = ProviderBuilder::new().on_builtin(ws_rpc_url).await.unwrap();

        let mailbox_address = address!("c2E0b1526E677EA0a856Ec6F50E708502F7fefa9");
        let filter = Filter::new()
            .address(mailbox_address)
            .event("ReceivedMessage(uint32,bytes32,uint256,string)")
            .from_block(BlockNumberOrTag::Latest);

        let sub = provider.subscribe_logs(&filter).await.unwrap();
        let mut stream = sub.into_stream();

        while let Some(log) = stream.next().await {
            println!("Mailbox logs: {log:?}");
            break;
        }
    }
}

pub async fn load_contracts(fuel_wallet: WalletUnlocked, evm_provider: EvmProvider) -> Contracts {
    // fuel contract addresses
    let mailbox_id = get_value_from_json("fueltestnet", &["mailbox"]);
    let igp = get_contract_id_from_json("fueltestnet", &["interchainGasPaymaster"]);
    let ism = get_contract_id_from_json("fueltestnet", &["interchainSecurityModule"]);
    let merkle_tree_hook = get_contract_id_from_json("fueltestnet", &["merkleTreeHook"]);
    let validator_announce = get_contract_id_from_json("fueltestnet", &["validatorAnnounce"]);

    // sepolia contract addresses
    let recipient = get_value_from_json("sepolia", &["testRecipient"]);
    let sepolia_mailbox = get_value_from_json("sepolia", &["mailbox"]);

    let fuel_mailbox_id = match mailbox_id {
        Value::String(s) => s,
        _ => panic!("Mailbox ID not found - Fuel"),
    };
    let sepolia_mailbox_id = match sepolia_mailbox {
        Value::String(s) => s,
        _ => panic!("Mailbox ID not found - Sepolia"),
    };

    // Fuel instances
    let mailbox_contract_id = ContractId::from_str(fuel_mailbox_id.as_str()).unwrap();
    let mailbox_instance_fuel = Mailbox::new(mailbox_contract_id, fuel_wallet.clone());

    // Sepolia instances
    let mailbox_instance_sepolia = SepoliaMailbox::new(
        address!("fFAEF09B3cd11D9b20d1a19bECca54EEC2884766"),
        evm_provider,
    );

    Contracts {
        fuel: FuelContracts {
            mailbox: mailbox_instance_fuel,
            igp,
            ism,
            merkle_tree_hook,
            validator_announce,
        },
        sepolia: SepoliaContracts {
            mailbox: mailbox_instance_sepolia,
            recipient: recipient.to_string(),
        },
    }
}
