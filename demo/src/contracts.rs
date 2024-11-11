use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{address, Address, Bytes as AlloyBytes, FixedBytes, U256},
    providers::ProviderBuilder,
    sol,
    transports::BoxTransport,
};
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
    programs::calls::{CallParameters, Execution},
    types::{bech32::Bech32ContractId, Bits256, Bytes, ContractId},
};
use futures_util::StreamExt;
use rand::{thread_rng, Rng};
use std::env;
use SepoliaMailbox::SepoliaMailboxInstance;
use SepoliaRecipient::SepoliaRecipientInstance;

use crate::helper::{get_contract_id_from_json, get_native_asset, read_deployments_yaml};

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
    Contract(
        name = "GasOracle",
        abi = "contracts/igp/gas-oracle/out/debug/gas-oracle-abi.json",
    ),
    Contract(
        name = "GasPaymaster",
        abi = "contracts/igp/gas-paymaster/out/debug/gas-paymaster-abi.json",
    ),
    Contract(
        name = "TestRecipient",
        abi = "contracts/test/msg-recipient-test/out/debug/msg-recipient-test-abi.json",
    ),
);

// Codegen from embedded Solidity code and precompiled bytecode.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SepoliaMailbox,
    "evm-abis/Mailbox.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SepoliaRecipient,
    "evm-abis/Recipient.json"
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
    pub recipient: SepoliaRecipientInstance<
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
    pub merkle_tree_hook: Address,
    pub message_id_multisig_ism: Address,
    pub merkle_root_multisig_ism: Address,
    pub test_ism: Address,
}

pub struct FuelContracts {
    pub mailbox: Mailbox<WalletUnlocked>,
    pub ism: ContractId,
    pub merkle_tree_hook: ContractId,
    pub validator_announce: ContractId,
    pub igp: GasPaymaster<WalletUnlocked>,
    pub gas_oracle: ContractId,
    pub igp_hook: IGPHook<WalletUnlocked>,
    pub test_recipient: TestRecipient<WalletUnlocked>,
    pub aggregation_ism: ContractId,
    pub domain_routing_ism: ContractId,
    pub fallback_domain_routing_ism: ContractId,
    pub message_id_multisig_ism: ContractId,
    pub merkle_root_multisig_ism: ContractId,
    pub test_ism: ContractId,
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

pub enum DispatchType {
    WithNoHook,
    WithIGPHook,
    WithMerkleTreeHook,
    TokenSend,
}

impl Contracts {
    pub async fn fuel_send_dispatch(&self, dispatch_type: DispatchType) -> (String, String) {
        let recipient_address = self.sepolia.recipient.address().to_vec();
        let mut address_array = [0u8; 32];
        address_array[12..].copy_from_slice(&recipient_address);

        let rnd_number = thread_rng().gen_range(0..10000);
        let body_text = format!("Hello from Fuel! {}", rnd_number);

        let hook = match dispatch_type {
            DispatchType::WithIGPHook => self.fuel.igp_hook.contract_id(),
            DispatchType::WithMerkleTreeHook => &Bech32ContractId::from(self.fuel.merkle_tree_hook),
            DispatchType::WithNoHook => &Bech32ContractId::default(),
            DispatchType::TokenSend => &Bech32ContractId::default(),
        };
        let body = hex::encode(body_text).into_bytes();

        let res = match dispatch_type {
            DispatchType::TokenSend => {
                self.fuel
                    .mailbox
                    .methods()
                    .dispatch(
                        84532,
                        Bits256(address_array),
                        Bytes(body),
                        Bytes(vec![0]),
                        hook,
                    )
                    .call_params(CallParameters::new(223526, get_native_asset(), 223526))
                    .unwrap()
                    .with_contracts(&[&self.fuel.igp, &self.fuel.igp_hook])
                    .determine_missing_contracts(Some(10))
                    .await
                    .unwrap()
                    .call()
                    .await
            }
            _ => {
                self.fuel
                    .mailbox
                    .methods()
                    .dispatch(
                        84532,
                        Bits256(address_array),
                        Bytes(body),
                        Bytes(vec![0]),
                        hook,
                    )
                    .with_contracts(&[&self.fuel.igp, &self.fuel.igp_hook])
                    .determine_missing_contracts(Some(10))
                    .await
                    .unwrap()
                    .call()
                    .await
            }
        };

        match res {
            Ok(res) => {
                let message_id = format!("0x{}", hex::encode(res.value.0));
                let tx_id = res.tx_id.unwrap();
                println!(
                    "Dispatch from Fuel successful at: 0x{:?}",
                    res.tx_id.unwrap()
                );
                (message_id, format!("0x{:?}", tx_id))
            }
            Err(e) => {
                println!("Dispatch error: {:?}", e);
                panic!();
            }
        }
    }

    pub async fn sepolia_send_dispatch(
        &self,
        dispatch_type: DispatchType,
    ) -> (FixedBytes<32>, FixedBytes<32>) {
        let recipient_address = ContractId::from(self.fuel.test_recipient.contract_id()).to_vec();
        let parsed_address: FixedBytes<32> = FixedBytes::from_slice(&recipient_address.as_slice());
        let rnd_number = thread_rng().gen_range(0..10000);
        let body_text = format!("Hello from sepolia! {}", rnd_number);
        let body = AlloyBytes::copy_from_slice(body_text.as_bytes());
        let metadata = AlloyBytes::copy_from_slice("".as_bytes());

        let res = match dispatch_type {
            DispatchType::WithNoHook => {
                self.sepolia
                    .mailbox
                    .dispatch_2(1717982312, parsed_address, body)
                    .value(U256::from(1))
                    .send()
                    .await
                    .unwrap()
                    .watch()
                    .await
            }
            DispatchType::WithMerkleTreeHook => {
                self.sepolia
                    .mailbox
                    .dispatch_0(
                        1717982312,
                        parsed_address,
                        body,
                        metadata,
                        self.sepolia.merkle_tree_hook,
                    )
                    .value(U256::from(1))
                    .send()
                    .await
                    .unwrap()
                    .watch()
                    .await
            }
            _ => panic!("Invalid dispatch type"),
        };

        match res {
            Ok(tx_id) => {
                println!("Dispatch from Sepolia successful");
                let message_id = self
                    .sepolia
                    .mailbox
                    .latestDispatchedId()
                    .call()
                    .await
                    .unwrap()
                    ._0;

                (message_id, tx_id)
            }
            Err(e) => {
                println!("Dispatch error: {:?}", e);
                panic!();
            }
        }
    }

    pub async fn set_fuel_mailbox_ism_to_test_ism(&self) {
        let res = self
            .fuel
            .mailbox
            .methods()
            .set_default_ism(self.fuel.test_ism)
            .call()
            .await
            .unwrap();

        println!("Mailbox ISM set to Test ISM at: {:?}", res.tx_id.unwrap());
    }

    pub async fn set_fuel_ism_to_aggregation(&self) {
        let res = self
            .fuel
            .test_recipient
            .methods()
            .set_ism(self.fuel.aggregation_ism)
            .call()
            .await
            .unwrap();

        println!("ISM set to Aggregation at: {:?}", res.tx_id.unwrap());
    }

    pub async fn set_fuel_ism_to_domain_routing(&self) {
        let res = self
            .fuel
            .test_recipient
            .methods()
            .set_ism(self.fuel.domain_routing_ism)
            .call()
            .await
            .unwrap();

        println!("ISM set to Domain Routing at: {:?}", res.tx_id.unwrap());
    }

    pub async fn set_fuel_ism_to_fallback_domain_routing(&self) {
        let res = self
            .fuel
            .test_recipient
            .methods()
            .set_ism(self.fuel.fallback_domain_routing_ism)
            .call()
            .await
            .unwrap();

        println!(
            "ISM set to Fallback Domain Routing at: {:?}",
            res.tx_id.unwrap()
        );
    }

    pub async fn set_fuel_ism_to_message_id_multisig(&self) {
        let res = self
            .fuel
            .test_recipient
            .methods()
            .set_ism(self.fuel.message_id_multisig_ism)
            .call()
            .await
            .unwrap();

        println!(
            "ISM set to Message ID Multisig at: {:?}",
            res.tx_id.unwrap()
        );
    }

    pub async fn set_fuel_ism_to_merkle_root_multisig(&self) {
        let res = self
            .fuel
            .test_recipient
            .methods()
            .set_ism(self.fuel.merkle_root_multisig_ism)
            .call()
            .await
            .unwrap();

        println!(
            "ISM set to Merkle Root Multisig at: {:?}",
            res.tx_id.unwrap()
        );
    }

    pub async fn set_sepolia_ism_to_message_id_multisig(&self) {
        let res = self
            .sepolia
            .recipient
            .setInterchainSecurityModule(self.sepolia.message_id_multisig_ism)
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();

        println!("ISM set to Message ID Multisig at: {:?}", res);
    }

    pub async fn set_sepolia_ism_to_merkle_root_multisig(&self) {
        let res = self
            .sepolia
            .recipient
            .setInterchainSecurityModule(self.sepolia.merkle_root_multisig_ism)
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();

        println!("ISM set to Merkle Root Multisig at: {:?}", res);
    }

    pub async fn set_sepolia_ism_to_test_ism(&self) {
        let res = self
            .sepolia
            .recipient
            .setInterchainSecurityModule(self.sepolia.test_ism)
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();

        println!("ISM set to Test ISM at: {:?}", res);
    }

    pub async fn fuel_quote_dispatch(&self) -> u64 {
        let gas_payment_quote = self
            .fuel
            .igp
            .methods()
            .quote_gas_payment(11155111, 5000)
            .with_contract_ids(&[self.fuel.gas_oracle.into()])
            .call()
            .await
            .map_err(|e| println!("Fuel quote gas payment error: {:?}", e))
            .unwrap();

        gas_payment_quote.value
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
                .simulate(Execution::StateReadOnly)
                .await
                .unwrap();

            println!("Is message delivered: {:?}", delivered_res.value);

            if delivered_res.value {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    }

    pub async fn monitor_sepolia_for_delivery(&self) -> FixedBytes<32> {
        let ws_rpc_url = env::var("SEPOLIA_WS_RPC_URL").expect("SEPOLIA_WS_RPC_URL must be set");
        let provider = ProviderBuilder::new()
            .on_builtin(ws_rpc_url.as_str())
            .await
            .unwrap();

        // let mailbox_address = address!("c2E0b1526E677EA0a856Ec6F50E708502F7fefa9");
        let recipient_address = self.sepolia.recipient.address().to_owned();
        let filter = Filter::new()
            .address(recipient_address)
            .event("ReceivedMessage(uint32,bytes32,uint256,string)")
            .from_block(BlockNumberOrTag::Latest);

        let sub = provider.subscribe_logs(&filter).await.unwrap();
        let mut stream = sub.into_stream();

        let mut tx_id = FixedBytes::default();
        while let Some(log) = stream.next().await {
            tx_id = log.transaction_hash.unwrap();
            println!("Sepolia Mailbox received message at: {:?}\n", tx_id);
            break;
        }
        tx_id
    }
}

pub async fn load_contracts(fuel_wallet: WalletUnlocked, evm_provider: EvmProvider) -> Contracts {
    // fuel contract addresses
    let mailbox_id = get_contract_id_from_json("fueltestnet", &["mailbox"]);
    let igp = get_contract_id_from_json("fueltestnet", &["interchainGasPaymaster"]);
    let ism = get_contract_id_from_json("fueltestnet", &["interchainSecurityModule"]);
    let merkle_tree_hook = get_contract_id_from_json("fueltestnet", &["merkleTreeHook"]);
    let validator_announce = get_contract_id_from_json("fueltestnet", &["validatorAnnounce"]);
    let igp_hook_id = get_contract_id_from_json("fueltestnet", &["interchainGasPaymasterHook"]);
    let gas_oracle = get_contract_id_from_json("fueltestnet", &["storageGasOracle"]);

    let yaml_config = read_deployments_yaml();
    // Fuel instances
    let mailbox_instance_fuel = Mailbox::new(mailbox_id, fuel_wallet.clone());
    let igp_hook_instance = IGPHook::new(igp_hook_id, fuel_wallet.clone());
    let igp_instance = GasPaymaster::new(igp, fuel_wallet.clone());
    let msg_recipient_instance =
        TestRecipient::new(yaml_config.test_recipient, fuel_wallet.clone());

    // Base Sepolia contract addresses
    let mailbox_instance_sepolia = SepoliaMailbox::new(
        address!("6966b0E55883d49BFB24539356a2f8A673E02039"),
        evm_provider.clone(),
    );
    let sepolia_recipient = SepoliaRecipient::new(
        address!("0276aD879FABcfF657b29DE6857F66282664B2f2"),
        evm_provider.clone(),
    );

    Contracts {
        fuel: FuelContracts {
            mailbox: mailbox_instance_fuel,
            igp: igp_instance,
            ism,
            merkle_tree_hook,
            validator_announce,
            gas_oracle,
            igp_hook: igp_hook_instance,
            aggregation_ism: yaml_config.aggregation_ism,
            domain_routing_ism: yaml_config.domain_routing_ism,
            fallback_domain_routing_ism: yaml_config.fallback_domain_routing_ism,
            message_id_multisig_ism: yaml_config.message_id_multisig_ism,
            merkle_root_multisig_ism: yaml_config.merkle_root_multisig_ism,
            test_recipient: msg_recipient_instance,
            test_ism: yaml_config.test_ism,
        },
        sepolia: SepoliaContracts {
            mailbox: mailbox_instance_sepolia,
            recipient: sepolia_recipient,
            merkle_tree_hook: address!("86fb9F1c124fB20ff130C41a79a432F770f67AFD"),
            message_id_multisig_ism: address!("5Fe883ad5BFe31942e2c383eb49e3c96eE053079"),
            merkle_root_multisig_ism: address!("8C94BA5A741a842eAa6eADd9CcA9d8B658D50024"),
            test_ism: address!("c56caE617c490C24a8fd82FDdf9B42DC4069813e"),
        },
    }
}
