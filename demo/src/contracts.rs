use std::env;

use crate::{
    contracts::sepolia_mailbox::SepoliaMailbox::SepoliaMailboxInstance, get_bridged_asset,
};
use sepolia_mailbox::SepoliaMailbox;
use sepolia_warp_route_bridged::SepoliaWarpRouteBridged::SepoliaWarpRouteBridgedInstance;
use sepolia_warp_route_collateral::SepoliaWarpRouteCollateral::SepoliaWarpRouteCollateralInstance;

use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{address, Bytes as AlloyBytes, FixedBytes, U256},
    providers::ProviderBuilder,
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
    programs::calls::CallParameters,
    types::{
        bech32::Bech32ContractId, transaction_builders::VariableOutputPolicy, Address, Bits256,
        Bytes, ContractId,
    },
};
use futures_util::StreamExt;
use rand::{thread_rng, Rng};

use serde_json::Value;

use crate::helper::{get_contract_id_from_json, get_native_asset, get_value_from_json};

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
        name = "WarpRoute",
        abi = "contracts/warp-route/out/debug/warp-route-abi.json",
    ),
);

mod sepolia_mailbox {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        SepoliaMailbox,
        "evm-abis/Mailbox.json"
    );
}

mod sepolia_warp_route_bridged {
    use alloy::sol;
    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        SepoliaWarpRouteBridged,
        "evm-abis/HypERC20.json",
    );
}

mod sepolia_warp_route_collateral {
    use alloy::sol;
    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        SepoliaWarpRouteCollateral,
        "evm-abis/HypERC20Collateral.json",
    );
}

#[allow(clippy::type_complexity)]
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
    pub warp_route_collateral: SepoliaWarpRouteCollateralInstance<
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
    pub warp_route_bridged: SepoliaWarpRouteBridgedInstance<
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
}

pub struct FuelContracts {
    pub mailbox: Mailbox<WalletUnlocked>,
    pub ism: ContractId,
    pub merkle_tree_hook: ContractId,
    pub validator_announce: ContractId,
    pub igp: GasPaymaster<WalletUnlocked>,
    pub gas_oracle: ContractId,
    pub igp_hook: IGPHook<WalletUnlocked>,
    pub warp_route_collateral: WarpRoute<WalletUnlocked>,
    pub warp_route_bridged: WarpRoute<WalletUnlocked>,
    pub recipient: ContractId,
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

    pub async fn fuel_send_dispatch(&self, with_igp: bool) {
        let recipient_address = hex::decode("c2E0b1526E677EA0a856Ec6F50E708502F7fefa9").unwrap();
        let mut address_array = [0u8; 32];
        address_array[12..].copy_from_slice(&recipient_address);

        let rnd_number = thread_rng().gen_range(0..10000);
        let body_text = format!("Hello from Fuel! {}", rnd_number);

        let hook = match with_igp {
            true => self.fuel.igp_hook.contract_id(),
            false => &Bech32ContractId::default(),
        };

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
                hook,
            )
            .call_params(CallParameters::new(223526, get_native_asset(), 223526))
            .unwrap()
            .with_contracts(&[&self.fuel.igp, &self.fuel.igp_hook])
            .determine_missing_contracts(Some(5))
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

    /// Fuel (ETH) -> Sepolia (USDC)
    pub async fn fuel_transfer_remote_collateral(&self) {
        let recipient_address = hex::decode("031AD9c560D37baC7d6Bd2d27A2443bAfd10101A").unwrap();
        let mut address_array = [0u8; 32];
        address_array[12..].copy_from_slice(&recipient_address);

        let remote_wr = hex::decode("78026106472a7FB10668fED0301Af9dD321cf16B").unwrap();
        let mut remote_wr_array = [0u8; 32];
        remote_wr_array[12..].copy_from_slice(&remote_wr);

        let add_router_res = self
            .fuel
            .warp_route_collateral
            .methods()
            .enroll_remote_router(11155111, Bits256(remote_wr_array))
            .call()
            .await
            .unwrap();

        println!("Enrolled remote router: {:?}", add_router_res.value);

        let token_info = self
            .fuel
            .warp_route_collateral
            .methods()
            .get_token_info()
            .call()
            .await
            .unwrap();

        let amount = 8;

        let res = self
            .fuel
            .warp_route_collateral
            .methods()
            .transfer_remote(11155111, Bits256(address_array), amount)
            .call_params(CallParameters::new(amount, get_native_asset(), 223_526))
            .unwrap()
            .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
            .determine_missing_contracts(Some(8))
            .await
            .unwrap()
            .call()
            .await;

        match res {
            Ok(res) => {
                println!(
                    "Transfer remote collateral (ETH) from fuel successful: 0x{:?}",
                    res.tx_id.unwrap()
                );
            }
            Err(e) => {
                println!("Transfer remote collateral (ETH) from fuel error: {:?}", e);
            }
        }
    }

    /// Fuel (FST) -> Sepolia (FST)
    pub async fn fuel_transfer_remote_bridged(&self, wallet: WalletUnlocked) {
        let recipient_address = hex::decode("031AD9c560D37baC7d6Bd2d27A2443bAfd10101A").unwrap();
        let mut address_array = [0u8; 32];
        address_array[12..].copy_from_slice(&recipient_address);

        let wr_address = hex::decode("b018793a4Bed2b5e859286786DFCD7eC0322a34E").unwrap();
        let mut wr_address_array = [0u8; 32];
        wr_address_array[12..].copy_from_slice(&wr_address);

        let add_router_res = self
            .fuel
            .warp_route_bridged
            .methods()
            .enroll_remote_router(11155111, Bits256(wr_address_array))
            .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
            .call()
            .await
            .unwrap();

        println!(
            "Enrolled Sepolia as remote router: {:?}",
            add_router_res.value
        );

        let router_address = self.fuel.warp_route_bridged.contract_id().hash();
        let parsed_router_address: FixedBytes<32> =
            FixedBytes::from_slice(router_address.as_slice());

        let res = self
            .sepolia
            .warp_route_bridged
            .enrollRemoteRouter(1717982312, parsed_router_address)
            .send()
            .await
            .unwrap()
            .watch()
            .await;

        println!("Enrolled Fuel as remote router: {:?}", res);

        let token_info = self
            .fuel
            .warp_route_bridged
            .methods()
            .get_token_info()
            .call()
            .await
            .unwrap();

        let amount = 9;

        let _token_mint_res = self
            .fuel
            .warp_route_bridged
            .methods()
            .mint_tokens(Address::from(wallet.address()), 10000)
            .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
            .determine_missing_contracts(Some(5))
            .await
            .unwrap()
            .call()
            .await
            .unwrap();

        // println!("Token minted: {:?}", _token_mint_res.value);
        println!("Bridged Asset ID in fuel: {:?}", token_info.value.asset_id);

        let res = self
            .fuel
            .warp_route_bridged
            .methods()
            .transfer_remote(11155111, Bits256(address_array), amount)
            .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
            .call_params(CallParameters::new(
                amount,
                token_info.value.asset_id,
                223_526,
            ))
            .unwrap()
            .determine_missing_contracts(Some(5))
            .await
            .unwrap()
            .call()
            .await;

        match res {
            Ok(res) => {
                println!(
                    "Transfer remote bridged from fuel successful: 0x{:?}",
                    res.tx_id.unwrap()
                );
            }
            Err(e) => {
                println!("Transfer remote bridged from fuel error: {:?}", e);
            }
        }
    }

    pub async fn sepolia_send_dispatch(&self) -> FixedBytes<32> {
        let recipient_address =
            hex::decode("a347fa1775198aa68fb1a4523a4925f891cca8f4dc79bf18ca71274c49f600c3")
                .unwrap();
        let parsed_address: FixedBytes<32> = FixedBytes::from_slice(recipient_address.as_slice());
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

    /// Sepolia (FST) -> Fuel (FST)
    pub async fn sepolia_transfer_remote_bridged(&self) {
        let recipient_address =
            hex::decode("a347fa1775198aa68fb1a4523a4925f891cca8f4dc79bf18ca71274c49f600c3")
                .unwrap();
        let parsed_address: FixedBytes<32> = FixedBytes::from_slice(recipient_address.as_slice());

        let router_address = self.fuel.warp_route_bridged.contract_id().hash();
        let parsed_router_address: FixedBytes<32> =
            FixedBytes::from_slice(router_address.as_slice());

        let res = self
            .sepolia
            .warp_route_bridged
            .enrollRemoteRouter(1717982312, parsed_router_address)
            .send()
            .await
            .unwrap()
            .watch()
            .await;

        println!("Enrolled remote router: {:?}", res);

        let res = self
            .sepolia
            .warp_route_bridged
            .transferRemote_1(1717982312, parsed_address, U256::from(1))
            .value(U256::from(1)) // qoute dispatch result
            .send()
            .await
            .unwrap()
            .watch()
            .await;

        match res {
            Ok(res) => {
                println!("Transfer remote native successful: {:?}", res);
            }
            Err(e) => {
                println!("Transfer remote native error: {:?}", e);
            }
        }
    }

    /// Sepolia (USDC) -> Fuel (ETH)
    pub async fn sepolia_transfer_remote_collateral(&self) {
        let recipient_address =
            hex::decode("a347fa1775198aa68fb1a4523a4925f891cca8f4dc79bf18ca71274c49f600c3")
                .unwrap();
        let parsed_address: FixedBytes<32> = FixedBytes::from_slice(recipient_address.as_slice());

        let router_address = self.fuel.warp_route_bridged.contract_id().hash();
        let parsed_router_address: FixedBytes<32> =
            FixedBytes::from_slice(router_address.as_slice());

        let res = self
            .sepolia
            .warp_route_collateral
            .enrollRemoteRouter(1717982312, parsed_router_address)
            .send()
            .await
            .unwrap()
            .watch()
            .await;

        println!("Enrolled remote router: {:?}", res);

        let res = self
            .sepolia
            .warp_route_collateral
            .transferRemote_1(1717982312, parsed_address, U256::from(1))
            .value(U256::from(1)) // qoute dispatch result
            .send()
            .await
            .unwrap()
            .watch()
            .await;

        match res {
            Ok(res) => {
                println!("Transfer remote collateral successful: {:?}", res);
            }
            Err(e) => {
                println!("Transfer remote native error: {:?}", e);
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
        let ws_rpc_url = env::var("SEPOLIA_WS_RPC_URL").expect("SEPOLIA_WS_RPC_URL must be set");
        let provider = ProviderBuilder::new()
            .on_builtin(ws_rpc_url.as_str())
            .await
            .unwrap();

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
    let mailbox_id = get_contract_id_from_json("fueltestnet", &["mailbox"]);
    let igp = get_contract_id_from_json("fueltestnet", &["interchainGasPaymaster"]);
    let ism = get_contract_id_from_json("fueltestnet", &["interchainSecurityModule"]);
    let merkle_tree_hook = get_contract_id_from_json("fueltestnet", &["merkleTreeHook"]);
    let validator_announce = get_contract_id_from_json("fueltestnet", &["validatorAnnounce"]);
    let igp_hook_id = get_contract_id_from_json("fueltestnet", &["igpHook"]);
    let gas_oracle = get_contract_id_from_json("fueltestnet", &["gasOracle"]);
    let warp_route_collateral = get_contract_id_from_json("fueltestnet", &["warpRouteNative"]);
    let warp_route_bridged = get_contract_id_from_json("fueltestnet", &["warpRouteBridged"]);
    let recipient = get_contract_id_from_json("fueltestnet", &["recipient"]);

    // sepolia contract addresses
    let sepolia_recipient = get_value_from_json("sepolia", &["testRecipient"]);
    let sepolia_mailbox = get_value_from_json("sepolia", &["mailbox"]);
    let _sepolia_warp_route_collateral = get_value_from_json("sepolia", &["nativeWarpRoute"]);

    let _sepolia_mailbox_id = match sepolia_mailbox {
        Value::String(s) => s,
        _ => panic!("Mailbox ID not found - Sepolia"),
    };

    // Fuel instances
    let mailbox_instance_fuel = Mailbox::new(mailbox_id, fuel_wallet.clone());
    let igp_hook_instance = IGPHook::new(igp_hook_id, fuel_wallet.clone());
    let igp_instance = GasPaymaster::new(igp, fuel_wallet.clone());
    let warp_route_collateral_instance = WarpRoute::new(warp_route_collateral, fuel_wallet.clone());
    let warp_route_bridged_instance = WarpRoute::new(warp_route_bridged, fuel_wallet.clone());

    // Sepolia instances
    let mailbox_instance_sepolia = SepoliaMailbox::new(
        address!("fFAEF09B3cd11D9b20d1a19bECca54EEC2884766"), //fix
        evm_provider.clone(),
    );

    let warp_route_collateral_instance_sepolia = SepoliaWarpRouteCollateralInstance::new(
        address!("78026106472a7FB10668fED0301Af9dD321cf16B"),
        evm_provider.clone(),
    );

    let warp_route_bridged_instance_sepolia = SepoliaWarpRouteBridgedInstance::new(
        address!("b018793a4Bed2b5e859286786DFCD7eC0322a34E"),
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
            warp_route_collateral: warp_route_collateral_instance,
            warp_route_bridged: warp_route_bridged_instance,
            recipient,
        },
        sepolia: SepoliaContracts {
            mailbox: mailbox_instance_sepolia,
            recipient: sepolia_recipient.to_string(),
            warp_route_collateral: warp_route_collateral_instance_sepolia,
            warp_route_bridged: warp_route_bridged_instance_sepolia,
        },
    }
}
