use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::FixedBytes,
    providers::ProviderBuilder,
    signers::{
        k256::{ecdsa::SigningKey, SecretKey as SepoliaPrivateKey},
        local::PrivateKeySigner,
    },
    sol,
    transports::BoxTransport,
};
use alloy_provider::{
    fillers::{
        BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
    },
    Identity, RootProvider,
};
use serde::Deserialize;
use std::fs;
use std::{collections::HashMap, env};

use sepolia_warp_route_collateral::SepoliaWarpRouteCollateral::SepoliaWarpRouteCollateralInstance;
use sepolia_warp_route_synthetic::SepoliaWarpRouteSynthetic::SepoliaWarpRouteSyntheticInstance;
use SepoliaMailbox::SepoliaMailboxInstance;
use SepoliaRecipient::SepoliaRecipientInstance;

use crate::{
    setup::abis::Mailbox,
    utils::local_contracts::{get_value_from_agent_config_json, load_remote_wr_addresses},
};
use fuels::{accounts::wallet::Wallet, programs::calls::Execution, types::Bits256};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SepoliaRecipient,
    "src/evm/abis/Recipient.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SepoliaMailbox,
    "src/evm/abis/Mailbox.json"
);

mod sepolia_warp_route_synthetic {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        SepoliaWarpRouteSynthetic,
        "src/evm/abis/HypERC20.json",
    );
}
mod sepolia_warp_route_collateral {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        SepoliaWarpRouteCollateral,
        "src/evm/abis/HypERC20Collateral.json",
    );
}

#[allow(clippy::type_complexity, dead_code)]
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
    pub warp_route_synthetic: SepoliaWarpRouteSyntheticInstance<
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

#[allow(dead_code)]
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

#[allow(dead_code)]
#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub chainId: u32,
    pub domainId: String,
    pub protocol: String,
    pub rpcUrls: Vec<HashMap<String, String>>,
    pub displayName: String,
}

pub fn get_evm_metadata_from_yaml() -> Metadata {
    let path = "../infra/configs/chains/test1/metadata.yaml";
    let data = fs::read_to_string(path).expect("Unable to read YAML config file");
    let metadata: Metadata = serde_yaml::from_str(&data).expect("YAML format error");
    metadata
}

pub async fn get_evm_wallet() -> EthereumWallet {
    let sepolia_pk_env = env::var("SEPOLIA_PRIVATE_KEY").expect("SEPOLIA_PRIVATE_KEY must be set");
    let sepolia_pk_bytes = hex::decode(sepolia_pk_env).expect("Failed to decode hex string");

    let sepolia_pk = SepoliaPrivateKey::from_slice(&sepolia_pk_bytes)
        .expect("Failed to create SepoliaPrivateKey from slice");

    let sepolia_pk = SigningKey::from(sepolia_pk);

    let signer = PrivateKeySigner::from_signing_key(sepolia_pk);
    EthereumWallet::from(signer)
}

pub async fn monitor_fuel_for_delivery(
    mailbox_instance: Mailbox<Wallet>,
    message_id: FixedBytes<32>,
) -> bool {
    let message_id = Bits256(message_id.0);

    loop {
        let delivered_res = mailbox_instance
            .methods()
            .delivered(message_id)
            .simulate(Execution::state_read_only())
            .await
            .unwrap();

        if delivered_res.value {
            return true;
        } else {
            println!("Waiting for message delivery");
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
    }
}

impl SepoliaContracts {
    pub async fn initialize(wallet: EthereumWallet) -> Self {
        let metadata = get_evm_metadata_from_yaml();
        let rpc_url = metadata.rpcUrls[0]
            .get("http")
            .expect("URL not found")
            .to_string(); // Extract the URL string

        let evm_provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet.clone())
            .on_builtin(&rpc_url)
            .await
            .unwrap();

        let mailbox_address_value = get_value_from_agent_config_json("test1", "mailbox").unwrap();
        let mailbox_address_str: &str = mailbox_address_value
            .as_str()
            .expect("Failed to get mailbox address as string");
        let mailbox_address = mailbox_address_str.parse().expect("Invalid address format");

        let mailbox = SepoliaMailbox::new(mailbox_address, evm_provider.clone());

        let recipient_address_value =
            get_value_from_agent_config_json("test1", "testRecipient").unwrap();
        let recipient_address_str: &str = recipient_address_value
            .as_str()
            .expect("Failed to get mailbox address as string");

        let recipient = SepoliaRecipient::new(
            recipient_address_str
                .parse()
                .expect("Invalid address format"),
            evm_provider.clone(),
        );

        let collateral_wr = load_remote_wr_addresses("NTR").unwrap();
        let synthetic_wr = load_remote_wr_addresses("NTR").unwrap();

        let warp_route_collateral = SepoliaWarpRouteCollateralInstance::new(
            collateral_wr.parse().expect("Invalid address format"),
            evm_provider.clone(),
        );

        let warp_route_synthetic = SepoliaWarpRouteSyntheticInstance::new(
            synthetic_wr.parse().expect("Invalid address format"),
            evm_provider.clone(),
        );

        SepoliaContracts {
            mailbox,
            recipient,
            warp_route_synthetic,
            warp_route_collateral,
        }
    }
}
