pub mod abis;
pub mod config;

use abis::*;
use config::{
    get_contract_data, get_deployment_config, get_e2e_env, get_loaded_private_key, get_node_url,
    EnvE2E, HyperlaneContract as HyperlaneContractVariant,
};
use dotenv::dotenv;
use fuels::prelude::*;
use once_cell::sync::Lazy;
use tokio::{process::Child, sync::Mutex};

use crate::utils::{
    contract_registry::initialize_contract_registry,
    token::{get_collateral_asset, get_native_asset},
};

pub async fn setup() -> Option<Child> {
    dotenv().ok();

    let env = get_e2e_env();
    if let EnvE2E::Local = env {
        launch_local_node().await;
        initialize_contract_registry().await;
    }
    // let env = get_e2e_env();
    // println!("Setting up {:?} E2E environment", env);

    // let fuel_node = match env {
    //     EnvE2E::Local => {
    //         let mut child = Command::new("fuel-core")
    //             .arg("run")
    //             .arg("--db-type")
    //             .arg("in-memory")
    //             .stdout(Stdio::piped())
    //             .spawn()
    //             .expect("Failed to start fuel-core process");

    //         let stdout = child.stdout.take().expect("Failed to get stdout");

    //         Some(child)
    //     }
    //     _ => None,
    // };

    // fuel_node

    None
}

pub async fn cleanup(fuel_node: Option<Child>) {
    if let Some(mut fuel_node) = fuel_node {
        fuel_node
            .kill()
            .await
            .expect("Failed to kill fuel-core process");
    }
}

static PROVIDER: Lazy<Mutex<Option<Provider>>> = Lazy::new(|| Mutex::new(None));
static WALLET: Lazy<Mutex<Option<WalletUnlocked>>> = Lazy::new(|| Mutex::new(None));
// static MAILBOX: Lazy<Mutex<Option<Mailbox<WalletUnlocked>>>> = Lazy::new(|| Mutex::new(None));

pub async fn get_provider() -> Provider {
    let mut provider_guard = PROVIDER.lock().await;
    if provider_guard.is_none() {
        let url = get_node_url();
        let provider = Provider::connect(url).await.unwrap();
        *provider_guard = Some(provider);
    }
    provider_guard.clone().unwrap()
}

pub async fn launch_local_node() {
    // Initializing a wallet in a local env launches a local node
    let _ = get_loaded_wallet().await;
}
pub async fn get_loaded_wallet() -> WalletUnlocked {
    let mut wallet_guard = WALLET.lock().await;

    if wallet_guard.is_none() {
        let env = get_e2e_env();

        match env {
            EnvE2E::Local => {
                let mut wallets = launch_custom_provider_and_get_wallets(
                    WalletsConfig::new_multiple_assets(
                        1,
                        vec![
                            AssetConfig {
                                id: get_native_asset(),
                                num_coins: 1,                 /* Single coin (UTXO) */
                                coin_amount: 100_000_000_000, /* Amount per coin */
                            },
                            AssetConfig {
                                id: get_collateral_asset(),
                                num_coins: 1,                 /* Single coin (UTXO) */
                                coin_amount: 100_000_000_000, /* Amount per coin */
                            },
                        ],
                    ),
                    None,
                    None,
                )
                .await
                .unwrap();
                let wallet = wallets.pop().unwrap();
                *wallet_guard = Some(wallet);
            }
            _ => {
                let provider = get_provider().await;
                let private_key = get_loaded_private_key();
                let wallet = WalletUnlocked::new_from_private_key(private_key, Some(provider));
                *wallet_guard = Some(wallet);
            }
        };
    }
    wallet_guard.clone().unwrap()
}

// pub async fn get_mailbox() -> Result<Mailbox<WalletUnlocked>> {
//     let mut mailbox_guard = MAILBOX.lock().await;

//     if mailbox_guard.is_none() {
//         let (mailbox, _) = instantiate_mailbox().await?;
//         *mailbox_guard = Some(mailbox);
//     }
//     Ok(mailbox_guard.clone().unwrap())
// }

pub async fn deploy(
    variant: HyperlaneContractVariant,
) -> Result<(Bech32ContractId, WalletUnlocked)> {
    let binary_filepath = get_contract_data(variant).bin_path;

    let config = get_deployment_config();
    let contract = Contract::load_from(binary_filepath, config.clone()).unwrap();

    let wallet = get_loaded_wallet().await;

    Ok((
        contract.deploy(&wallet, TxPolicies::default()).await?,
        wallet,
    ))
}

// pub async fn deploy_with_wallet(
//     variant: HyperlaneContractVariant,
//     wallet: &WalletUnlocked,
// ) -> Bech32ContractId {
//     let binary_filepath = get_contract_data(variant).bin_path;

//     let config = get_deployment_config();
//     let contract = Contract::load_from(binary_filepath, config.clone()).unwrap();

//     contract
//         .deploy(wallet, TxPolicies::default())
//         .await
//         .unwrap()
// }

// pub async fn instantiate_mailbox() -> Result<(Mailbox<WalletUnlocked>, Bech32ContractId)> {
//     let (contract_id, wallet) = deploy(HyperlaneContractVariant::Mailbox).await?;
//     Ok((Mailbox::new(contract_id.clone(), wallet), contract_id))
// }

pub async fn deploy_test_contracts() -> MsgRecipient<WalletUnlocked> {
    let (contract_id, wallet) = deploy(HyperlaneContractVariant::MsgRecipient)
        .await
        .unwrap();

    MsgRecipient::new(contract_id.clone(), wallet)
}

pub async fn deploy_core_contracts() -> (
    Mailbox<WalletUnlocked>,
    WarpRoute<WalletUnlocked>,
    InterchainGasPaymaster<WalletUnlocked>,
    GasOracle<WalletUnlocked>,
) {
    let (contract_id, wallet) = deploy(HyperlaneContractVariant::Mailbox).await.unwrap();
    let mailbox = Mailbox::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::WarpRoute).await.unwrap();
    let warp_route = WarpRoute::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::InterchainGasPaymaster)
        .await
        .unwrap();

    let igp = InterchainGasPaymaster::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::GasOracle).await.unwrap();
    let gas_oracle = GasOracle::new(contract_id.clone(), wallet);

    (mailbox, warp_route, igp, gas_oracle)
}

pub async fn deploy_all_hooks() -> (IGPHook<WalletUnlocked>, MerkleTreeHook<WalletUnlocked>) {
    let (contract_id, wallet) = deploy(HyperlaneContractVariant::IGPHook).await.unwrap();
    let igp_hook = IGPHook::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::MerkleTreeHook)
        .await
        .unwrap();
    let merkle_tree_hook = MerkleTreeHook::new(contract_id.clone(), wallet);

    (igp_hook, merkle_tree_hook)
}

pub async fn deploy_all_isms() -> (
    AggregationISM<WalletUnlocked>,
    MessageIdMultisigISM<WalletUnlocked>,
    MerkleRootMultisigISM<WalletUnlocked>,
    DomainRoutingISM<WalletUnlocked>,
    DefaultFallbackDomainRoutingISM<WalletUnlocked>,
) {
    let (contract_id, wallet) = deploy(HyperlaneContractVariant::AggregationISM)
        .await
        .unwrap();
    let aggregation_ism = AggregationISM::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::MessageIdMultisigISM)
        .await
        .unwrap();
    let message_id_multisig_ism = MessageIdMultisigISM::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::MerkleRootMultisigISM)
        .await
        .unwrap();
    let merkle_root_multisig_ism = MerkleRootMultisigISM::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::DomainRoutingISM)
        .await
        .unwrap();
    let domain_routing_ism = DomainRoutingISM::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::DefaultFallbackDomainRoutingISM)
        .await
        .unwrap();
    let default_fallback_domain_routing_ism =
        DefaultFallbackDomainRoutingISM::new(contract_id.clone(), wallet);

    (
        aggregation_ism,
        message_id_multisig_ism,
        merkle_root_multisig_ism,
        domain_routing_ism,
        default_fallback_domain_routing_ism,
    )
}
