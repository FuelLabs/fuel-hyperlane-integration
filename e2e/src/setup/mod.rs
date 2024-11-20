pub mod abis;
pub mod config;

use config::{get_e2e_env, get_loaded_private_key, get_node_url, EnvE2E};
use dotenv::dotenv;
use fuels::prelude::*;
use once_cell::sync::Lazy;
use tokio::{process::Child, sync::Mutex};

use crate::utils::token::{get_collateral_asset, get_native_asset};

pub async fn setup() -> Option<Child> {
    dotenv().ok();

    let env = get_e2e_env();
    if let EnvE2E::Local = env {
        launch_local_node().await;
        // initialize_contract_registry().await;
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
    let _ = get_loaded_wallet().await;
}
pub async fn get_loaded_wallet() -> WalletUnlocked {
    let mut wallet_guard = WALLET.lock().await;

    if wallet_guard.is_none() {
        let env = get_e2e_env();

        match env {
            EnvE2E::LocalMocked => {
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
