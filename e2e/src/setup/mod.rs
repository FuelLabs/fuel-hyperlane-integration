pub mod abis;
pub mod config;

use config::{get_e2e_env, get_loaded_private_key, get_node_url, EnvE2E};
use fuels::{accounts::signers::private_key::PrivateKeySigner, prelude::*};
use once_cell::sync::Lazy;
use tokio::sync::Mutex;

use crate::utils::token::get_native_asset;

static PROVIDER: Lazy<Mutex<Option<Provider>>> = Lazy::new(|| Mutex::new(None));
static WALLET: Lazy<Mutex<Option<Wallet>>> = Lazy::new(|| Mutex::new(None));

pub async fn get_provider() -> Provider {
    let mut provider_guard = PROVIDER.lock().await;
    if provider_guard.is_none() {
        let url = get_node_url();
        let provider = Provider::connect(url).await.unwrap();
        *provider_guard = Some(provider);
    }
    provider_guard.clone().unwrap()
}

pub async fn get_loaded_wallet() -> Wallet {
    let mut wallet_guard = WALLET.lock().await;

    if wallet_guard.is_none() {
        let env = get_e2e_env();

        match env {
            EnvE2E::LocalMocked => {
                let mut wallets = launch_custom_provider_and_get_wallets(
                    WalletsConfig::new_multiple_assets(
                        1,
                        vec![AssetConfig {
                            id: get_native_asset(),
                            num_coins: 1,                 /* Single coin (UTXO) */
                            coin_amount: 100_000_000_000, /* Amount per coin */
                        }],
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
                let signer = PrivateKeySigner::new(private_key);
                let wallet = Wallet::new(signer, provider);
                *wallet_guard = Some(wallet);
            }
        };
    }
    wallet_guard.clone().unwrap()
}
