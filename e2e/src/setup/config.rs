use dotenv::dotenv;
use fuels::crypto::SecretKey;
use std::{env, str::FromStr};

#[derive(Debug)]
pub enum EnvE2E {
    Local,
    Testnet,
    Mainnet,
    LocalMocked,
}

impl From<String> for EnvE2E {
    fn from(env: String) -> Self {
        match env.as_str() {
            "local" => EnvE2E::Local,
            "testnet" => EnvE2E::Testnet,
            "mainnet" => EnvE2E::Mainnet,
            "local_mocked" => EnvE2E::LocalMocked,
            _ => EnvE2E::Local,
        }
    }
}

pub fn get_e2e_env() -> EnvE2E {
    let env = env::var("E2E_ENV")
        .ok()
        .map(EnvE2E::from)
        .expect("Failed to get E2E_ENV");

    println!("env read: {:?}", env);
    env
}

pub fn get_node_url() -> String {
    match get_e2e_env() {
        EnvE2E::Local => env::var("LOCAL_NODE_URL").unwrap_or_else(|_| {
            println!("Failed to get `LOCAL_NODE_URL`, defaulting to `127.0.0.1:4000`");
            "127.0.0.1:4000".to_string()
        }),
        EnvE2E::Testnet => env::var("TESTNET_NODE_URL").unwrap_or_else(|_| {
            println!("Failed to get `TESTNET_NODE_URL`, defaulting to `testnet.fuel.network`");
            "testnet.fuel.network".to_string()
        }),
        EnvE2E::Mainnet => {
            panic!("Mainnet not supported yet");
        }
        EnvE2E::LocalMocked => {
            println!("LocalMocked not supported yet");
            "127.0.0.1:4000".to_string()
        }
    }
}

pub fn get_loaded_private_key() -> SecretKey {
    dotenv().ok();
    let private_key = env::var("LOADED_FUEL_PRIVATE_KEY").unwrap_or_else(|_| {
        println!("Failed to get `PRIVATE_KEY`, defaulting to `0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711`");
        "0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711".to_string()
    });
    SecretKey::from_str(&private_key).unwrap()
}
