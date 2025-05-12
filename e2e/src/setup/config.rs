use dotenv::dotenv;
use fuels::crypto::SecretKey;
use std::{env, str::FromStr};

#[derive(Debug)]
pub enum EnvE2E {
    Local,
    LocalMocked,
}

impl From<String> for EnvE2E {
    fn from(env: String) -> Self {
        match env.as_str() {
            "local" => EnvE2E::Local,
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
        EnvE2E::LocalMocked => {
            println!("LocalMocked not supported yet");
            "127.0.0.1:4000".to_string()
        }
    }
}

pub fn get_loaded_private_key() -> SecretKey {
    dotenv().ok();
    let private_key = env::var("LOADED_FUEL_PRIVATE_KEY").unwrap_or_else(|_| {
        println!("Failed to get `PRIVATE_KEY`, defaulting to `0xde97d8624a438121b86a1956544bd72ed68cd69f2c99555b08b1e8c51ffd511c`");
        "0xde97d8624a438121b86a1956544bd72ed68cd69f2c99555b08b1e8c51ffd511c".to_string()
    });
    SecretKey::from_str(&private_key).unwrap()
}
