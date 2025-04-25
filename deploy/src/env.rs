use std::{env, str::FromStr};

use fuels::crypto::SecretKey;

pub struct DeploymentEnv {
    pub structure: String,
    pub rpc_url: &'static str,
    pub secret_key: SecretKey,
    pub dump_path: String,
    pub origin_domain: u32,
}

impl DeploymentEnv {
    pub fn new() -> Self {
        let args: Vec<String> = env::args().collect();

        if args.len() < 2 {
            eprintln!("Error: Please provide deployment location (LOCAL or TESTNET), and optionally deployment structure and a path to dump deployments.");
            std::process::exit(1);
        }
        let env = &args[1];
        let structure = match args.get(2) {
            Some(structure) => structure.to_owned(),
            None => "test".to_owned(),
        };
        let dump_path = match args.get(3) {
            Some(path) => path,
            None => &"./deployments".to_owned(),
        };
        let fuel_pk = env::var("FUEL_PRIVATE_KEY").expect("FUEL_PRIVATE_KEY must be set");

        let (secret, rpc, dump_path, domain) = match env.as_str() {
            "LOCAL" => {
                let secret_key = SecretKey::from_str(&fuel_pk).unwrap();
                let local_rpc: &str = "127.0.0.1:4000";
                let dump_path = format!("{}/local", dump_path);
                let domain = 13373;
                (secret_key, local_rpc, dump_path, domain)
            }
            "TESTNET" => {
                let secret_key = SecretKey::from_str(&fuel_pk).unwrap();
                let testnet_rpc: &str = "testnet.fuel.network";
                let dump_path = format!("{}/testnet", dump_path);
                let domain = 1717982312;
                (secret_key, testnet_rpc, dump_path, domain)
            }
            "MAINNET" => {
                let secret_key = SecretKey::from_str(&fuel_pk).unwrap();
                let mainnet_rpc: &str = "mainnet.fuel.network";
                let dump_path = format!("{}/mainnet", dump_path);
                let domain = 1717982311;
                (secret_key, mainnet_rpc, dump_path, domain)
            }
            _ => panic!("Invalid environment string."),
        };
        Self {
            structure,
            rpc_url: rpc,
            secret_key: secret,
            dump_path,
            origin_domain: domain,
        }
    }
}

pub fn get_remote_domain_ids() -> Vec<u32> {
    let values = match env::var("REMOTE_DOMAINS") {
        Ok(val) => val,
        Err(_) => panic!("Must specify REMOTE_DOMAINS as comma separated integers for hyperlane structure deployment"),
    };
    values
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<u32>()
                .unwrap_or_else(|_| panic!("Invalid domain ID: {}", s))
        })
        .collect()
}

pub fn zero_pad(hex_str: &str) -> String {
    // Remove "0x" if it exists
    let hex = hex_str.trim_start_matches("0x");
    // Pad with zeros on the left to ensure the string is 64 characters long
    let padded = format!("{:0>64}", hex);
    // Reattach the "0x" prefix
    format!("0x{}", padded)
}
