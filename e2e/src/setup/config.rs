use dotenv::dotenv;
use fuels::{crypto::SecretKey, programs::contract::LoadConfiguration, types::Salt};
use rand::{rngs::OsRng, Rng};
use std::{env, str::FromStr};

#[derive(Debug, Clone, Copy)]
pub enum HyperlaneContract {
    Mailbox,
    InterchainGasPaymaster,
    GasOracle,
    IGPHook,
    MerkleTreeHook,
    ValidatorAnnounce,
    AggregationISM,
    MessageIdMultisigISM,
    MerkleRootMultisigISM,
    DomainRoutingISM,
    DefaultFallbackDomainRoutingISM,
}

#[derive(Debug)]
pub enum EnvE2E {
    Local,
    Testnet,
    Mainnet,
}

impl From<String> for EnvE2E {
    fn from(env: String) -> Self {
        match env.as_str() {
            "local" => EnvE2E::Local,
            "testnet" => EnvE2E::Testnet,
            "mainnet" => EnvE2E::Mainnet,
            _ => EnvE2E::Local,
        }
    }
}

pub struct ContractData {
    pub _variant: HyperlaneContract,
    pub bin_path: &'static str,
}

// TODO is no more useful data will be stored, remove and implement
// get_contract_bin_path() instead of get_contract_data()
// Also probably remove _variant if it's not used in E2E tests
const MAILBOX_DATA: ContractData = ContractData {
    _variant: HyperlaneContract::Mailbox,
    bin_path: "../contracts/mailbox/out/debug/mailbox.bin",
};
const INTERCHAIN_GAS_PAYMASTER_DATA: ContractData = ContractData {
    _variant: HyperlaneContract::InterchainGasPaymaster,
    bin_path: "",
};
const GAS_ORACLE_DATA: ContractData = ContractData {
    _variant: HyperlaneContract::GasOracle,
    bin_path: "",
};
const IGP_HOOK_DATA: ContractData = ContractData {
    _variant: HyperlaneContract::IGPHook,
    bin_path: "",
};
const MERKLE_TREE_HOOK_DATA: ContractData = ContractData {
    _variant: HyperlaneContract::MerkleTreeHook,
    bin_path: "",
};
const VALIDATOR_ANNOUNCE_DATA: ContractData = ContractData {
    _variant: HyperlaneContract::ValidatorAnnounce,
    bin_path: "",
};
const AGGREGATION_ISM_DATA: ContractData = ContractData {
    _variant: HyperlaneContract::AggregationISM,
    bin_path: "",
};
const MESSAGE_ID_MULTISIG_ISM_DATA: ContractData = ContractData {
    _variant: HyperlaneContract::MessageIdMultisigISM,
    bin_path: "",
};
const MERKLE_ROOT_MULTISIG_ISM_DATA: ContractData = ContractData {
    _variant: HyperlaneContract::MerkleRootMultisigISM,
    bin_path: "",
};
const DOMAIN_ROUTING_ISM_DATA: ContractData = ContractData {
    _variant: HyperlaneContract::DomainRoutingISM,
    bin_path: "",
};
const DEFAULT_FALLBACK_DOMAIN_ROUTING_ISM_DATA: ContractData = ContractData {
    _variant: HyperlaneContract::DefaultFallbackDomainRoutingISM,
    bin_path: "",
};

pub fn get_contract_data(variant: HyperlaneContract) -> ContractData {
    match variant {
        HyperlaneContract::Mailbox => MAILBOX_DATA,
        HyperlaneContract::InterchainGasPaymaster => INTERCHAIN_GAS_PAYMASTER_DATA,
        HyperlaneContract::GasOracle => GAS_ORACLE_DATA,
        HyperlaneContract::IGPHook => IGP_HOOK_DATA,
        HyperlaneContract::MerkleTreeHook => MERKLE_TREE_HOOK_DATA,
        HyperlaneContract::ValidatorAnnounce => VALIDATOR_ANNOUNCE_DATA,
        HyperlaneContract::AggregationISM => AGGREGATION_ISM_DATA,
        HyperlaneContract::MessageIdMultisigISM => MESSAGE_ID_MULTISIG_ISM_DATA,
        HyperlaneContract::MerkleRootMultisigISM => MERKLE_ROOT_MULTISIG_ISM_DATA,
        HyperlaneContract::DomainRoutingISM => DOMAIN_ROUTING_ISM_DATA,
        HyperlaneContract::DefaultFallbackDomainRoutingISM => {
            DEFAULT_FALLBACK_DOMAIN_ROUTING_ISM_DATA
        }
    }
}

pub fn get_e2e_env() -> EnvE2E {
    let env = env::var("E2E_ENV")
        .ok()
        .map(|env| EnvE2E::from(env))
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

pub fn get_deployment_config() -> LoadConfiguration {
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    let salt = Salt::new(bytes);

    LoadConfiguration::default().with_salt(salt)
}
