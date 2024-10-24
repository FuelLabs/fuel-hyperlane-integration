use ethers::{prelude::*, signers::LocalWallet};
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::sync::Arc;

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

pub fn get_evm_client_and_wallet() -> (
    Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    LocalWallet,
) {
    let metadata = get_evm_metadata_from_yaml();
    let rpc_url = metadata.rpcUrls[0]
        .get("http")
        .expect("URL not found")
        .clone(); // Extract the URL string

    let provider = Provider::<Http>::try_from(rpc_url)
        .unwrap()
        .interval(std::time::Duration::from_millis(10u64));

    let wallet: LocalWallet = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(metadata.chainId as u64);

    (
        Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone())),
        wallet,
    )
}
