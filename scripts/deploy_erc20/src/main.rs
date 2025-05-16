use ethers::{
    abi::Abi,
    prelude::{abigen, ContractFactory, LocalWallet, Signer, SignerMiddleware},
    providers::{Http, Provider},
    types::{Bytes, U256},
};
use eyre::Result;
use std::{env, fs, str::FromStr, sync::Arc};

abigen!(ERC20Test, "src/ERC20Test.json");

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let rpc_url = args
        .get(1)
        .unwrap_or(&"http://localhost:8545".to_string())
        .clone();
    let private_key = args
        .get(2)
        .ok_or_else(|| eyre::eyre!("Private key must be provided as the second argument"))?
        .clone();
    let token_name = args
        .get(3)
        .unwrap_or(&"CollateralTokenRoute".to_string())
        .clone();
    let token_symbol = args.get(4).unwrap_or(&"CTR".to_string()).clone();
    let token_supply_str = args
        .get(5)
        .unwrap_or(&"10000000000000000000".to_string())
        .clone();
    let token_decimals_str = args.get(6).unwrap_or(&"18".to_string()).clone();
    let chain_id_str = args.get(7).unwrap_or(&"31337".to_string()).clone();

    let token_decimals = token_decimals_str.parse::<u8>()?;
    let token_supply = U256::from_dec_str(&token_supply_str)? * U256::exp10(token_decimals as usize);

    let provider = Provider::<Http>::try_from(rpc_url)?;

    let formatted_key = if private_key.starts_with("0x") {
        private_key.strip_prefix("0x").unwrap().to_string()
    } else {
        private_key.clone()
    };

    let wallet = LocalWallet::from_str(&formatted_key)?.with_chain_id(chain_id_str.parse::<u64>()?);
    let client = SignerMiddleware::new(provider, wallet.clone());
    let client = Arc::new(client);

    let json = fs::read_to_string("src/ERC20Test.json")?;
    let contract_json: serde_json::Value = serde_json::from_str(&json)?;
    let abi: Abi = serde_json::from_value(contract_json["abi"].clone())?;

    let bytecode_str = contract_json["bytecode"]
        .as_str()
        .ok_or(eyre::eyre!("Bytecode not found"))?;
    let bytecode = if bytecode_str.starts_with("0x") {
        Bytes::from_str(bytecode_str)?
    } else {
        Bytes::from_str(&format!("0x{}", bytecode_str))?
    };

    let factory = ContractFactory::new(abi, bytecode, client.clone());
    let contract_instance = factory
        .deploy((token_name, token_symbol, token_supply, token_decimals))?
        .send()
        .await?;

    let contract = ERC20Test::new(contract_instance.address(), client.clone());
    let contract_address = format!("{:?}", contract.address());
    let wallet_address = wallet.address();

    let tx_hash = contract
        .mint_to(wallet_address, token_supply)
        .send()
        .await?
        .tx_hash();
    println!("✅ Tokens minted for evm wallet in tx: {:?}", tx_hash);

    println!("{}", contract_address);
    Ok(())
}
