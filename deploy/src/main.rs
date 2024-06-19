use rand::{thread_rng, Rng};
use std::str::FromStr;

use fuels::{
    crypto::SecretKey,
    prelude::*,
    types::{Bits256, Bytes, ContractId, Salt},
};

// const LOCAL_NODE: &str = "127.0.0.1:4000"; // For local deplyments use latest version of fuels
const TESTNET_NODE: &str = "testnet.fuel.network"; // For testnet deployments use fuels 0.55.0

abigen!(Contract(
    name = "Mailbox",
    abi = "../contracts/mailbox/out/debug/mailbox-abi.json",
));

// Random accounts to use
// PrivateKey(0xde97d8624a438121b86a1956544bd72ed68cd69f2c99555b08b1e8c51ffd511c), Address(0x6b63804cfbf9856e68e5b6e7aef238dc8311ec55bec04df774003a2c96e0418e [bech32: fuel1dd3cqn8mlxzku689kmn6au3cmjp3rmz4hmqymam5qqaze9hqgx8qtjpwn9]), Balance(10000000)
// PrivateKey(0x37fa81c84ccd547c30c176b118d5cb892bdb113e8e80141f266519422ef9eefd), Address(0x54944e5b8189827e470e5a8bacfc6c3667397dc4e1eef7ef3519d16d6d6c6610 [bech32: fuel12j2yukup3xp8u3cwt296elrvxennjlwyu8h00me4r8gk6mtvvcgqmtakkk]), Balance(10000000)
// PrivateKey(0x862512a2363db2b3a375c0d4bbbd27172180d89f23f2e259bac850ab02619301), Address(0xe10f526b192593793b7a1559a391445faba82a1d669e3eb2dcd17f9c121b24b1 [bech32: fuel1uy84y6ceykfhjwm6z4v68y2yt746s2sav60ravku69lecysmyjcss0yrdx]), Balance(10000000)
// PrivateKey(0x976e5c3fa620092c718d852ca703b6da9e3075b9f2ecb8ed42d9f746bf26aafb), Address(0x577e424ee53a16e6a85291feabc8443862495f74ac39a706d2dd0b9fc16955eb [bech32: fuel12alyynh98gtwd2zjj8l2hjzy8p3yjhm54su6wpkjm59elstf2h4swddd2d]), Balance(10000000)
// PrivateKey(0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711), Address(0xc36be0e14d3eaf5d8d233e0f4a40b3b4e48427d25f84c460d2b03b242a38479e [bech32: fuel1cd47pc2d86h4mrfr8c855s9nknjggf7jt7zvgcxjkqajg23cg70qnxg0hd]), Balance(10000000)

#[tokio::main]
async fn main() {
    let provider = Provider::connect(TESTNET_NODE).await.unwrap();
    let private_key =
        SecretKey::from_str("0x560651e6d8824272b34a229a492293091d0f8f735c4534cdf76addc57774b711")
            .unwrap();

    let wallet = WalletUnlocked::new_from_private_key(private_key, Some(provider));

    let binary_filepath = "../contracts/mailbox/out/debug/mailbox.bin";

    let config = get_deployment_config();
    let contract = Contract::load_from(binary_filepath, config).unwrap();

    let contract_id = contract
        .deploy(&wallet, TxPolicies::default())
        .await
        .unwrap();

    println!("Contract deployed with ID: {}", contract_id);
    println!("From: {}", wallet.address());

    // Example

    let mailbox = Mailbox::new(contract_id, wallet);

    let paused = mailbox.methods().is_paused().call().await.unwrap();
    println!("Paused: {}", paused.value);

    let destination_domain = 0x01;
    let recipient_address = Bits256::zeroed();
    let message_body_str ="0x03000000150033d90d0000000000000000000000006caeb3f629335544e5c83920358511528ab4d32500aa36a7000000000000000000000000678c64f17b4e91d737640e5c62e8f329f31dc4ac000000000000000000000000c908e76871406df6f866b068beb0100ea678d9f600000000000000000000000000000000000000000000003635c9adc5dea00000";
    let message_body = Bytes::from_hex_str(message_body_str).unwrap();
    let metadata_str = "0x000000000000000000000010000000950000000000000000000000007222b8b24788a79b173a42b2efa2585ed5a76198d06677e4f9f9426baf25bb5869b727d9d762e7ad0e65a0b996c8c26bdec9b4bc000000154fc320ced73551ed55147775d01afd40aa0c487e1d03492285a023a0d2f7696311b4658361ffe3e917b871e8982e0a488921076222eb5805dcd54d628e0c82981c";
    let metadata = Bytes::from_hex_str(metadata_str).unwrap();
    let hook = ContractId::default();

    let dispatch_res = mailbox
        .methods()
        .dispatch(
            destination_domain,
            recipient_address,
            message_body,
            metadata,
            hook,
        )
        .call()
        .await;

    if let Err(e) = dispatch_res {
        println!("Error: {}", e);
        return;
    }

    let res = dispatch_res.unwrap();

    let logs: LogResult = res.decode_logs();
    let succeeded = logs.filter_succeeded();
    for log in succeeded {
        println!("Log: {}", log);
    }

    if let Some(tx) = res.tx_id {
        println!("Transaction sent with ID: {}", tx);
    } else {
        println!("Failed to get TX ID.");
    }

    let owner = mailbox.methods().owner().call().await.unwrap();
    println!("Owner: {:?}", owner.value);
}

fn get_deployment_config() -> LoadConfiguration {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    let salt = Salt::new(bytes);

    LoadConfiguration::default().with_salt(salt)
}
