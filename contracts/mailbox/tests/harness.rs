use fuels::{
    prelude::*,
    types::{Bits256, Bytes, Identity},
};
use ethers::types::H256;


use fuels::types::errors::transaction::Reason;

use hyperlane_core::{Decode, Encode, HyperlaneMessage as HyperlaneAgentMessage};

// use test_utils::{
//     bits256_to_h256, funded_wallet_with_private_key, get_revert_reason, get_revert_string,
//     h256_to_bits256,
// };


// Load abi from json
abigen!(Contract(
    name = "Mailbox",
    abi = "out/debug/mailbox-abi.json"
));

const NON_OWNER_PRIVATE_KEY: &str =
    "0xde97d8624a438121b86a1956544bd72ed68cd69f2c99555b08b1e8c51ffd511c";

const TEST_LOCAL_DOMAIN: u32 = 0x6675656cu32;
const TEST_REMOTE_DOMAIN: u32 = 0x112233cu32;
const TEST_RECIPIENT: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";


async fn get_contract_instance() -> (Mailbox<WalletUnlocked>, ContractId) {
    // Launch a local network and deploy the contract
    let mut wallets = launch_custom_provider_and_get_wallets(
        WalletsConfig::new(
            Some(1),             /* Single wallet */
            Some(1),             /* Single coin (UTXO) */
            Some(1_000_000_000), /* Amount per coin */
        ),
        None,
        None,
    )
    .await
    .unwrap();
    let wallet = wallets.pop().unwrap();

    let id = Contract::load_from(
        "./out/debug/mailbox.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let instance = Mailbox::new(id.clone(), wallet);

    (instance, id.into())
}

// XXX
#[tokio::test]
async fn can_deploy_with_defaults() {
    let (_instance, _id) = get_contract_instance().await;

    let state = _instance.methods().owner().call().await.unwrap();
    assert_eq!(state.value, State::Uninitialized);

    println!("Owner: {:?}", state.value);
}

// Gets the wallet address from the `Mailbox` instance, and
// creates a test message with that address as the sender.
fn test_message(
    mailbox: &Mailbox<WalletUnlocked>,
    recipient: Bech32ContractId,
    outbound: bool,
) -> HyperlaneAgentMessage {
    let sender = mailbox.account().address().hash().as_slice();
    let formatted_sender: [u8; 32] = sender.try_into().unwrap();
    HyperlaneAgentMessage {
        version: 3u8,
        nonce: 0u32,
        origin: if outbound {
            TEST_LOCAL_DOMAIN
        } else {
            TEST_REMOTE_DOMAIN
        },
        sender: H256::from(formatted_sender ),
        destination: if outbound {
            TEST_REMOTE_DOMAIN
        } else {
            TEST_LOCAL_DOMAIN
        },
        recipient: H256::from(recipient.hash().as_slice()),
        body: vec![10u8; 100],
    }
}

// ============ dispatch ============


#[tokio::test]
async fn test_dispatch_too_large_message() {
    let (mailbox, _) = get_contract_instance().await;

    let large_message_body = vec![0u8; 6000];

    let dispatch_err = mailbox
        .methods()
        .dispatch(
            TEST_REMOTE_DOMAIN,
            Bits256::from_hex_str(TEST_RECIPIENT).unwrap(),
            Bytes(large_message_body),
            Bytes::from_hex_str("0x01").unwrap(),
            ContractId::default(),
        )
        .call()
        .await
        .unwrap_err();

    // TODO use test utils
    let reason = if let Error::Transaction(Reason::Reverted { reason, .. }) = dispatch_err {
        reason
    } else {
        panic!(
            "Unexpected error type - Error: {:?}",
            dispatch_err
        );
    };

    // TODO avoid hardcoding
    assert_eq!(reason, "MessageTooLarge(6000)");
}