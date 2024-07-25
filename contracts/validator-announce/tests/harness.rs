use std::str::FromStr;

use ethers::utils::hex;
use fuels::{
    prelude::*,
    programs::call_response::FuelCallResponse,
    types::{Bits256, EvmAddress},
};

use hyperlane_core::{Announcement, HyperlaneSigner, H256};
use hyperlane_ethereum::Signers;
use test_utils::{evm_address, get_revert_string, sign_compact};

// fn log_info(message: &str) {
//     println!("{}", message);
// }

// Load abi from json
abigen!(Contract(
    name = "ValidatorAnnounce",
    abi = "contracts/validator-announce/out/debug/validator-announce-abi.json"
));

#[derive(Debug, PartialEq, Eq)]
pub struct ValidatorAnnouncementEvent {
    pub validator: EvmAddress,
    pub storage_location: Bytes,
}

const TEST_MAILBOX_ID: &str = "0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";
const TEST_LOCAL_DOMAIN: u32 = 0x6675656cu32;

// Random generated private keys
const TEST_VALIDATOR_0_PRIVATE_KEY: &str =
    "2ef987da35e5b389bb47cc4ec024ce0c37e5defd00de35fe61db6f50d1a858a1";

const TEST_VALIDATOR_1_PRIVATE_KEY: &str =
    "411f401057d09d1d65d898ff48f775b0568e8a4cd1212e894b8b4c8820c75c3e";

static mut TEST_VALIDATOR_SIGNER_0: Option<Signers> = None;
static mut TEST_VALIDATOR_SIGNER_1: Option<Signers> = None;

fn initialize_global_signers() {
    unsafe {
        TEST_VALIDATOR_SIGNER_0 = Some(Signers::Local(
            TEST_VALIDATOR_0_PRIVATE_KEY.parse().unwrap(),
        ));
        TEST_VALIDATOR_SIGNER_1 = Some(Signers::Local(
            TEST_VALIDATOR_1_PRIVATE_KEY.parse().unwrap(),
        ));
    }
}

fn get_signer_0() -> &'static Signers {
    unsafe {
        if TEST_VALIDATOR_SIGNER_0.is_none() {
            initialize_global_signers();
        }
        TEST_VALIDATOR_SIGNER_0.as_ref().unwrap()
    }
}

fn get_signer_1() -> &'static Signers {
    unsafe {
        if TEST_VALIDATOR_SIGNER_1.is_none() {
            initialize_global_signers();
        }
        TEST_VALIDATOR_SIGNER_1.as_ref().unwrap()
    }
}

async fn get_contract_instance() -> (ValidatorAnnounce<WalletUnlocked>, ContractId) {
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
        "./out/debug/validator-announce.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let instance = ValidatorAnnounce::new(id.clone(), wallet);

    (instance, id.into())
}

fn string_to_hex_string(input: &str) -> String {
    let bytes = input.as_bytes();
    hex::encode(bytes)
}

async fn sign_and_announce(
    validator_announce: &ValidatorAnnounce<WalletUnlocked>,
    signer: &Signers,
    storage_location: String,
) -> Result<FuelCallResponse<()>> {
    let mailbox_id = H256::from_str(TEST_MAILBOX_ID).unwrap();
    let signer_address = signer.eth_address();

    let announcement = Announcement {
        validator: signer_address,
        mailbox_address: mailbox_id,
        mailbox_domain: TEST_LOCAL_DOMAIN,
        storage_location: storage_location.clone(),
    };

    let compact_signed = sign_compact(signer, announcement).await;
    let storage_location_hex = string_to_hex_string(&storage_location);
    
    validator_announce
        .methods()
        .announce(
            evm_address(signer),
            Bytes::from_hex_str(&storage_location_hex).unwrap(),
            compact_signed,
        )
        .call()
        .await
}

// ================ announce ================

#[tokio::test]
async fn test_announce() {
    let (validator_announce, _id) = get_contract_instance().await;

    let signer = get_signer_0();

    let storage_location = "file://some/path/to/storage".to_string();
    sign_and_announce(&validator_announce, signer, storage_location.clone())
        .await
        .unwrap();

    //Check that we can't announce twice
    let call = sign_and_announce(&validator_announce, signer, storage_location.clone()).await;
    assert!(call.is_err());
    assert_eq!(
        get_revert_string(call.err().unwrap()),
        "0validator and storage location already announced"
    );
}

//================ test_announce_reverts_if_invalid_signature ================

// #[tokio::test]
// async fn test_announce_reverts_if_invalid_signature() {
//     log_info("Starting test_announce_reverts_if_invalid_signature");
//     let (validator_announce, _id) = get_contract_instance().await;

//     let signer = get_signer_0();

//     let mailbox_id = H256::from_str(TEST_MAILBOX_ID).unwrap();

//     let validator_h160 = signer.eth_address();

//     let non_signer_validator = evm_address(&signer.clone());

//     let storage_location = "file://some/path/to/storage";
//     let storage_location_hex = string_to_hex_string(storage_location);

//     let announcement = Announcement {
//         validator: validator_h160,
//         mailbox_address: mailbox_id,
//         mailbox_domain: TEST_LOCAL_DOMAIN,
//         storage_location: storage_location.into(),
//     };

//     // Sign an announcement and announce it
//     log_info("Signing the announcement");
//     let compact_signature = sign_compact(signer, announcement).await;
//     log_info("Calling announce method with an invalid signature");
//     let call = validator_announce
//         .methods()
//         .announce(
//             // Try announcing with a different validator address
//             non_signer_validator,
//             Bytes::from_hex_str(&storage_location_hex).unwrap(),
//             compact_signature,
//         )
//         .call()
//         .await;

//     // assert!(call.is_err());
//     print!("{:?}", call);
//     assert_eq!(
//         get_revert_string(call.err().unwrap()),
//         "\u{1b}validator is not the signer"
//     );
//     log_info("test_announce_reverts_if_invalid_signature completed");
// }

//================ test_announce_reverts_if_storage_location_over_128_chars ================
#[tokio::test]
async fn test_announce_reverts_if_storage_location_over_128_chars() {
    let (validator_announce, _id) = get_contract_instance().await;

    let signer = get_signer_1();

    let storage_location = "a".repeat(129);
    let call = sign_and_announce(&validator_announce, signer, storage_location).await;
    assert!(call.is_err());
    assert_eq!(
        get_revert_string(call.err().unwrap()),
        "/storage location must be at most 128 characters"
    );
}

//================ get_announced_storage_location ================
#[tokio::test]
async fn test_get_announced_storage_location() {
    let (validator_announce, _id) = get_contract_instance().await;

    let signer = get_signer_0();
    let validator = evm_address(signer);

    let storage_location = "file://some/path/to/storage".to_string();

    sign_and_announce(&validator_announce, signer, storage_location.clone())
        .await
        .unwrap();

    let announced_storage_location: String = validator_announce
        .methods()
        .get_announced_storage_location(validator)
        .simulate()
        .await
        .unwrap()
        .value;

    assert_eq!(announced_storage_location, storage_location);
    let second_storage_location = "s3://some/s3/path".to_string();

    // Sign a new announcement and announce it
    sign_and_announce(&validator_announce, signer, second_storage_location.clone())
        .await
        .unwrap();

    // Get the latest storage location, which should be the second announcement now
    let announced_storage_location = validator_announce
        .methods()
        .get_announced_storage_location(validator)
        .simulate()
        .await
        .unwrap()
        .value;

    println!("{:?}", announced_storage_location);
    assert_eq!(announced_storage_location, second_storage_location);
}

// ================ get_announced_storage_location_count ================

#[tokio::test]
async fn test_get_announced_storage_location_count() {
    let (validator_announce, _id) = get_contract_instance().await;

    let signer = get_signer_0();
    let validator = evm_address(signer);

    // Get the count of storage locations, expect 1
    let storage_location_count = validator_announce
        .methods()
        .get_announced_storage_location(validator)
        .simulate()
        .await
        .unwrap()
        .value;
    assert_eq!(storage_location_count.len(), 0);

    let first_storage_location = "file://some/path/to/storage".to_string();
    sign_and_announce(&validator_announce, signer, first_storage_location.clone())
        .await
        .unwrap();

    // Get the count of storage locations, expect 1
    let storage_location_output = validator_announce
        .methods()
        .get_announced_storage_location(validator)
        .simulate()
        .await
        .unwrap()
        .value;
    assert_eq!(storage_location_output, first_storage_location);

    let second_storage_location = "s3://some/s3/path".to_string();
    sign_and_announce(&validator_announce, signer, second_storage_location.clone())
        .await
        .unwrap();

    // let second_storage_loc = call.decode_logs();
    // let succeeded = second_storage_loc.filter_succeeded();
    // for log in succeeded {
    //     println!("Log: {}", log);
    // }

    // Get the count of storage locations, expect 2
    let storage_location_output = validator_announce
        .methods()
        .get_announced_storage_location(validator)
        .simulate()
        .await
        .unwrap()
        .value;
    assert_eq!(storage_location_output, second_storage_location);
}

//================ get_announced_validators ================

#[tokio::test]
async fn test_get_announced_validators() {
    let (validator_announce, _id) = get_contract_instance().await;

    let signer_0 = get_signer_0();
    let validator_0 = evm_address(signer_0);

    let signer_1 = get_signer_1();
    let validator_1 = evm_address(signer_1);

    // No validators yet
    let announced_validators = validator_announce
        .methods()
        .get_validators()
        .simulate()
        .await
        .unwrap()
        .value;
    assert_eq!(announced_validators, vec![]);

    let storage_location = "file://some/path/to/storage".to_string();

    sign_and_announce(&validator_announce, signer_0, storage_location.clone())
        .await
        .unwrap();

    let announced_validators = validator_announce
        .methods()
        .get_validators()
        .simulate()
        .await
        .unwrap()
        .value;
    assert_eq!(announced_validators, vec![validator_0.value()]);

    // Sign another announcement from validator_1 and announce it
    let second_storage_location = "file://a/different/path/to/storage".to_string();

    sign_and_announce(
        &validator_announce,
        signer_1,
        second_storage_location.clone(),
    )
    .await
    .unwrap();

    // Now 2 validators
    let announced_validators = validator_announce
        .methods()
        .get_validators()
        .simulate()
        .await
        .unwrap()
        .value;

    assert_eq!(
        announced_validators,
        vec![validator_0.value(), validator_1.value()]
    );

    //second announcement from the validator_0, should not change the announced validators output
    sign_and_announce(
        &validator_announce,
        signer_0,
        second_storage_location.clone(),
    )
    .await
    .unwrap();

    // Still the same 2 validators
    let announced_validators = validator_announce
        .methods()
        .get_validators()
        .simulate()
        .await
        .unwrap()
        .value;

    assert_eq!(
        announced_validators,
        vec![validator_0.value(), validator_1.value()]
    );
}

