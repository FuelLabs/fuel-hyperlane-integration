use std::str::FromStr;

use alloy_primitives::{eip191_hash_message, Address, FixedBytes, Keccak256, B256};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use fuels::{
    core::{codec::ABIEncoder, traits::Tokenizable},
    prelude::*,
    types::{
        errors::{transaction::Reason, Error},
        Bits256, ContractId, EvmAddress, Token,
    },
};
use serde::{Deserialize, Serialize};

// Load abi from json
abigen!(Contract(
    name = "ValidatorAnnounce",
    abi = "contracts/validator-announce/out/debug/validator-announce-abi.json"
));

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignatureGenerationData {
    pub mailbox_id: ContractId,
    pub expected_domain_hash: Vec<u8>,
    pub storage_location: String,
    pub expected_announcement_digest: Vec<u8>,
}

// Data pulled from the unit tests in the VA contract
// to ensure that the Rust encoding implementation is correct
fn get_signature_generation_data() -> Vec<SignatureGenerationData> {
    vec![
        SignatureGenerationData {
            mailbox_id: ContractId::from_str(
                "0x676170cf14cbe655abf440d6d9c0b846c585269941c3c6d7066cfb7018e6ccd9",
            )
            .unwrap(),
            expected_domain_hash: hex::decode(
                "ea0de3c5380866991ae35cf3bdead2335aa01384553533f50535306fc71f2e8b",
            )
            .unwrap(),
            storage_location: "s3@test-location-123".to_owned(),
            expected_announcement_digest: hex::decode(
                "0733ba7dec612f80f4f0694f18605356ed5b81a55e264fed18f1454ed93150af",
            )
            .unwrap(),
        },
        SignatureGenerationData {
            mailbox_id: ContractId::from_str(
                "0x8ca1704b7319911cc5c5b8646098ae8be23b4f99ba8bd2ff0e2aa6ec612ee94c",
            )
            .unwrap(),
            expected_domain_hash: hex::decode(
                "a7b8f97f47df0289638ae37f70a1915d816046968eb86ee4e5bfcccc67808aef",
            )
            .unwrap(),
            storage_location: "s3@test-location-456".to_owned(),
            expected_announcement_digest: hex::decode(
                "a1eed844bcd579ddf9413a2259d2128f89851e3bbaaca47f44a1fbcfa3797897",
            )
            .unwrap(),
        },
        SignatureGenerationData {
            mailbox_id: ContractId::from_str(
                "0x0283771fd0c98a35138244a70d8f663b55aceaaf7e095e9b503c0f7e0f5aca60",
            )
            .unwrap(),
            expected_domain_hash: hex::decode(
                "e362658ffe1bb3a8218217f48a9e0d1f213b6624d9f0b48dcbe789b322263f7c",
            )
            .unwrap(),
            storage_location: "s3@test-location-789".to_owned(),
            expected_announcement_digest: hex::decode(
                "5e10170422e19738bce465aeeb4abebd1bbfef5905b9aaf80ca75978b025c36d",
            )
            .unwrap(),
        },
        SignatureGenerationData {
            mailbox_id: ContractId::from_str(
                "0x37971c00dbcc46e364e8e97886f48a110b2f3cacf02f24c7df4686395d8d2aa2",
            )
            .unwrap(),
            expected_domain_hash: hex::decode(
                "4ee2b8cac076a2f6eb3a65e8e7434d393f08c2a81353df02bdb1be252b25dc26",
            )
            .unwrap(),
            storage_location: "s3@test-location-420".to_owned(),
            expected_announcement_digest: hex::decode(
                "ff97e8eec083d6a00aefdbdfc5e43c8c6a169219505435e6a8f4a18dbe675b68",
            )
            .unwrap(),
        },
    ]
}

fn convert_signer_address_to_evm_address(signer_address: Address) -> EvmAddress {
    let mut address_data = [0u8; 32];
    let signer_address = signer_address.0 .0;
    address_data[12..].copy_from_slice(&signer_address);

    EvmAddress::from(Bits256(address_data))
}

fn vec_to_fixed_bytes_32(vec: Vec<u8>) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&vec);
    FixedBytes(bytes)
}

fn get_announcement_digest(storage_location: String, mut encoded_domain_hash: Vec<u8>) -> [u8; 32] {
    let encoder = ABIEncoder::default();
    let encoded_storage_location = encoder
        .encode(&[Token::RawSlice(storage_location.as_bytes().to_vec())])
        .unwrap();
    let encoded_storage_location = &encoded_storage_location[8..].to_vec(); // cut off length encoding

    encoded_domain_hash.extend(encoded_storage_location);

    let mut hasher = Keccak256::new();
    hasher.update(encoded_domain_hash);
    hasher.finalize().0
}

fn domain_hash(mailbox_id: ContractId) -> Vec<u8> {
    let encoder = ABIEncoder::default();

    let domain = 0x6675656c; // "fuel"
    let postfix = "HYPERLANE_ANNOUNCEMENT".as_bytes().to_vec();
    let mut encoded_domain_start = encoder
        .encode(&[Token::U32(domain), mailbox_id.into_token()])
        .unwrap();

    let encoded_postfix = encoder.encode(&[Token::RawSlice(postfix)]).unwrap();
    let encoded_postfix = &encoded_postfix[8..].to_vec(); // cut off length encoding

    encoded_domain_start.extend(encoded_postfix);

    let mut hasher = Keccak256::new();
    hasher.update(encoded_domain_start);
    hasher.finalize().0.to_vec()
}

async fn get_contract_instance(
    index: u64,
) -> (ValidatorAnnounce<WalletUnlocked>, SignatureGenerationData) {
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

    let test_data = &get_signature_generation_data()[index as usize];
    let mailbox_id = test_data.mailbox_id;
    let configurables = ValidatorAnnounceConfigurables::default()
        .with_MAILBOX_ID(mailbox_id)
        .unwrap();

    let id = Contract::load_from(
        "./out/debug/validator-announce.bin",
        LoadConfiguration::default().with_configurables(configurables),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let va_instance = ValidatorAnnounce::new(id.clone(), wallet);

    (va_instance, test_data.clone())
}

// ----------------------------------------------------------------------------
// -------------------------------- Announce ----------------------------------
// ----------------------------------------------------------------------------

#[tokio::test]
async fn announce_success() {
    for index in 0..4 {
        let (va_contract, test_data) = get_contract_instance(index).await;

        let domain_hash = domain_hash(test_data.mailbox_id);
        assert_eq!(domain_hash, test_data.expected_domain_hash);

        let alloy_signer = PrivateKeySigner::random();
        let signer_address = convert_signer_address_to_evm_address(alloy_signer.address());

        let announcement_digest =
            get_announcement_digest(test_data.storage_location.clone(), domain_hash);

        assert_eq!(
            eip191_hash_message(FixedBytes(announcement_digest)),
            B256::from(vec_to_fixed_bytes_32(
                test_data.expected_announcement_digest
            ))
        );

        let signature = alloy_signer
            .sign_message(&announcement_digest)
            .await
            .unwrap();

        let announcement_res = va_contract
            .methods()
            .announce(
                signer_address,
                test_data.storage_location.clone(),
                Bytes(signature.as_bytes().to_vec()),
            )
            .call()
            .await
            .unwrap();

        assert!(announcement_res.value);

        let log = announcement_res
            .decode_logs_with_type::<ValidatorAnnouncementEvent>()
            .unwrap();
        let log = log[0].clone(); // There should only be one log

        assert_eq!(log.validator, signer_address);
        assert_eq!(log.storage_location, test_data.storage_location);
    }
}

#[tokio::test]
async fn announce_replay() {
    let (va_contract, test_data) = get_contract_instance(0).await;

    let domain_hash = domain_hash(test_data.mailbox_id);

    let alloy_signer = PrivateKeySigner::random();
    let signer_address = convert_signer_address_to_evm_address(alloy_signer.address());

    let announcement_digest =
        get_announcement_digest(test_data.storage_location.clone(), domain_hash);

    let signature = alloy_signer
        .sign_message(&announcement_digest)
        .await
        .unwrap();

    let announcement_res = va_contract
        .methods()
        .announce(
            signer_address,
            test_data.storage_location.clone(),
            Bytes(signature.as_bytes().to_vec()),
        )
        .call()
        .await
        .unwrap();

    assert!(announcement_res.value);

    let announcement_err = va_contract
        .methods()
        .announce(
            signer_address,
            test_data.storage_location.clone(),
            Bytes(signature.as_bytes().to_vec()),
        )
        .call()
        .await
        .unwrap_err();

    if let Error::Transaction(Reason::Reverted { reason, .. }) = announcement_err {
        assert_eq!(reason, "ReplayAnnouncement");
    } else {
        panic!("Expected revert error");
    }
}

#[tokio::test]
async fn announce_invalid_signer() {
    let (va_contract, test_data) = get_contract_instance(0).await;

    let domain_hash = domain_hash(test_data.mailbox_id);

    let alloy_signer = PrivateKeySigner::random();
    let signer_address = convert_signer_address_to_evm_address(alloy_signer.address());

    let announcement_digest =
        get_announcement_digest(test_data.storage_location.clone(), domain_hash);

    let signature = alloy_signer
        .sign_message(&announcement_digest)
        .await
        .unwrap();

    let announcement_res = va_contract
        .methods()
        .announce(
            signer_address,
            test_data.storage_location.clone(),
            Bytes(signature.as_bytes().to_vec()),
        )
        .call()
        .await
        .unwrap();

    assert!(announcement_res.value);

    let invalid_signer = EvmAddress::from(Bits256([0u8; 32]));

    let announcement_err = va_contract
        .methods()
        .announce(
            invalid_signer,
            test_data.storage_location.clone(),
            Bytes(signature.as_bytes().to_vec()),
        )
        .call()
        .await
        .unwrap_err();

    if let Error::Transaction(Reason::Reverted { reason, .. }) = announcement_err {
        assert_eq!(reason, "ValidatorNotSigner");
    } else {
        panic!("Expected revert error");
    }
}

#[tokio::test]
async fn announce_invalid_signature() {
    let (va_contract, test_data) = get_contract_instance(0).await;

    let domain_hash = domain_hash(test_data.mailbox_id);

    let alloy_signer = PrivateKeySigner::random();
    let signer_address = convert_signer_address_to_evm_address(alloy_signer.address());

    let announcement_digest =
        get_announcement_digest(test_data.storage_location.clone(), domain_hash);

    let signature = alloy_signer
        .sign_message(&announcement_digest)
        .await
        .unwrap();

    let invalid_signature = signature
        .clone()
        .as_bytes()
        .iter()
        .copied()
        .rev()
        .collect::<Vec<u8>>();

    let announcement_err = va_contract
        .methods()
        .announce(
            signer_address,
            test_data.storage_location.clone(),
            Bytes(invalid_signature),
        )
        .call()
        .await
        .unwrap_err();

    if let Error::Transaction(Reason::Reverted { reason, .. }) = announcement_err {
        // Depending what type of invalid signature is provided, the error can be either of these
        // Making the invalid signature by reversing the bytes is just one example which can yield different errors
        let possible_errors = ["ValidatorNotSigner", "Revert(0)"];
        assert!(possible_errors.contains(&reason.as_str()));
    } else {
        panic!("Expected revert error");
    }
}

// ----------------------------------------------------------------------------
// ------------------------- Get Announced Validators -------------------------
// ----------------------------------------------------------------------------

#[tokio::test]
async fn get_announced_validators() {
    let (va_contract, test_data) = get_contract_instance(0).await;

    let domain_hash = domain_hash(test_data.mailbox_id);

    let alloy_signer = PrivateKeySigner::random();
    let signer_address = convert_signer_address_to_evm_address(alloy_signer.address());
    let mut expected_announced_validators = vec![signer_address];

    let announcement_digest =
        get_announcement_digest(test_data.storage_location.clone(), domain_hash.clone());

    let signature = alloy_signer
        .sign_message(&announcement_digest)
        .await
        .unwrap();

    let announcement_res = va_contract
        .methods()
        .announce(
            signer_address,
            test_data.storage_location.clone(),
            Bytes(signature.as_bytes().to_vec()),
        )
        .call()
        .await
        .unwrap();

    assert!(announcement_res.value);

    let announced_validators = va_contract
        .methods()
        .get_announced_validators()
        .call()
        .await
        .unwrap()
        .value;

    for (i, validator) in announced_validators.iter().enumerate() {
        assert_eq!(
            EvmAddress::from(*validator),
            expected_announced_validators[i]
        );
    }

    // Add another validator
    let alloy_signer = PrivateKeySigner::random();
    let signer_address = convert_signer_address_to_evm_address(alloy_signer.address());
    expected_announced_validators.push(signer_address);

    let announcement_digest =
        get_announcement_digest(test_data.storage_location.clone(), domain_hash);

    let signature = alloy_signer
        .sign_message(&announcement_digest)
        .await
        .unwrap();

    let announcement_res = va_contract
        .methods()
        .announce(
            signer_address,
            test_data.storage_location.clone(),
            Bytes(signature.as_bytes().to_vec()),
        )
        .call()
        .await
        .unwrap();

    assert!(announcement_res.value);

    let announced_validators = va_contract
        .methods()
        .get_announced_validators()
        .call()
        .await
        .unwrap()
        .value;

    for (i, validator) in announced_validators.iter().enumerate() {
        assert_eq!(
            EvmAddress::from(*validator),
            expected_announced_validators[i]
        );
    }
}

// ----------------------------------------------------------------------------
// ------------------------- Get Announced Storage Locations ------------------
// ----------------------------------------------------------------------------

#[tokio::test]
async fn get_announced_storage_locations_one_validator() {
    let (va_contract, test_data) = get_contract_instance(0).await;

    let storage_locations = get_signature_generation_data()
        .iter()
        .map(|data| data.storage_location.clone())
        .collect::<Vec<String>>();

    let alloy_signer = PrivateKeySigner::random();
    let signer_address = convert_signer_address_to_evm_address(alloy_signer.address());

    // Announce all storage locations

    for storage_location in storage_locations.iter() {
        let domain_hash = domain_hash(test_data.mailbox_id);

        let announcement_digest =
            get_announcement_digest(storage_location.clone(), domain_hash.clone());

        let signature = alloy_signer
            .sign_message(&announcement_digest)
            .await
            .unwrap();

        let announcement_res = va_contract
            .methods()
            .announce(
                signer_address,
                storage_location.clone(),
                Bytes(signature.as_bytes().to_vec()),
            )
            .call()
            .await
            .unwrap();

        assert!(announcement_res.value);
    }

    let announced_storage_locations = va_contract
        .methods()
        .get_announced_storage_locations(vec![signer_address.value()])
        .call()
        .await
        .unwrap()
        .value;
    let announced_storage_locations = announced_storage_locations[0].clone(); // Since we only queried for one validator

    for (i, storage_location) in announced_storage_locations.iter().enumerate() {
        assert_eq!(*storage_location, storage_locations[i]);
    }
}

#[tokio::test]
async fn get_announced_storage_locations_four_validators() {
    let (va_contract, test_data) = get_contract_instance(0).await;

    let storage_locations = get_signature_generation_data()
        .iter()
        .map(|data| data.storage_location.clone())
        .collect::<Vec<String>>();

    // Announce all storage locations
    let mut validator_addresses = vec![];

    for storage_location in storage_locations.iter() {
        let domain_hash = domain_hash(test_data.mailbox_id);

        let announcement_digest =
            get_announcement_digest(storage_location.clone(), domain_hash.clone());

        let alloy_signer = PrivateKeySigner::random();
        let signer_address = convert_signer_address_to_evm_address(alloy_signer.address());
        validator_addresses.push(signer_address);

        let signature = alloy_signer
            .sign_message(&announcement_digest)
            .await
            .unwrap();

        let announcement_res = va_contract
            .methods()
            .announce(
                signer_address,
                storage_location.clone(),
                Bytes(signature.as_bytes().to_vec()),
            )
            .call()
            .await
            .unwrap();

        assert!(announcement_res.value);
    }

    let announced_storage_locations = va_contract
        .methods()
        .get_announced_storage_locations(validator_addresses.iter().map(|v| v.value()).collect())
        .call()
        .await
        .unwrap()
        .value;

    for (i, storage_location) in announced_storage_locations.iter().enumerate() {
        let storage_location = storage_location.clone()[0].clone(); // Since we only announced one storage location per validator
        assert_eq!(*storage_location, storage_locations[i]);
    }
}
