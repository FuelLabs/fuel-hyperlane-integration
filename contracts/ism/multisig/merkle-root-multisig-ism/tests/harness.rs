use std::{fmt::format, str::FromStr};

use alloy_primitives::FixedBytes;
use alloy_signer::{k256::ecdsa::SigningKey, Signature, Signer};
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use fuel_merkle::binary::in_memory::MerkleTree;
use fuels::{
    prelude::*,
    types::{message, Bits256, ContractId},
};
use futures::future::join_all;
use futures::stream::{self, StreamExt};

use hyperlane_core::{accumulator::merkle, HyperlaneMessage, RawHyperlaneMessage, H256};
use sha3::{Digest, Keccak256};
use test_utils::{get_merkle_root_ism_test_data, to_eip_191_payload};

// Load abi from json
abigen!(Contract(
    name = "MerkeRootMultisigIsm",
    abi = "contracts/ism/multisig/merkle-root-multisig-ism/out/debug/merkle-root-multisig-ism-abi.json"
),
Contract(
    name = "MerkleTest",
    abi = "contracts/test/merkle-test/out/debug/merkle-test-abi.json"
)
);

fn load_message_with_proof() {
    let test_data = get_merkle_root_ism_test_data("./tests/message_with_proof.json");
    let expected_message_id =
        H256::from_str("0x4a6a78459ac1d35b6ee94f610571f6e98b320cdf6ea7ef249cae5b8092c819df")
            .unwrap();
    assert_eq!(test_data.message.id(), expected_message_id);

    // Create valid metadata for the message and proof data.
    // Format of metadata:
    // [   0:  32] Origin merkle tree address
    // [  32:  36] Index of message ID in merkle tree
    // [  36:  68] Signed checkpoint message ID
    // [  68:1092] Merkle proof
    // [1092:1096] Signed checkpoint index (computed from proof and index)
    // [1096:????] Validator signatures (length := threshold * 65)
    //
    let origin_merkle_tree = "1111111111111111111111111111111111111111111111111111111111111111";
    let message_index_in_merkle_tree = format!("{:04x}", test_data.index);
    // the message id used for recovery to get the root is the leaf from test_data,
    // XXX figure out got to get from the regular message id to leaf
    let message_id = "4a6a78459ac1d35b6ee94f610571f6e98b320cdf6ea7ef249cae5b8092c819df";

    let merkle_proof = test_data
        .proof
        .iter()
        .map(|proof| hex::encode(proof.0))
        .collect::<Vec<String>>()
        .join("");

    println!("message id: {:?}", message_id);
    println!("message origin: {:?}", test_data.message.origin);
    println!("merkle proof: {:?}", merkle_proof);
    println!("message index: {:?}", message_index_in_merkle_tree);

    println!();
    println!("message {:?}", test_data.message);

    // XXX

    // let raw_message: RawHyperlaneMessage = vec![
    //     0, 0, 3, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 243, 159, 214, 229, 26, 173, 136, 246,
    //     244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 0, 0, 11, 184, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 115, 81, 22, 105, 253, 77, 228, 71, 254, 209, 139, 183, 155, 175, 234,
    //     201, 58, 183, 243, 31, 18, 52,
    // ];
    // let message = HyperlaneMessage::from(raw_message);
    // println!("message {:?}", message);
    let message = hex::decode("000003e8000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000bb800000000000000000000000073511669fd4de447fed18bb79bafeac93ab7f31f1234").unwrap();
    println!("message {:?}", message);
}

async fn deploy_merkle_test() -> MerkleTest<WalletUnlocked> {
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

    let merkle_test_id = Contract::load_from(
        "../../../test/merkle-test/out/debug/merkle-test.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    MerkleTest::new(merkle_test_id, wallet)
}

fn generate_test_messages() -> Vec<HyperlaneMessage> {
    let origins = vec![1000, 1232, 567];
    let message_ids = vec![
        H256::from_str("0x87aef1eedec41cf03ce02f27f11c802c5931c52c8bd58d2aa194d2183f7c0d55")
            .unwrap(),
        H256::from_str("0x5c9aedf8714a9aefbc7f0386628c240ee2bf0e9c9c67821ea686bb9f472bf67d")
            .unwrap(),
        H256::from_str("0x5768ba4738b9bcece99c9b1c99d605f208e592b81999ef3836b7e4f39a41c9fa")
            .unwrap(),
    ];

    //  1. confirm conor/nam if the merkle root testing is missing from the other implementations
    // message conor for testing data from the CI
    // 2 wait and hope for the best
    //

    // Generate messages which should match the expected message ids
    let messages_generated = (0..3)
        .map(|index| HyperlaneMessage {
            version: 3,
            nonce: index,
            origin: origins[index as usize],
            sender: H256::zero(),
            destination: origins[index as usize],
            recipient: H256::zero(),
            body: vec![],
        })
        .collect::<Vec<HyperlaneMessage>>();

    for (index, message) in messages_generated.iter().enumerate() {
        assert_eq!(message.origin, origins[index]);
        assert_eq!(message.id(), message_ids[index]);
    }
    messages_generated
}

async fn sign_and_insert_messages_to_tree(messages: Vec<HyperlaneMessage>) -> Vec<[u8; 65]> {
    let mut merkle_tree = MerkleTree::new();

    let signer = PrivateKeySigner::random();

    assert_eq!(messages.len(), 3);

    let message_id_1 = messages[0].clone().id();
    let message_id_2 = messages[1].clone().id();
    let message_id_3 = messages[2].clone().id();

    let signature_1 = signer.sign_message(message_id_1.as_bytes()).await.unwrap();
    let signature_2 = signer.sign_message(message_id_2.as_bytes()).await.unwrap();
    let signature_3 = signer.sign_message(message_id_3.as_bytes()).await.unwrap();

    let leaves = vec![
        signature_1.as_bytes(),
        signature_2.as_bytes(),
        signature_3.as_bytes(),
    ];

    for leaf in leaves.iter() {
        let mut hasher = Keccak256::new();
        hasher.update(leaf);
        let hash = hasher.finalize();
        merkle_tree.push(&hash);
    }

    for (index, message) in messages.iter().enumerate() {
        let (merkle_root, proof_set) = merkle_tree.prove(index as u64).unwrap();

        println!("Merkle root: {:?}", merkle_root);
        println!("Proof set: {:?}", proof_set);
    }

    vec![
        signature_1.as_bytes(),
        signature_2.as_bytes(),
        signature_3.as_bytes(),
    ]

    // let (merkle_root, proof_set) = merkle_tree.prove(0).unwrap();

    // println!("Merkle root: {:?}", merkle_root);
    // println!("Proof set: {:?}", proof_set);
}

/// Format of metadata:
/// [   0:  32] Origin merkle tree address
/// [  32:  36] Index of message ID in merkle tree
/// [  36:  68] Signed checkpoint message ID
/// [  68:1092] Merkle proof
/// [1092:1096] Signed checkpoint index (computed from proof and index)
/// [1096:????] Validator signatures (length := threshold * 65)
///
// const ORIGIN_MERKLE_TREE_OFFSET = 0;
// const MESSAGE_INDEX_OFFSET = 32;
// const MESSAGE_ID_OFFSET = 36;
// const MERKLE_PROOF_OFFSET = 68;
// const MERKLE_PROOF_LENGTH = 32 * 32;
// const SIGNED_INDEX_OFFSET = 1092;
// const SIGNATURES_OFFSET: u32 = 1096;
// const SIGNATURE_LENGTH: u32 = 65;
fn generate_test_metadata(messages: Vec<HyperlaneMessage>) -> Vec<Bytes> {
    let origin_merkle_tree = "1111111111111111111111111111111111111111111111111111111111111111";

    // for (index, message) in messages.iter().enumerate() {
    //     let message_id = message.id();
    //     let message_index = format!("{:0>4}", index);

    //     let metadata = format!(
    //         "0x{}{}{}{}{}{}",
    //         origin_merkle_tree, message_index, message_id, merkle_proof, signed_index, signatures
    //     );

    //     Bytes(metadata.into_bytes())
    // }

    vec![]
}

// async fn populate_merkle_tests() -> Vec<MerkleTest<WalletUnlocked>> {
//     let test_cases = get_merkle_test_cases("../../../test/merkle-test/tests/test_cases.json");

//     let mut populated_test_cases: Vec<MerkleTest<WalletUnlocked>> = vec![];
//     let test_cases_needed = 3;

//     for case in test_cases.iter() {
//         let merkle_test = deploy_merkle_test().await;
//         // Insert all the leaves
//         for leaf in case.leaves.iter() {
//             let leaf_hash = {
//                 let mut hasher = Keccak256::new();
//                 hasher.update(to_eip_191_payload(leaf));
//                 hasher.finalize()
//             };

//             // Insert the leaf hash
//             merkle_test
//                 .methods()
//                 .insert(Bits256(leaf_hash.into()))
//                 .call()
//                 .await
//                 .unwrap();
//         }

//         if populated_test_cases.len() == test_cases_needed {
//             break;
//         }

//         populated_test_cases.push(merkle_test);
//     }

//     populated_test_cases
// }

async fn get_contract_instance() -> (MerkeRootMultisigIsm<WalletUnlocked>, ContractId) {
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

    let merkle_root_multisig_id = Contract::load_from(
        "./out/debug/merkle-root-multisig-ism.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let merkle_root_multisig = MerkeRootMultisigIsm::new(merkle_root_multisig_id.clone(), wallet);

    (merkle_root_multisig, merkle_root_multisig_id.into())
}

#[tokio::test]
async fn module_type() {
    let (ism, _) = get_contract_instance().await;

    let module_type = ism.methods().module_type().call().await.unwrap().value;

    assert_eq!(module_type, ModuleType::MERKLE_ROOT_MULTISIG);
}

#[tokio::test]
async fn getters_and_setters() {
    let (ism, _) = get_contract_instance().await;

    let message = Bytes(vec![]);

    let (validators, threshold) = ism
        .methods()
        .validators_and_threshold(message.clone())
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(validators, vec![]);
    assert_eq!(threshold, 0);

    ism.methods().set_threshold(1).call().await.unwrap();
    ism.methods()
        .enroll_validator(Bits256::zeroed().into())
        .call()
        .await
        .unwrap();

    let (validators, threshold) = ism
        .methods()
        .validators_and_threshold(message)
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(validators, vec![Bits256::zeroed().into()]);
    assert_eq!(threshold, 1);
}

// #[tokio::test]
// TODO Unit testing not essential, delete if not going to be implemented
async fn digest() {
    let (ism, _) = get_contract_instance().await;

    load_message_with_proof();

    // let messages = generate_test_messages();

    // sign_and_insert_messages_to_tree(messages).await;

    // let (message, metadata, expected_digests, _) = message_id_test_data();

    // for (index, message) in message.iter().enumerate() {
    //     let digest = ism
    //         .methods()
    //         .digest(
    //             metadata[index].clone(),
    //             Bytes(RawHyperlaneMessage::from(message)),
    //         )
    //         .call()
    //         .await
    //         .unwrap()
    //         .value;

    //     assert_eq!(
    //         H256(Bytes32::try_from(digest.0.as_slice()).unwrap().into()),
    //         expected_digests[index]
    //     );
    // }
}
