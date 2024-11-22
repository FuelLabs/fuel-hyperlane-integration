use std::str::FromStr;

use alloy_signer_local::PrivateKeySigner;
use fuels::{
    prelude::*,
    types::{errors::transaction::Reason, Bits256, Bytes32, ContractId, EvmAddress},
};
use hyperlane_core::{HyperlaneMessage, RawHyperlaneMessage, H256};

// Load abi from json
abigen!(Contract(
    name = "MessageIdMultisigIsm",
    abi =
        "contracts/ism/multisig/message-id-multisig-ism/out/debug/message-id-multisig-ism-abi.json"
));

/// Generate data to test the ISM
fn message_id_test_data() -> (Vec<HyperlaneMessage>, Vec<Bytes>, Vec<H256>, Vec<Bytes>) {
    // Determined by passing data into the Solidity function implementation
    // https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/8e942d3c6bcebcc6c16782f4d48153a1df06c353/solidity/contracts/libs/CheckpointLib.sol#L18
    let expected_digests = vec![
        // origin - 1000
        // origin_merkle_tree_hook - 0x1111111111111111111111111111111111111111111111111111111111111111
        // checkpoint_root - 0x2222222222222222222222222222222222222222222222222222222222222222
        // checkpoint_index - 1
        // message_id - 0x87aef1eedec41cf03ce02f27f11c802c5931c52c8bd58d2aa194d2183f7c0d55
        //
        H256::from_str("0x37971c00dbcc46e364e8e97886f48a110b2f3cacf02f24c7df4686395d8d2aa2")
            .unwrap(),
        // origin - 1232
        // origin_merkle_tree_hook - 0x3333333333333333333333333333333333333333333333333333333333333333
        // checkpoint_root - 0x4444444444444444444444444444444444444444444444444444444444444444
        // checkpoint_index - 2
        // message_id - 0x5c9aedf8714a9aefbc7f0386628c240ee2bf0e9c9c67821ea686bb9f472bf67d
        //
        H256::from_str("0x3fae2ed17553e31ae03178dadf0e30bfe84c616e04f0b59cd7863f09e7c26e86")
            .unwrap(),
        // origin - 567
        // origin_merkle_tree_hook - 0x5555555555555555555555555555555555555555555555555555555555555555
        // checkpoint_root - 0x6666666666666666666666666666666666666666666666666666666666666666
        // checkpoint_index - 3
        // message_id - 0x5768ba4738b9bcece99c9b1c99d605f208e592b81999ef3836b7e4f39a41c9fa
        //
        H256::from_str("0xb18f5299ac0adec272a2f5ce707e668011edbef3993ae36a7498aacf407b7eb1")
            .unwrap(),
    ];

    let origins = [1000, 1232, 567];
    let message_ids = [
        H256::from_str("0x87aef1eedec41cf03ce02f27f11c802c5931c52c8bd58d2aa194d2183f7c0d55")
            .unwrap(),
        H256::from_str("0x5c9aedf8714a9aefbc7f0386628c240ee2bf0e9c9c67821ea686bb9f472bf67d")
            .unwrap(),
        H256::from_str("0x5768ba4738b9bcece99c9b1c99d605f208e592b81999ef3836b7e4f39a41c9fa")
            .unwrap(),
    ];

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

    // Encoded Message Id ISM Metadata
    let metadata = vec![
        // origin_merkle_tree_address = "0x1111111111111111111111111111111111111111111111111111111111111111";
        // signed_checkpoint_root = "0x2222222222222222222222222222222222222222222222222222222222222222";
        // signed_checkpoint_index = "0x00000001";
        // validator_signatures = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd011a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b02";
        Bytes::from_hex_str("0x1111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222200000001abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd011a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b02")
            .unwrap(),

        // origin_merkle_tree_address = "0x3333333333333333333333333333333333333333333333333333333333333333";
        // signed_checkpoint_root = "0x4444444444444444444444444444444444444444444444444444444444444444";
        // signed_checkpoint_index = "0x00000002"; 
        // validator_signatures = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd011a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b02";
        Bytes::from_hex_str("0x3333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444400000002abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd011a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b02")
            .unwrap(),

        // origin_merkle_tree_address = "0x5555555555555555555555555555555555555555555555555555555555555555";
        // signed_checkpoint_root = "0x6666666666666666666666666666666666666666666666666666666666666666";
        // signed_checkpoint_index = "0x00000003"; 
        // validator_signatures = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd011a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b02";
        Bytes::from_hex_str("0x5555555555555555555555555555555555555555555555555555555555555555666666666666666666666666666666666666666666666666666666666666666600000003abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd011a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b02")
            .unwrap(),
    ];

    // Extracted from the ecoded metadata above
    let signatures = vec![
        Bytes::from_hex_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd01")
            .unwrap(),
        Bytes::from_hex_str("0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b02")
            .unwrap(),
    ];

    (messages_generated, metadata, expected_digests, signatures)
}

async fn get_contract_instance() -> (MessageIdMultisigIsm<WalletUnlocked>, ContractId) {
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

    let message_id_multisig_ism_id = Contract::load_from(
        "./out/debug/message-id-multisig-ism.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let message_id_multisig_ism =
        MessageIdMultisigIsm::new(message_id_multisig_ism_id.clone(), wallet);

    (message_id_multisig_ism, message_id_multisig_ism_id.into())
}

#[tokio::test]
async fn module_type() {
    let (ism, _) = get_contract_instance().await;

    let module_type = ism.methods().module_type().call().await.unwrap().value;

    assert_eq!(module_type, ModuleType::MESSAGE_ID_MULTISIG);
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

#[tokio::test]
async fn digest() {
    let (ism, _) = get_contract_instance().await;

    let (message, metadata, expected_digests, _) = message_id_test_data();

    for (index, message) in message.iter().enumerate() {
        let digest = ism
            .methods()
            .digest(
                metadata[index].clone(),
                Bytes(RawHyperlaneMessage::from(message)),
            )
            .call()
            .await
            .unwrap()
            .value;

        assert_eq!(
            H256(Bytes32::try_from(digest.0.as_slice()).unwrap().into()),
            expected_digests[index]
        );
    }
}

#[tokio::test]
async fn signature_at() {
    let (ism, _) = get_contract_instance().await;

    let (_, metadata, _, signatures) = message_id_test_data();

    let encoded_metadata = metadata[0].clone();

    let signature_1 = ism
        .methods()
        .signature_at(encoded_metadata.clone(), 0)
        .call()
        .await
        .unwrap()
        .value;

    let signature_2 = ism
        .methods()
        .signature_at(encoded_metadata, 1)
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(signature_1, signatures[0]);
    assert_eq!(signature_2, signatures[1]);
}

#[tokio::test]
async fn verify_no_threshold() {
    let (ism, _) = get_contract_instance().await;

    let (messages, _, _, _) = message_id_test_data();

    let message = messages[0].clone();
    let signer = PrivateKeySigner::random();
    let metadata_with_signature = Bytes::from_hex_str("0xa7bf5b6c33b77c058b83849c7ab0193f86bbc71d8d4b183ad89da4b9c23311eede0a5c35d109e5555d9eb485d12c283f6bccd8aaf5fede627cda4a551bf0c9fd00000005").unwrap();

    let address = EvmAddress::from(Bits256(signer.address().into_word().0));
    ism.methods()
        .enroll_validator(address)
        .call()
        .await
        .unwrap();

    let error = ism
        .methods()
        .verify(
            metadata_with_signature,
            Bytes(RawHyperlaneMessage::from(&message)),
        )
        .call()
        .await
        .unwrap_err();

    if let Error::Transaction(Reason::Reverted { reason, .. }) = error {
        assert_eq!(reason, "NoMultisigThreshold");
    } else {
        panic!("Expected NoMultisigThreshold error");
    }
}

#[tokio::test]
async fn verify_invalid_metadata_len() {
    let (ism, _) = get_contract_instance().await;

    let (messages, _, _, _) = message_id_test_data();

    let message = messages[0].clone();
    let signer = PrivateKeySigner::random();

    let address = EvmAddress::from(Bits256(signer.address().into_word().0));
    ism.methods()
        .enroll_validator(address)
        .call()
        .await
        .unwrap();

    let error = ism
        .methods()
        .verify(
            Bytes::from_hex_str("0xdeadbeef").unwrap(),
            Bytes(RawHyperlaneMessage::from(&message)),
        )
        .call()
        .await
        .unwrap_err();

    if let Error::Transaction(Reason::Reverted { reason, .. }) = error {
        assert_eq!(reason, "assertion failed");
    } else {
        panic!("Expected InvalidMetadata error");
    }
}

#[tokio::test]
async fn verify_invalid_metadata() {
    let (ism, _) = get_contract_instance().await;

    let (messages, _, _, _) = message_id_test_data();

    let message = messages[0].clone();
    let signer = PrivateKeySigner::random();
    let mut metadata_with_signature = Bytes::from_hex_str("0xa7bf5b6c33b77c058b83849c7ab0193f86bbc71d8d4b183ad89da4b9c23311eede0a5c35d109e5555d9eb485d12c283f6bccd8aaf5fede627cda4a551bf0c9fd00000005").unwrap();

    let address = EvmAddress::from(Bits256(signer.address().into_word().0));
    ism.methods()
        .enroll_validator(address)
        .call()
        .await
        .unwrap();

    metadata_with_signature.0.swap(0, 1);

    let error = ism
        .methods()
        .verify(
            Bytes::from_hex_str(
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .unwrap(),
            Bytes(RawHyperlaneMessage::from(&message)),
        )
        .call()
        .await
        .unwrap_err();

    if let Error::Transaction(Reason::Reverted { reason, .. }) = error {
        assert_eq!(reason, "assertion failed");
    } else {
        panic!("Expected InvalidMetadata error");
    }
}
