use std::str::FromStr;

use alloy_primitives::FixedBytes;
use alloy_signer::{k256::ecdsa::SigningKey, Signature, Signer};
use alloy_signer_local::{LocalSigner, PrivateKeySigner};
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

async fn sign_digest(digest: H256) -> (String, LocalSigner<SigningKey>, Bytes) {
    let alloy_signer = PrivateKeySigner::random();

    println!("digest that we are signing length: {:?}", digest.0.len());
    let signed_digest = alloy_signer.sign_message(digest.as_bytes()).await.unwrap();

    assert_eq!(digest.0.as_slice(), digest.as_bytes());

    let alloy_recovered_address = signed_digest.recover_address_from_msg(digest.0).unwrap();
    let alloy_recovered_address = alloy_recovered_address.into_word().0;
    let signer_address = alloy_signer.address().into_word().0;
    println!("signer_address: {:?}", signer_address);
    println!("alloy_recovered_address: {:?}", alloy_recovered_address);

    // XXX testing

    let ddigest = digest.0;
    println!("ddigest as slice: {:?}", ddigest.as_slice());
    let ssignature = Signature::try_from(signed_digest.as_bytes().as_slice()).unwrap();
    println!(
        "ssignature as slice: {:?}",
        ssignature.as_bytes().as_slice()
    );

    let rec_from_string = ssignature
        .recover_address_from_prehash(&FixedBytes::from(ddigest))
        .unwrap();
    println!("rec_from_string: {:?}", rec_from_string.into_word().0);

    // XXX testing

    // Convert r, s, and v to hexadecimal format
    let r_hex = format!("{:064x}", signed_digest.r());
    let s_hex = format!("{:064x}", signed_digest.s());
    let v_hex = format!(
        "{:02x}",
        (signed_digest.v().y_parity_byte_non_eip155().unwrap())
    );
    let v_not_hex = format!(
        "{:02}",
        (signed_digest.v().y_parity_byte_non_eip155().unwrap())
    );

    println!("r (hex): {}", r_hex);
    println!("s (hex): {}", s_hex);
    println!("v (hex): {}", v_hex);
    println!("v (not hex): {}", v_not_hex);

    let signature = format!("{}{}{}", r_hex, s_hex, v_hex);

    // Convert the signature into a Bytes object
    let hex = format!("0x{}", signature);
    println!("signature: {:?}", signature);
    let signature_bytes = Bytes::from_hex_str(&hex).unwrap();
    println!("signature_bytes: {:?}", signature_bytes);
    println!("signature_bytes.len(): {:?}", signature_bytes.0.len());

    let sig_slice: &[u8] = &signature_bytes.0;
    let const_sig = Signature::try_from(sig_slice).unwrap();
    let const_recovers = const_sig.recover_address_from_msg(digest.0).unwrap();
    println!("const_recovers: {:?}", const_recovers.into_word().0);

    // Assuming append_signature_to_test_metadata is a function that takes a signature and returns Bytes
    let metadata = append_signatures_to_test_metadata(vec![signature.clone()]);

    (signature, alloy_signer, metadata)
}

fn append_signatures_to_test_metadata(signatures: Vec<String>) -> Bytes {
    // origin_merkle_tree_address = "0x1111111111111111111111111111111111111111111111111111111111111111";
    // signed_checkpoint_root = "0x2222222222222222222222222222222222222222222222222222222222222222";
    // signed_checkpoint_index = "0x00000001";
    // validator_signatures =  None, will be appended
    let test_metadata = "0x1111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222200000001";
    let mut appended_metadata = test_metadata.to_string();

    for signature in signatures {
        appended_metadata.push_str(&signature);
    }

    println!("appended_metadata: {:?}", appended_metadata);
    Bytes::from_hex_str(&appended_metadata).unwrap()
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
async fn verify_single_validator_success() {
    let (ism, _) = get_contract_instance().await;

    ism.methods().set_threshold(1).call().await.unwrap();

    let (messages, metadata, expected_digests, _) = message_id_test_data();

    let message = messages[0].clone();
    let message_bytes = Bytes(RawHyperlaneMessage::from(&message));
    // println!("message_bytes: {:?}", message_bytes);
    println!("message id: {:?}", message.id());
    println!("message origin: {:?}", message.origin);

    let digest = expected_digests[0];
    let digest_from_contract = ism
        .methods()
        .digest(metadata[0].clone(), message_bytes.clone())
        .call()
        .await
        .unwrap()
        .value;

    println!("digest: {:?}", digest.0);
    println!("digest_from_contract: {:?}", digest_from_contract);

    assert_eq!(
        digest,
        H256(
            Bytes32::try_from(digest_from_contract.0.as_slice())
                .unwrap()
                .into()
        )
    );

    let (_, signer, metadata_with_signature) = sign_digest(digest).await;

    println!("metadata_with_signature: {:?}", metadata_with_signature);

    let digest_from_contract_2 = ism
        .methods()
        .digest(metadata_with_signature.clone(), message_bytes)
        .call()
        .await
        .unwrap()
        .value;

    assert_eq!(
        digest_from_contract, digest_from_contract_2,
        "Digests should match"
    );
    println!("digest_from_contract_2: {:?}", digest_from_contract_2);

    // println!("address: {}", H256::from(signer.address().0));
    let signer_address = signer.address().into_word().0;
    // let address = EvmAddress::from(Bits256(pad_to_32_bytes(signer.address().0)));
    let address = EvmAddress::from(Bits256(signer_address));
    println!("address: {:?}", signer.address().into_word().0);
    println!("address: {:?}", address);
    ism.methods()
        .enroll_validator(address)
        .call()
        .await
        .unwrap();

    let result = ism
        .methods()
        .verify(
            metadata_with_signature,
            Bytes(RawHyperlaneMessage::from(&message)),
        )
        .call()
        .await
        .unwrap()
        .value;

    assert!(result);
}

#[tokio::test]
async fn verify_triple_validator_success() {
    let (ism, _) = get_contract_instance().await;

    ism.methods().set_threshold(3).call().await.unwrap();

    let (messages, _, expected_digests, _) = message_id_test_data();

    let message = messages[0].clone();
    let message_bytes = Bytes(RawHyperlaneMessage::from(&message));
    let digest = expected_digests[0];

    let (signature_1, signer_1, _) = sign_digest(digest).await;
    let (signature_2, signer_2, _) = sign_digest(digest).await;
    let (signature_3, signer_3, _) = sign_digest(digest).await;

    let metadata_with_signatures =
        append_signatures_to_test_metadata(vec![signature_1, signature_2, signature_3]);

    let address_1 = EvmAddress::from(Bits256(signer_1.address().into_word().0));
    let address_2 = EvmAddress::from(Bits256(signer_2.address().into_word().0));
    let address_3 = EvmAddress::from(Bits256(signer_3.address().into_word().0));

    let addresses = vec![address_1, address_2, address_3];

    for address in addresses {
        ism.methods()
            .enroll_validator(address)
            .call()
            .await
            .unwrap();
    }

    let result = ism
        .methods()
        .verify(metadata_with_signatures, message_bytes)
        .call()
        .await
        .unwrap()
        .value;

    assert!(result);
}

#[tokio::test]
async fn verify_no_threshold() {
    let (ism, _) = get_contract_instance().await;

    let (messages, _, expected_digests, _) = message_id_test_data();

    let digest = expected_digests[0];
    let message = messages[0].clone();
    let (_, signer, metadata_with_signature) = sign_digest(digest).await;

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

    let (messages, _, expected_digests, _) = message_id_test_data();

    let digest = expected_digests[0];
    let message = messages[0].clone();
    let (_, signer, _) = sign_digest(digest).await;

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

    let (messages, _, expected_digests, _) = message_id_test_data();

    let digest = expected_digests[0];
    let message = messages[0].clone();
    let (_, signer, mut metadata_with_signature) = sign_digest(digest).await;

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
