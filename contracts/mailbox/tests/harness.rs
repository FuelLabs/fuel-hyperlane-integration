use std::str::FromStr;

use fuels::{
    prelude::*,
    types::{Bits256, Bytes, Identity},
};
use hyperlane_core::{Encode, HyperlaneMessage as HyperlaneAgentMessage, H256};

use test_utils::{
    bits256_to_h256, funded_wallet_with_private_key, get_revert_reason, h256_to_bits256,
};

// Load abi from json
abigen!(
    Contract(
        name = "Mailbox",
        abi = "contracts/mailbox/out/debug/mailbox-abi.json"
    ),
    Contract(
        name = "MsgRecipient",
        abi = "contracts/test/msg-recipient-test/out/debug/msg-recipient-test-abi.json"
    ),
    Contract(
        name = "PostDispatchMock",
        abi = "contracts/mocks/mock-post-dispatch/out/debug/mock-post-dispatch-abi.json",
    ),
    Contract(
        name = "TestInterchainSecurityModule",
        abi = "contracts/test/ism-test/out/debug/ism-test-abi.json",
    ),
);

const NON_OWNER_PRIVATE_KEY: &str =
    "0xde97d8624a438121b86a1956544bd72ed68cd69f2c99555b08b1e8c51ffd511c";

const TEST_LOCAL_DOMAIN: u32 = 0x6675656cu32;
const TEST_REMOTE_DOMAIN: u32 = 0x112233cu32;
const TEST_RECIPIENT: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn get_contract_instance() -> (
    Mailbox<WalletUnlocked>,
    ContractId,
    Bech32ContractId,
    Bech32ContractId,
    Bech32ContractId,
) {
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

    let mailbox_id = Contract::load_from("./out/debug/mailbox.bin", LoadConfiguration::default())
        .unwrap()
        .deploy(&wallet, TxPolicies::default())
        .await
        .unwrap();

    let post_dispatch_id = Contract::load_from(
        "../mocks/mock-post-dispatch/out/debug/mock-post-dispatch.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let recipient_id = Contract::load_from(
        "../test/msg-recipient-test/out/debug/msg-recipient-test.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let default_ism_id = Contract::load_from(
        "../test/ism-test/out/debug/ism-test.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let mailbox_instance = Mailbox::new(mailbox_id.clone(), wallet.clone());
    let post_dispatch = PostDispatchMock::new(post_dispatch_id.clone(), wallet.clone());

    let wallet_identity = Identity::from(wallet.address());
    let post_dispatch_address = Bits256(ContractId::from(post_dispatch.id()).into());

    let init_res = mailbox_instance
        .methods()
        .initialize(
            wallet_identity,
            post_dispatch_address,
            post_dispatch_address,
            post_dispatch_address,
        )
        .call()
        .await;
    assert!(init_res.is_ok(), "Failed to initialize Mailbox.");

    let set_ism_res = mailbox_instance
        .methods()
        .set_default_ism(default_ism_id.clone())
        .call()
        .await;
    assert!(set_ism_res.is_ok(), "Failed to set default ISM.");

    (
        mailbox_instance,
        mailbox_id.into(),
        recipient_id,
        post_dispatch_id,
        default_ism_id,
    )
}

// Gets the wallet address from the `Mailbox` instance, and
// creates a test message with that address as the sender.
pub fn test_message(
    mailbox: &Mailbox<WalletUnlocked>,
    recipient: &Bech32ContractId,
    outbound: bool,
) -> (HyperlaneAgentMessage, Bytes, ContractId) {
    let hash = mailbox.account().address().hash();
    let sender = hash.as_slice();
    let metadata_str = "0x000000000000000000000010000000950000000000000000000000007222b8b24788a79b173a42b2efa2585ed5a76198d06677e4f9f9426baf25bb5869b727d9d762e7ad0e65a0b996c8c26bdec9b4bc000000154fc320ced73551ed55147775d01afd40aa0c487e1d03492285a023a0d2f7696311b4658361ffe3e917b871e8982e0a488921076222eb5805dcd54d628e0c82981c";
    let metadata = Bytes::from_hex_str(metadata_str).unwrap();
    let hook = ContractId::default();
    let body = vec![10u8; 100];

    (
        HyperlaneAgentMessage {
            version: 3u8,
            nonce: 0u32,
            origin: if outbound {
                TEST_LOCAL_DOMAIN
            } else {
                TEST_REMOTE_DOMAIN
            },
            sender: H256::from_slice(sender),
            destination: if outbound {
                TEST_REMOTE_DOMAIN
            } else {
                TEST_LOCAL_DOMAIN
            },
            recipient: H256::from_slice(recipient.hash().as_slice()),
            body,
        },
        metadata,
        hook,
    )
}

// ============ dispatch ============
#[tokio::test]
async fn test_dispatch_too_large_message() {
    let (mailbox, _, _, _, _) = get_contract_instance().await;

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

    let reason = get_revert_reason(dispatch_err);

    assert_eq!(reason, "MessageTooLarge(6000)");
}

// ============ Dispatch Logs Message ============
#[tokio::test]
async fn test_dispatch_logs_message() {
    let (mailbox, _, recipient, _, _) = get_contract_instance().await;

    let (message, metadata, hook) = test_message(&mailbox, &recipient, true);
    let message_id = message.id();

    let dispatch_call = mailbox
        .methods()
        .dispatch(
            message.destination,
            h256_to_bits256(message.recipient),
            Bytes(message.body),
            metadata,
            hook,
        )
        .determine_missing_contracts(Some(3))
        .await
        .unwrap()
        .call()
        .await
        .unwrap();

    // Make sure the message was logged and can be constructed from the logs
    let dispatch_events = dispatch_call
        .decode_logs_with_type::<DispatchEvent>()
        .unwrap();
    let dispatch_id_events = dispatch_call
        .decode_logs_with_type::<DispatchIdEvent>()
        .unwrap();
    let dispatch_message: Vec<u8> = dispatch_events
        .first()
        .unwrap()
        .message
        .bytes
        .clone()
        .into();
    let decoded_message = HyperlaneAgentMessage::from(dispatch_message);

    assert_eq!(decoded_message.id(), message_id);
    assert_eq!(
        dispatch_id_events,
        vec![DispatchIdEvent {
            message_id: h256_to_bits256(message_id),
        }],
    );

    // Also make sure the DispatchIdEvent was logged
    let dispatch_id_events = dispatch_call
        .decode_logs_with_type::<DispatchIdEvent>()
        .unwrap();

    assert_eq!(
        dispatch_id_events,
        vec![DispatchIdEvent {
            message_id: h256_to_bits256(message_id),
        }],
    );
}

// ============ Dispatch Returns Id ============
#[tokio::test]
async fn test_dispatch_returns_id() {
    let (mailbox, _, recipient, _, _) = get_contract_instance().await;

    let (message, metadata, hook) = test_message(&mailbox, &recipient, true);
    let id = message.id();

    let dispatch_call = mailbox
        .methods()
        .dispatch(
            message.destination,
            h256_to_bits256(message.recipient),
            Bytes(message.body),
            metadata,
            hook,
        )
        .determine_missing_contracts(Some(3))
        .await
        .unwrap()
        .call()
        .await
        .unwrap();

    assert_eq!(bits256_to_h256(dispatch_call.value), id);
}

// ============ Dispatch Reverts If Paused ============
#[tokio::test]
async fn test_dispatch_reverts_if_paused() {
    let (mailbox, _, _, post_dispatch_id, _) = get_contract_instance().await;

    // First pause...
    mailbox.methods().pause().call().await.unwrap();

    let call = mailbox
        .methods()
        .dispatch(
            TEST_REMOTE_DOMAIN,
            Bits256::from_hex_str(TEST_RECIPIENT).unwrap(),
            Bytes(vec![10u8; 100]),
            Bytes::from_hex_str("0x01").unwrap(),
            post_dispatch_id,
        )
        .call()
        .await;
    assert!(call.is_err());

    assert_eq!(get_revert_reason(call.unwrap_err()), "Paused");
}

// ============ Process ============

#[tokio::test]
async fn test_process_event() {
    let (mailbox, _, recipient, _, _) = get_contract_instance().await;

    let (message, metadata, _) = test_message(&mailbox, &recipient, false);

    let process_call = mailbox
        .methods()
        .process(metadata, Bytes(message.to_vec()))
        .with_tx_policies(TxPolicies::default())
        .determine_missing_contracts(Some(3))
        .await
        .unwrap()
        .call()
        .await
        .unwrap();

    // Make sure the ProcessEvent was logged
    let process_events = process_call
        .decode_logs_with_type::<ProcessEvent>()
        .unwrap();

    let process_id_event = process_call
        .decode_logs_with_type::<ProcessIdEvent>()
        .unwrap();

    assert_eq!(
        process_events,
        vec![ProcessEvent {
            origin: message.origin,
            sender: h256_to_bits256(message.sender),
            recipient: h256_to_bits256(message.recipient),
        }],
    );

    assert_eq!(
        process_id_event,
        vec![ProcessIdEvent {
            message_id: h256_to_bits256(message.id()),
        }],
    );
}

// ============ Process Handled ============
#[tokio::test]
async fn test_process_handled() {
    let (mailbox, _, recipient, _, ism_id) = get_contract_instance().await;

    let (message, metadata, _) = test_message(&mailbox, &recipient, false);

    mailbox
        .methods()
        .process(metadata, Bytes(message.to_vec()))
        .with_tx_policies(TxPolicies::default())
        .with_contract_ids(&[recipient.clone(), ism_id])
        .call()
        .await
        .unwrap();

    let msg_recipient = MsgRecipient::new(recipient, mailbox.account());
    let handled = msg_recipient
        .methods()
        .handled()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap();
    assert!(handled.value);
}

// ============ Process Deliver Twice ============
#[tokio::test]
async fn test_process_deliver_twice() {
    let (mailbox, _, recipient, _, _) = get_contract_instance().await;

    let (message, metadata, _) = test_message(&mailbox, &recipient, false);

    mailbox
        .methods()
        .process(metadata.clone(), Bytes(message.to_vec()))
        .with_tx_policies(TxPolicies::default())
        .determine_missing_contracts(Some(3))
        .await
        .unwrap()
        .call()
        .await
        .unwrap();

    let delivered: bool = mailbox
        .methods()
        .delivered(h256_to_bits256(message.id()))
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert!(delivered);

    let process_delivered_error = mailbox
        .methods()
        .process(metadata, Bytes(message.to_vec()))
        .with_tx_policies(TxPolicies::default())
        .determine_missing_contracts(Some(3))
        .await
        .unwrap_err();

    assert_eq!(
        get_revert_reason(process_delivered_error),
        "MessageAlreadyDelivered"
    );
}

// ============ Process ISM Reject ============
#[tokio::test]
async fn test_process_ism_reject() {
    let (mailbox, _, recipient, _, default_ism) = get_contract_instance().await;

    let (message, metadata, _) = test_message(&mailbox, &recipient, false);

    let test_ism = TestInterchainSecurityModule::new(default_ism.clone(), mailbox.account());
    test_ism.methods().set_accept(false).call().await.unwrap();

    let process_call_error = mailbox
        .methods()
        .process(metadata, Bytes(message.to_vec()))
        .with_tx_policies(TxPolicies::default())
        .determine_missing_contracts(Some(3))
        .await
        .unwrap_err();

    assert_eq!(
        get_revert_reason(process_call_error),
        "MessageVerificationFailed"
    );
}

// ============ Process Reverts If Paused ============
#[tokio::test]
async fn test_process_reverts_if_paused() {
    let (mailbox, _, recipient, _, _) = get_contract_instance().await;

    // Pause the contract
    mailbox.methods().pause().call().await.unwrap();

    let (message, metadata, _) = test_message(&mailbox, &recipient, true);

    let process_call_error = mailbox
        .methods()
        .process(metadata, Bytes(message.to_vec()))
        .with_tx_policies(TxPolicies::default())
        .determine_missing_contracts(Some(3))
        .await
        .unwrap_err();

    assert_eq!(get_revert_reason(process_call_error), "Paused");
}

// ============ Pause ============

#[tokio::test]
async fn test_pause() {
    let (mailbox, _, _, _, _) = get_contract_instance().await;

    mailbox.methods().pause().call().await.unwrap();

    let paused: bool = mailbox
        .methods()
        .is_paused()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert!(paused);
}

// ============ Pause Reverts If Not Owner ============
#[tokio::test]
async fn test_pause_reverts_if_not_owner() {
    let (mailbox, _, _, _, _) = get_contract_instance().await;

    let non_owner_wallet =
        funded_wallet_with_private_key(&mailbox.account(), NON_OWNER_PRIVATE_KEY).await;

    let call = mailbox
        .with_account(non_owner_wallet)
        .methods()
        .pause()
        .call()
        .await;

    assert!(call.is_err());
    assert_eq!(get_revert_reason(call.err().unwrap()), "NotOwner");
}

// ============ Unpause ============

#[tokio::test]
async fn test_unpause() {
    let (mailbox, _, _, _, _) = get_contract_instance().await;

    // First pause...
    mailbox.methods().pause().call().await.unwrap();

    // Now unpause!
    mailbox.methods().unpause().call().await.unwrap();

    let paused: bool = mailbox
        .methods()
        .is_paused()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert!(!paused);
}

// ============ Unpause Reverts If Not Owner ============
#[tokio::test]
async fn test_unpause_reverts_if_not_owner() {
    let (mailbox, _, _, _, _) = get_contract_instance().await;

    let non_owner_wallet =
        funded_wallet_with_private_key(&mailbox.account(), NON_OWNER_PRIVATE_KEY).await;

    // First pause...
    mailbox.methods().pause().call().await.unwrap();

    let call = mailbox
        .with_account(non_owner_wallet.clone())
        .methods()
        .unpause()
        .call()
        .await;

    assert!(call.is_err());
    assert_eq!(get_revert_reason(call.err().unwrap()), "NotOwner");
}

// ============ Recipient Ism ============

#[tokio::test]
async fn test_recipient_ism() {
    let (mailbox, _, recipient, _, default_ism) = get_contract_instance().await;

    let msg_recipient = MsgRecipient::new(recipient, mailbox.account());
    let set_ism = msg_recipient
        .methods()
        .interchain_security_module()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap();
    assert!(set_ism.value == ContractId::zeroed());

    msg_recipient
        .methods()
        .set_ism(default_ism.clone())
        .call()
        .await
        .unwrap();

    let set_ism = msg_recipient
        .methods()
        .interchain_security_module()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap();

    assert_eq!(set_ism.value, default_ism.into());
}

// ============ Set Default Ism ============

#[tokio::test]
async fn test_set_default_ism() {
    let (mailbox, _, _, _, _) = get_contract_instance().await;

    // Sanity check the current default ISM is the one we expect
    let default_ism = mailbox
        .methods()
        .default_ism()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(default_ism, default_ism);

    let new_default_ism =
        ContractId::from_str("0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
            .unwrap();
    assert_ne!(default_ism, new_default_ism);

    let call = mailbox
        .methods()
        .set_default_ism(new_default_ism)
        .call()
        .await
        .unwrap();
    // Ensure the event was logged
    assert_eq!(
        call.decode_logs_with_type::<DefaultIsmSetEvent>().unwrap(),
        vec![DefaultIsmSetEvent {
            module: new_default_ism,
        }]
    );

    // And make sure the default ISM was really updated
    let default_ism = mailbox
        .methods()
        .default_ism()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(default_ism, new_default_ism);
}

// ============ Set Default Ism Reverts If Not Owner ============
#[tokio::test]
async fn test_set_default_ism_reverts_if_not_owner() {
    let (mailbox, _, _, _, _) = get_contract_instance().await;
    let new_default_ism =
        ContractId::from_str("0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
            .unwrap();

    let non_owner_wallet =
        funded_wallet_with_private_key(&mailbox.account(), NON_OWNER_PRIVATE_KEY).await;

    let call = mailbox
        .with_account(non_owner_wallet)
        .methods()
        .set_default_ism(new_default_ism)
        .call()
        .await;

    assert!(call.is_err());
    assert_eq!(get_revert_reason(call.err().unwrap()), "NotOwner",);
}

// ============ Set Default Hook ============

#[tokio::test]
async fn test_set_default_hook() {
    let (mailbox, _, _, post_dispatch_id, _) = get_contract_instance().await;

    // Sanity check the current default hook is the one we expect
    let default_hook = mailbox
        .methods()
        .default_hook()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(default_hook, post_dispatch_id.into());

    let new_default_hook =
        ContractId::from_str("0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
            .unwrap();

    let call = mailbox
        .methods()
        .set_default_hook(new_default_hook)
        .call()
        .await
        .unwrap();
    // Ensure the event was logged
    assert_eq!(
        call.decode_logs_with_type::<DefaultHookSetEvent>().unwrap(),
        vec![DefaultHookSetEvent {
            module: new_default_hook,
        }]
    );

    // And make sure the default hook was really updated
    let default_hook = mailbox
        .methods()
        .default_hook()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(default_hook, new_default_hook);
}

// ============ Set Default Hook Reverts If Not Owner ============
#[tokio::test]
async fn test_set_default_hook_reverts_if_not_owner() {
    let (mailbox, _, _, _, _) = get_contract_instance().await;
    let new_default_hook =
        ContractId::from_str("0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
            .unwrap();

    let non_owner_wallet =
        funded_wallet_with_private_key(&mailbox.account(), NON_OWNER_PRIVATE_KEY).await;

    let call = mailbox
        .with_account(non_owner_wallet)
        .methods()
        .set_default_hook(new_default_hook)
        .call()
        .await;

    assert!(call.is_err());
    assert_eq!(get_revert_reason(call.err().unwrap()), "NotOwner",);
}

// ============ Set Required Hook ============

#[tokio::test]
async fn test_set_required_hook() {
    let (mailbox, _, _, _, _) = get_contract_instance().await;

    let new_required_hook =
        ContractId::from_str("0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
            .unwrap();

    let call = mailbox
        .methods()
        .set_required_hook(new_required_hook)
        .call()
        .await
        .unwrap();
    // Ensure the event was logged
    assert_eq!(
        call.decode_logs_with_type::<RequiredHookSetEvent>()
            .unwrap(),
        vec![RequiredHookSetEvent {
            module: new_required_hook,
        }]
    );

    // And make sure the required hook was really updated
    let required_hook = mailbox
        .methods()
        .required_hook()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert_eq!(required_hook, new_required_hook);
}

// ============ Set Required Hook Reverts If Not Owner ============
#[tokio::test]
async fn test_set_required_hook_reverts_if_not_owner() {
    let (mailbox, _, _, _, _) = get_contract_instance().await;
    let new_required_hook =
        ContractId::from_str("0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
            .unwrap();

    let non_owner_wallet =
        funded_wallet_with_private_key(&mailbox.account(), NON_OWNER_PRIVATE_KEY).await;

    let call = mailbox
        .with_account(non_owner_wallet)
        .methods()
        .set_required_hook(new_required_hook)
        .call()
        .await;

    assert!(call.is_err());
    assert_eq!(get_revert_reason(call.err().unwrap()), "NotOwner",);
}
