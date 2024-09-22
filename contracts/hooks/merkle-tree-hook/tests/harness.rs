use fuels::{
    prelude::*,
    types::{Bits256, ContractId},
};
use hyperlane_core::HyperlaneMessage;

// Load abi from json
abigen!(
    Contract(
        name = "MailboxTest",
        abi = "contracts/test/mailbox-test/out/debug/mailbox-test-abi.json"
    ),
    Contract(
        name = "MerkleTreeHook",
        abi = "contracts/hooks/merkle-tree-hook/out/debug/merkle-tree-hook-abi.json"
    )
);

const DESTINATION: u32 = 22;
const MSG_COUNT: u32 = 3;

async fn get_contract_instance() -> (
    MailboxTest<WalletUnlocked>,
    MerkleTreeHook<WalletUnlocked>,
    ContractId,
    Bits256,
    [Bits256; 3],
    [Bytes; 3],
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

    let mailbox_id = Contract::load_from(
        "../../test/mailbox-test/out/debug/mailbox-test.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let hook_id = Contract::load_from(
        "./out/debug/merkle-tree-hook.bin",
        LoadConfiguration::default(),
    )
    .unwrap()
    .deploy(&wallet, TxPolicies::default())
    .await
    .unwrap();

    let mailbox: MailboxTest<WalletUnlocked> = MailboxTest::new(mailbox_id.clone(), wallet.clone());
    let hook = MerkleTreeHook::new(hook_id.clone(), wallet);

    hook.methods()
        .initialize(mailbox_id.clone())
        .call()
        .await
        .unwrap();

    let recipient: Bits256 =
        Bits256::from_hex_str("0x00000000000000000000000000000000000000000000000000000000deadbeef")
            .unwrap();

    // Extracted from outputs of this test when the test cases of `test/merkle-test` are passing
    let expected_roots: [Bits256; 3] = [
        Bits256([
            10, 211, 30, 37, 247, 188, 114, 145, 117, 69, 246, 186, 20, 43, 66, 153, 80, 54, 184,
            246, 4, 80, 30, 107, 218, 176, 53, 239, 4, 212, 189, 136,
        ]),
        Bits256([
            54, 81, 143, 211, 87, 64, 103, 21, 139, 110, 154, 157, 221, 10, 158, 103, 59, 203, 94,
            92, 50, 84, 178, 109, 2, 141, 181, 11, 114, 228, 148, 210,
        ]),
        Bits256([
            50, 169, 244, 205, 108, 63, 164, 213, 229, 160, 7, 67, 44, 145, 242, 96, 7, 236, 188,
            129, 92, 58, 54, 198, 169, 170, 130, 43, 46, 14, 127, 72,
        ]),
    ];

    let mut messages: [Bytes; 3] = core::array::from_fn(|_| Bytes(vec![0; 32]));
    for i in 0..MSG_COUNT {
        let body = Bytes(vec![i as u8; 32]);
        let message = mailbox
            .methods()
            .build_outbound_message(DESTINATION, recipient, body)
            .simulate(Execution::Realistic)
            .await
            .unwrap()
            .value;
        messages[i as usize] = message
    }

    (
        mailbox,
        hook,
        mailbox_id.into(),
        recipient,
        expected_roots,
        messages,
    )
}

#[tokio::test]
async fn test_hook_event_logs() {
    let (mailbox, hook, mailbox_id, _, roots, messages) = get_contract_instance().await;

    for i in 0..MSG_COUNT {
        let message = messages[i as usize].clone();
        let decoded_message = HyperlaneMessage::from(&message.0);
        let parsed_id = Bits256::from_hex_str(&format!("{:?}", decoded_message.id())).unwrap();

        // Update the latest dispatched id in the Mailbox contract
        // This would be done when dispatch is called on the mailbox
        mailbox
            .methods()
            .update_latest_dispatched_id(parsed_id)
            .call()
            .await
            .unwrap();

        let root = roots[i as usize];
        let empty_body = Bytes(vec![0]);

        // Invoke the post dispatch hook
        let post_dispatch_call = hook
            .methods()
            .post_dispatch(empty_body, message)
            .with_contract_ids(&[mailbox_id.into()])
            .call()
            .await
            .unwrap();

        // Get logs
        let post_dispatch_events = post_dispatch_call
            .decode_logs_with_type::<MerkleTreeEvent>()
            .unwrap();

        // Ensure the event is correct
        let event = post_dispatch_events.first().unwrap();
        let MerkleTreeEvent::InsertedIntoTree((id, index)) = event;

        // Ensure the id and index are correct
        assert_eq!(id, &parsed_id);
        assert_eq!(index, &i);

        let count = hook.methods().count().call().await.unwrap().value;
        let current_root = hook.methods().root().call().await.unwrap().value;

        // Ensure the count and root are correct
        assert_eq!(count, i + 1);
        assert_eq!(current_root, root);
    }
}

#[tokio::test]
async fn test_quote_dispatch() {
    let (_, hook, _, _, _, messages) = get_contract_instance().await;

    for i in 0..MSG_COUNT {
        let message = messages[i as usize].clone();
        let empty_body = Bytes(vec![0]);

        let quote = hook
            .methods()
            .quote_dispatch(empty_body, message)
            .call()
            .await
            .unwrap()
            .value;

        // The quote should be 0
        assert_eq!(quote, 0);
    }
}

#[tokio::test]
async fn test_module_type() {
    let (_, hook, _, _, _, _) = get_contract_instance().await;

    // Check that the hook type is correct
    let hook_type = hook.methods().hook_type().call().await.unwrap().value;
    assert_eq!(hook_type, PostDispatchHookType::MERKLE_TREE);
}
