use fuels::{
    prelude::*,
    types::{Bits256, Identity},
};
use hyperlane_core::{HyperlaneMessage, RawHyperlaneMessage, H256};
use rand::{thread_rng, Rng};
use test_utils::get_revert_reason;

// Load abi from json
abigen!(
    Contract(
        name = "FallbackDomainRoutingHook",
        abi = "contracts/hooks/fallback-domain-routing-hook/out/debug/fallback-domain-routing-hook-abi.json"
    ),
    Contract(
        name = "PostDispatchHookMock",
        abi = "contracts/mocks/mock-post-dispatch/out/debug/mock-post-dispatch-abi.json"
    )
);

fn get_deployment_config() -> LoadConfiguration {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    let salt = Salt::new(bytes);

    LoadConfiguration::default().with_salt(salt)
}

async fn deploy_mock_hook(
    wallet: &WalletUnlocked,
    quote: u64,
) -> PostDispatchHookMock<WalletUnlocked> {
    let mock_hook_id = Contract::load_from(
        "../../mocks/mock-post-dispatch/out/debug/mock-post-dispatch.bin",
        get_deployment_config(),
    )
    .unwrap()
    .deploy(wallet, TxPolicies::default())
    .await
    .unwrap();

    let hook = PostDispatchHookMock::new(mock_hook_id, wallet.clone());

    assert!(hook.methods().set_quote(quote).call().await.is_ok());

    hook
}

fn generate_hyperlane_messages() -> Vec<RawHyperlaneMessage> {
    (1..3)
        .map(|domain| {
            RawHyperlaneMessage::from(&HyperlaneMessage {
                version: 3,
                nonce: 0,
                origin: domain,
                sender: H256::zero(),
                destination: domain,
                recipient: H256::zero(),
                body: vec![],
            })
        })
        .collect()
}

fn get_quotes() -> Vec<u64> {
    vec![123, 456, 789]
}

async fn get_contract_instance() -> (
    FallbackDomainRoutingHook<WalletUnlocked>,
    WalletUnlocked,
    Vec<PostDispatchHookMock<WalletUnlocked>>,
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
    let deployer = wallets.pop().unwrap();

    let fallback_domain_routing_hook = Contract::load_from(
        "./out/debug/fallback-domain-routing-hook.bin",
        get_deployment_config(),
    )
    .unwrap()
    .deploy(&deployer, TxPolicies::default())
    .await
    .unwrap();

    let fallback_routing_hook =
        FallbackDomainRoutingHook::new(fallback_domain_routing_hook.clone(), deployer.clone());

    let quotes = get_quotes();

    // Hooks used for testing
    let hooks = vec![
        deploy_mock_hook(&deployer, *quotes.get(0).unwrap()).await,
        deploy_mock_hook(&deployer, *quotes.get(1).unwrap()).await,
        deploy_mock_hook(&deployer, *quotes.get(2).unwrap()).await,
    ];

    (fallback_routing_hook, deployer, hooks)
}

#[tokio::test]
async fn module_type_and_metadata() {
    let (fallback_routing_hook, _, _) = get_contract_instance().await;

    let module_type = fallback_routing_hook
        .methods()
        .hook_type()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(module_type, PostDispatchHookType::FALLBACK_ROUTING);

    let supports_metadata = fallback_routing_hook
        .methods()
        .supports_metadata(Bytes(vec![]))
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert!(supports_metadata);
}

#[tokio::test]
async fn initialize() {
    let (fallback_routing_hook, owner, mut hooks) = get_contract_instance().await;

    let hook = hooks.pop().unwrap().id();
    let init_res = fallback_routing_hook
        .methods()
        .initialize(
            Identity::Address(owner.address().into()),
            Bits256(*hook.hash),
        )
        .call()
        .await;
    // Works with a valid hook address
    assert!(init_res.is_ok());

    let owner_res = fallback_routing_hook
        .methods()
        .owner()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    // Owner set correctly
    assert_eq!(
        owner_res,
        State::Initialized(Identity::Address(owner.address().into()))
    );
}

#[tokio::test]
async fn setters() {
    let (fallback_routing_hook, owner, hooks) = get_contract_instance().await;

    let hook_id = deploy_mock_hook(&owner, 123).await.id();

    let some_dest = 123;
    let set_res = fallback_routing_hook
        .methods()
        .set_hook(some_dest, Bits256(*hook_id.hash))
        .call()
        .await;
    // Cannot set the hook if not initialized
    assert!(set_res.is_err());
    assert_eq!(get_revert_reason(set_res.unwrap_err()), "NotOwner");

    let init_res = fallback_routing_hook
        .methods()
        .initialize(
            Identity::Address(owner.address().into()),
            Bits256(*hook_id.hash),
        )
        .call()
        .await;
    assert!(init_res.is_ok());

    let set_res = fallback_routing_hook
        .methods()
        .set_hook(some_dest, Bits256(*hook_id.hash))
        .call()
        .await;
    // Can set the hook if initialized
    assert!(set_res.is_ok());

    let hook_configs = hooks
        .into_iter()
        .enumerate()
        .map(|(index, hook)| HookConfig {
            hook: Bits256(*hook.id().hash),
            destination: index as u32,
        })
        .collect::<Vec<_>>();

    let set_res = fallback_routing_hook
        .methods()
        .set_hooks(hook_configs)
        .call()
        .await;
    // Can set multiple hooks at once
    assert!(set_res.is_ok());
}

#[tokio::test]
async fn routing_and_quoting() {
    let (fallback_routing_hook, owner, hooks) = get_contract_instance().await;

    // Fallback hook
    let fallback_quote = 1000;
    let fallback_hook = deploy_mock_hook(&owner, fallback_quote).await;
    let fallback_hook_id = fallback_hook.id();

    assert!(fallback_routing_hook
        .methods()
        .initialize(
            Identity::Address(owner.address().into()),
            Bits256(*fallback_hook_id.hash),
        )
        .call()
        .await
        .is_ok());

    for (index, hook) in hooks.iter().enumerate() {
        let hook_id = Bits256(*hook.id().hash);

        // Set hooks for domains 1, 2, 3
        assert!(fallback_routing_hook
            .methods()
            .set_hook(index as u32 + 1, hook_id)
            .call()
            .await
            .is_ok());
    }

    let messages = generate_hyperlane_messages();
    let quotes = get_quotes();

    for ((message, hook), quote) in messages.into_iter().zip(hooks).zip(quotes) {
        let hook_called = hook
            .methods()
            .was_called()
            .simulate(Execution::StateReadOnly)
            .await
            .unwrap()
            .value;
        // Hook not called yet
        assert!(!hook_called);

        // --- Routing to hook ---
        let hook_call = fallback_routing_hook
            .methods()
            .post_dispatch(Bytes(vec![]), Bytes(message.clone()))
            .determine_missing_contracts(None)
            .await
            .unwrap()
            .call()
            .await;
        // routing to hook successful
        assert!(hook_call.is_ok());

        let hook_called = hook
            .methods()
            .was_called()
            .simulate(Execution::StateReadOnly)
            .await
            .unwrap()
            .value;
        // Hook called
        assert!(hook_called);

        // --- Quoting ---
        let hook_quote = hook
            .methods()
            .quote_dispatch(Bytes(vec![]), Bytes(message))
            .determine_missing_contracts(None)
            .await
            .unwrap()
            .simulate(Execution::StateReadOnly)
            .await
            .unwrap()
            .value;
        // Hook quote matches
        assert_eq!(hook_quote, quote);
    }

    // Fallback not hit

    let hook_called = fallback_hook
        .methods()
        .was_called()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    // Fallback hook not called yet
    assert!(!hook_called);
}

#[tokio::test]
async fn fallback() {
    let (fallback_routing_hook, owner, _) = get_contract_instance().await;

    // Fallback hook
    let fallback_quote = 1000;
    let fallback_hook = deploy_mock_hook(&owner, fallback_quote).await;
    let fallback_hook_id = fallback_hook.id();

    assert!(fallback_routing_hook
        .methods()
        .initialize(
            Identity::Address(owner.address().into()),
            Bits256(*fallback_hook_id.hash),
        )
        .call()
        .await
        .is_ok());

    // --- Fallback routing ---

    let hook_called = fallback_hook
        .methods()
        .was_called()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    // Fallback hook not called yet
    assert!(!hook_called);

    // Message with unknown/unset domain
    let message = RawHyperlaneMessage::from(&HyperlaneMessage {
        version: 3,
        nonce: 0,
        origin: 123456,
        sender: H256::zero(),
        destination: 123456,
        recipient: H256::zero(),
        body: vec![],
    });

    let fallback_call = fallback_routing_hook
        .methods()
        .post_dispatch(Bytes(vec![]), Bytes(message))
        .determine_missing_contracts(None)
        .await
        .unwrap()
        .call()
        .await;
    // routing to fallback hook successful
    assert!(fallback_call.is_ok());

    let hook_called = fallback_hook
        .methods()
        .was_called()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    // Fallback hook called
    assert!(hook_called);

    // --- Fallback quoting ---

    let hook_quote = fallback_hook
        .methods()
        .quote_dispatch(Bytes(vec![]), Bytes(vec![]))
        .determine_missing_contracts(None)
        .await
        .unwrap()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    // Fallback hook quote matches
    assert_eq!(hook_quote, fallback_quote);
}
