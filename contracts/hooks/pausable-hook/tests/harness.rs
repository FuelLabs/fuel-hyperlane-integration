use fuels::{prelude::*, types::Identity};
use rand::{thread_rng, Rng};
use test_utils::get_revert_reason;

// Load abi from json
abigen!(Contract(
    name = "PausableHook",
    abi = "contracts/hooks/pausable-hook/out/debug/pausable-hook-abi.json"
));

fn get_deployment_config() -> LoadConfiguration {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    let salt = Salt::new(bytes);

    LoadConfiguration::default().with_salt(salt)
}

async fn get_contract_instance() -> (PausableHook<WalletUnlocked>, WalletUnlocked) {
    // Launch a local network and deploy the contract
    let mut wallets = launch_custom_provider_and_get_wallets(
        WalletsConfig::new(
            Some(2),             /* Single wallet */
            Some(1),             /* Single coin (UTXO) */
            Some(1_000_000_000), /* Amount per coin */
        ),
        None,
        None,
    )
    .await
    .unwrap();
    let wallet = wallets.pop().unwrap();
    let second_wallet = wallets.pop().unwrap();

    let hook_id = Contract::load_from("./out/debug/pausable-hook.bin", get_deployment_config())
        .unwrap()
        .deploy(&wallet, TxPolicies::default())
        .await
        .unwrap();

    let hook = PausableHook::new(hook_id.clone(), wallet.clone());

    hook.methods()
        .initialize_ownership(Identity::from(wallet.address()))
        .call()
        .await
        .unwrap();

    (hook, second_wallet)
}

#[tokio::test]
async fn post_dispatch_interface() {
    let (hook, _) = get_contract_instance().await;

    // Hook type
    let hook_type = hook
        .methods()
        .hook_type()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(hook_type, PostDispatchHookType::PAUSABLE);

    // Quote dispatch
    let quote = hook
        .methods()
        .quote_dispatch(Bytes(vec![]), Bytes(vec![]))
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(quote, 0);

    // Supports metadata
    let supports_metadata = hook
        .methods()
        .supports_metadata(Bytes(vec![]))
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert!(!supports_metadata);

    // Post dispatch
    let post_dispatch = hook
        .methods()
        .post_dispatch(Bytes(vec![]), Bytes(vec![]))
        .call()
        .await;

    // Paused hook does not revert if not paused, default is unpaused
    assert!(post_dispatch.is_ok());
}

#[tokio::test]
async fn pausable() {
    let (hook, non_owner_wallet) = get_contract_instance().await;

    let is_paused = hook
        .methods()
        .is_paused()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    // False by default
    assert!(!is_paused);

    // Pause
    let pause_res = hook.methods().pause().call().await;
    assert!(pause_res.is_ok());

    let is_paused = hook
        .methods()
        .is_paused()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert!(is_paused);

    // Only owner can pause
    let pause_res = hook
        .clone()
        .with_account(non_owner_wallet.clone())
        .methods()
        .pause()
        .call()
        .await;
    assert!(pause_res.is_err());
    let pause_err = pause_res.unwrap_err();
    assert_eq!(get_revert_reason(pause_err), "NotOwner");

    // Unpause
    let unpause_res = hook.methods().unpause().call().await;
    assert!(unpause_res.is_ok());

    let is_paused = hook
        .methods()
        .is_paused()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert!(!is_paused);

    // Only owner can unpause
    let unpause_res = hook
        .with_account(non_owner_wallet)
        .methods()
        .unpause()
        .call()
        .await;
    assert!(unpause_res.is_err());
    let unpause_err = unpause_res.unwrap_err();
    assert_eq!(get_revert_reason(unpause_err), "NotOwner");
}

#[tokio::test]
async fn pausable_post_dispatch() {
    let (hook, _) = get_contract_instance().await;

    // Pause
    let pause_res = hook.methods().pause().call().await;
    assert!(pause_res.is_ok());

    // Post dispatch
    let post_dispatch = hook
        .methods()
        .post_dispatch(Bytes(vec![]), Bytes(vec![]))
        .call()
        .await;

    // Paused hook reverts if paused
    assert!(post_dispatch.is_err());
    let post_dispatch_err = post_dispatch.unwrap_err();
    assert_eq!(get_revert_reason(post_dispatch_err), "Paused");
}
