use fuels::{prelude::*, types::Identity};
use rand::{thread_rng, Rng};
use test_utils::get_revert_reason;

// Load abi from json
abigen!(Contract(
    name = "PausableIsm",
    abi = "contracts/ism/pausable-ism/out/debug/pausable-ism-abi.json"
));

fn get_deployment_config() -> LoadConfiguration {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    let salt = Salt::new(bytes);

    LoadConfiguration::default().with_salt(salt)
}

async fn get_contract_instance() -> (PausableIsm<WalletUnlocked>, WalletUnlocked) {
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

    let ism_id = Contract::load_from("./out/debug/pausable-ism.bin", get_deployment_config())
        .unwrap()
        .deploy(&wallet, TxPolicies::default())
        .await
        .unwrap();
    let ism = PausableIsm::new(ism_id.clone(), wallet.clone());

    ism.methods()
        .initialize_ownership(Identity::from(wallet.address()))
        .call()
        .await
        .unwrap();

    (ism, second_wallet)
}

// ============ ISM Interface ============
#[tokio::test]
async fn ism_interface() {
    let (ism, _) = get_contract_instance().await;

    let ism_type = ism
        .methods()
        .module_type()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert_eq!(ism_type, ModuleType::NULL);

    let verified_res = ism
        .methods()
        .verify(Bytes(vec![]), Bytes(vec![]))
        .call()
        .await;

    // verification successful since unpaused by default
    assert!(verified_res.is_ok());
    // success returns true
    assert!(verified_res.unwrap().value);
}

// ============ Pausable ============
#[tokio::test]
async fn pausable() {
    let (ism, non_owner_wallet) = get_contract_instance().await;

    let is_paused = ism
        .methods()
        .is_paused()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    // False by default
    assert!(!is_paused);

    // Pause
    let pause_res = ism.methods().pause().call().await;
    assert!(pause_res.is_ok());

    let is_paused = ism
        .methods()
        .is_paused()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;
    assert!(is_paused);

    // Only owner can pause
    let pause_res = ism
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
    let unpause_res = ism.methods().unpause().call().await;
    assert!(unpause_res.is_ok());

    let is_paused = ism
        .methods()
        .is_paused()
        .simulate(Execution::StateReadOnly)
        .await
        .unwrap()
        .value;

    assert!(!is_paused);

    // Only owner can unpause
    let unpause_res = ism
        .with_account(non_owner_wallet)
        .methods()
        .unpause()
        .call()
        .await;
    assert!(unpause_res.is_err());
    let unpause_err = unpause_res.unwrap_err();
    assert_eq!(get_revert_reason(unpause_err), "NotOwner");
}

// ============ Pausable Verify ============
#[tokio::test]
async fn pausable_verify() {
    let (ism, _) = get_contract_instance().await;

    // Pause
    let pause_res = ism.methods().pause().call().await;
    assert!(pause_res.is_ok());

    // Verify should fail since paused
    let post_dispatch = ism
        .methods()
        .verify(Bytes(vec![]), Bytes(vec![]))
        .call()
        .await;

    // Paused hook reverts if paused
    assert!(post_dispatch.is_err());
    let post_dispatch_err = post_dispatch.unwrap_err();
    assert_eq!(get_revert_reason(post_dispatch_err), "Paused");
}
