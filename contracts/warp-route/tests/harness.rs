#[cfg(test)]
mod warp_route {
    use fuels::{
        prelude::*,
        types::{Bits256, U256},
    };
    use once_cell::sync::Lazy;
    use std::str::FromStr;
    use test_utils::{funded_wallet_with_private_key, get_revert_reason};
    use tokio::sync::Mutex;

    // Load abi from JSON
    abigen!(
        Contract(
            name = "WarpRoute",
            abi = "contracts/warp-route/out/debug/warp-route-abi.json"
        ),
        Contract(
            name = "Mailbox",
            abi = "contracts/mailbox/out/debug/mailbox-abi.json"
        ),
        Contract(
            name = "PostDispatchMock",
            abi = "contracts/mocks/mock-post-dispatch/out/debug/mock-post-dispatch-abi.json",
        ),
        Contract(
            name = "MsgRecipient",
            abi = "contracts/test/msg-recipient-test/out/debug/msg-recipient-test-abi.json"
        ),
        Contract(
            name = "TestInterchainSecurityModule",
            abi = "contracts/test/ism-test/out/debug/ism-test-abi.json",
        ),
        Contract(
            name = "GasOracle",
            abi = "contracts/igp/gas-oracle/out/debug/gas-oracle-abi.json",
        ),
        Contract(
            name = "GasPaymaster",
            abi = "contracts/igp/gas-paymaster/out/debug/gas-paymaster-abi.json",
        ),
        Contract(
            name = "IGPHook",
            abi = "contracts/hooks/igp/out/debug/igp-hook-abi.json",
        ),
    );

    const TEST_NON_OWNER_PRIVATE_KEY: &str =
        "0xde97d8624a438121b86a1956544bd72ed68cd69f2c99555b08b1e8c51ffd511c";

    const TEST_HOOK_ADDRESS: &str =
        "0x00000000000000000000000000000000000000000000000000000000deadbeef";

    const REMOTE_ROUTER_ADDRESS: &str =
        "0x00000000000000000000000000000000000000000000000000000000deadbeef";

    const TEST_LOCAL_DOMAIN: u32 = 1717982312;
    const TEST_REMOTE_DOMAIN: u32 = 11155111;
    const TEST_RECIPIENT: &str =
        "0xa347fa1775198aa68fb1a4523a4925f891cca8f4dc79bf18ca71274c49f600c3";

    const TOKEN_NAME: &str = "TestToken";
    const TOKEN_SYMBOL: &str = "TT";
    const DECIMALS: u8 = 9;
    const TOTAL_SUPPLY: u64 = 100_000_000_000_000;
    const MAX_SUPPLY: u64 = 100_000_000_000_000;

    const COLLATERAL_ASSET_ID: &str =
        "6fa0fecded4a4b1f57b908435dc44d2f0b77834414d385d744c5c96cc2296471";

    /// Helper functions
    fn get_collateral_asset() -> AssetId {
        AssetId::from_str(COLLATERAL_ASSET_ID).unwrap()
    }

    fn get_native_asset() -> AssetId {
        AssetId::default()
    }

    fn build_message_body(recipient: Bits256, amount: u64) -> Bytes {
        let mut buffer = Vec::new();

        let amount_u256 = U256::from(amount);
        let mut amount_bytes = [0u8; 32];
        amount_u256.to_big_endian(&mut amount_bytes);

        buffer.extend(&recipient.0);
        buffer.extend(&amount_bytes);

        Bytes(buffer)
    }

    async fn get_balance(
        provider: &Provider,
        address: &Bech32Address,
        asset: AssetId,
    ) -> std::result::Result<u64, Error> {
        provider.get_asset_balance(address, asset).await
    }

    async fn get_contract_balance(
        provider: &Provider,
        contract_id: &Bech32ContractId,
        asset: AssetId,
    ) -> std::result::Result<u64, Error> {
        provider
            .get_contract_asset_balance(contract_id, asset)
            .await
    }

    fn _get_token_metadata(config: WarpRouteConfig) -> TokenMetadata {
        TokenMetadata {
            name: config.token_name,
            symbol: config.token_symbol,
            decimals: config.decimals,
            total_supply: config.total_supply,
            asset_id: config.asset_id.unwrap(),
            sub_id: AssetId::zeroed().into(),
        }
    }

    // Storing Test Configuration
    #[derive(Clone, Debug)]
    struct WarpRouteConfig {
        token_mode: WarpRouteTokenMode,
        token_name: String,
        token_symbol: String,
        decimals: u8,
        total_supply: u64,
        asset_id: Option<AssetId>,
    }

    // deploy the test contracts
    async fn get_contract_instance(
        config: &Mutex<WarpRouteConfig>,
    ) -> (
        WarpRoute<WalletUnlocked>,
        ContractId,
        ContractId,
        ContractId,
        ContractId,
    ) {
        let mut wallets = launch_custom_provider_and_get_wallets(
            WalletsConfig::new_multiple_assets(
                1,
                vec![
                    AssetConfig {
                        id: get_native_asset(),
                        num_coins: 1,                         /* Single coin (UTXO) */
                        coin_amount: 100_000_000_000_000_000, /* Amount per coin */
                    },
                    AssetConfig {
                        id: get_collateral_asset(),
                        num_coins: 1,                         /* Single coin (UTXO) */
                        coin_amount: 100_000_000_000_000_000, /* Amount per coin */
                    },
                ],
            ),
            None,
            None,
        )
        .await
        .unwrap();

        let wallet = wallets.pop().unwrap();

        let warp_route_id =
            Contract::load_from("./out/debug/warp-route.bin", LoadConfiguration::default())
                .unwrap()
                .deploy(&wallet, TxPolicies::default())
                .await
                .unwrap();

        let mailbox_id = Contract::load_from(
            "../mailbox/out/debug/mailbox.bin",
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

        let post_dispatch_id = Contract::load_from(
            "../mocks/mock-post-dispatch/out/debug/mock-post-dispatch.bin",
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

        let config = config.lock().await;

        let warp_route = WarpRoute::new(warp_route_id.clone(), wallet.clone());
        let mailbox = Mailbox::new(mailbox_id.clone(), wallet.clone());
        let post_dispatch = PostDispatchMock::new(post_dispatch_id.clone(), wallet.clone());
        let default_ism = TestInterchainSecurityModule::new(default_ism_id.clone(), wallet.clone());

        let owner = Bits256(Address::from(wallet.address()).into());
        let mailbox_address = Bits256(ContractId::from(mailbox.id()).into());
        let hook_address = Bits256(ContractId::from(post_dispatch.id()).into());
        let default_ism_address = Bits256(ContractId::from(default_ism.id()).into());
        let warp_init_res = warp_route
            .methods()
            .initialize(
                owner,
                mailbox_address,
                config.token_mode.clone(),
                hook_address,
                config.token_name.clone(),
                config.token_symbol.clone(),
                config.decimals,
                config.total_supply,
                Some(config.asset_id.unwrap()),
            )
            .call()
            .await;
        assert!(warp_init_res.is_ok(), "Failed to initialize Warp Route.");

        let mailbox_init_res = mailbox
            .methods()
            .initialize(owner, default_ism_address, hook_address, hook_address)
            .call()
            .await;
        assert!(mailbox_init_res.is_ok(), "Failed to initialize Mailbox.");

        let set_ism_res = mailbox
            .methods()
            .set_default_ism(default_ism_id.clone())
            .call()
            .await;
        assert!(set_ism_res.is_ok(), "Failed to set default ISM.");

        //For both cases warp route requires a remote wr adress to send assets
        let enroll_router_res = warp_route
            .methods()
            .enroll_remote_router(
                TEST_REMOTE_DOMAIN,
                Bits256(Address::from_str(REMOTE_ROUTER_ADDRESS).unwrap().into()),
            )
            .call()
            .await;
        assert!(enroll_router_res.is_ok(), "Failed to enroll remote router.");

        (
            warp_route,
            warp_route_id.into(),
            mailbox_id.into(),
            post_dispatch_id.into(),
            recipient_id.into(),
        )
    }

    #[cfg(test)]
    mod collateral {
        use super::*;

        static COLLATERAL_CONFIG: Lazy<Mutex<WarpRouteConfig>> = Lazy::new(|| {
            Mutex::new(WarpRouteConfig {
                token_mode: WarpRouteTokenMode::COLLATERAL,
                token_name: TOKEN_NAME.to_string(),
                token_symbol: TOKEN_SYMBOL.to_string(),
                decimals: DECIMALS,
                total_supply: TOTAL_SUPPLY,
                asset_id: Some(get_collateral_asset()),
            })
        });

        async fn get_collateral_contract_instance() -> (
            WarpRouteConfig,
            WarpRoute<WalletUnlocked>,
            ContractId,
            ContractId,
            ContractId,
        ) {
            let (warp_route, contract_id, mailbox_id, post_dispatch_id, _) =
                get_contract_instance(&COLLATERAL_CONFIG).await;
            let config = COLLATERAL_CONFIG.lock().await.clone();

            (
                config,
                warp_route,
                contract_id,
                mailbox_id,
                post_dispatch_id,
            )
        }

        /// ============ enroll_unenroll_router ============
        #[tokio::test]
        async fn test_enroll_unenroll_router() {
            let (_, warp_route, _, _, _) = get_collateral_contract_instance().await;

            let domain = TEST_REMOTE_DOMAIN;
            let router_address = Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap();

            // Verify the router is set
            let router = warp_route
                .methods()
                .router(domain)
                .call()
                .await
                .unwrap()
                .value;
            assert_eq!(router, router_address);

            // Unenroll the router
            warp_route
                .methods()
                .unenroll_remote_router(domain)
                .call()
                .await
                .unwrap();

            // Verify the router is removed
            let router_after_unenroll = warp_route
                .methods()
                .router(domain)
                .call()
                .await
                .unwrap()
                .value;
            assert_eq!(router_after_unenroll, Bits256::zeroed());
        }

        /// ============ get_token_info ============
        #[tokio::test]
        async fn test_get_token_info() {
            let (config, warp_route, _, _, _) = get_collateral_contract_instance().await;

            let token_info = warp_route
                .methods()
                .get_token_info()
                .call()
                .await
                .unwrap()
                .value;

            assert_eq!(token_info.name, config.token_name);
            assert_eq!(token_info.symbol, config.token_symbol);
            assert_eq!(token_info.decimals, config.decimals);
            assert_eq!(token_info.total_supply, config.total_supply);
        }

        /// ============ get_token_mode ============
        #[tokio::test]
        async fn test_get_token_mode() {
            let (config, warp_route, _, _, _) = get_collateral_contract_instance().await;

            let token_mode = warp_route
                .methods()
                .get_token_mode()
                .call()
                .await
                .unwrap()
                .value;

            assert_eq!(token_mode, config.token_mode);
        }

        /// ============ set_and_get_hook ============
        #[tokio::test]
        async fn test_set_get_hook() {
            let (_, warp_route, _, _, post_dispatch_id) = get_collateral_contract_instance().await;

            let hook = warp_route.methods().get_hook().call().await.unwrap().value;

            assert_eq!(hook, Bits256(post_dispatch_id.into()));

            //invalid update hook
            let call = warp_route
                .methods()
                .set_hook(Bits256::zeroed())
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(get_revert_reason(call.err().unwrap()), "InvalidAddress");

            let test_hook_address = Bits256::from_hex_str(TEST_HOOK_ADDRESS).unwrap();

            //update mailbox
            warp_route
                .methods()
                .set_hook(test_hook_address)
                .call()
                .await
                .unwrap();

            let new_hook = warp_route.methods().get_hook().call().await.unwrap().value;

            assert_eq!(new_hook, test_hook_address);
        }

        /// ============ set_and_get_mailbox ============
        #[tokio::test]
        async fn test_set_get_mailbox() {
            let (_, warp_route, _, mailbox_id, _) = get_collateral_contract_instance().await;

            let mailbox = warp_route
                .methods()
                .get_mailbox()
                .call()
                .await
                .unwrap()
                .value;

            assert_eq!(mailbox, Bits256(mailbox_id.into()));

            //update mailbox
            let call = warp_route
                .methods()
                .set_mailbox(Bits256::zeroed())
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(get_revert_reason(call.err().unwrap()), "InvalidAddress");

            let test_mailbox_address = Bits256::from_hex_str(TEST_HOOK_ADDRESS).unwrap();

            //update mailbox
            warp_route
                .methods()
                .set_mailbox(test_mailbox_address)
                .call()
                .await
                .unwrap();

            let new_mailbox = warp_route
                .methods()
                .get_mailbox()
                .call()
                .await
                .unwrap()
                .value;

            assert_eq!(new_mailbox, test_mailbox_address);
        }

        /// ============ set_mailbox_hook_unauthorized ============
        #[tokio::test]
        async fn test_unauthorized_set() {
            let (_, warp_route, _, _, _) = get_collateral_contract_instance().await;
            let non_owner_wallet =
                funded_wallet_with_private_key(&warp_route.account(), TEST_NON_OWNER_PRIVATE_KEY)
                    .await;

            //update mailbox
            let call = warp_route
                .with_account(non_owner_wallet.clone())
                .methods()
                .set_mailbox(Bits256::zeroed())
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(get_revert_reason(call.err().unwrap()), "NotOwner");
        }

        /// ============ transfer_remote_collateral ============
        #[tokio::test]
        async fn test_transfer_remote() {
            let (config, warp_route, warp_route_id, mailbox, post_dispatch_id) =
                get_collateral_contract_instance().await;

            let wallet = warp_route.account();
            let provider = wallet.provider().unwrap();
            let asset = config.asset_id.unwrap();

            let wallet_balance_before = get_balance(provider, wallet.address(), asset)
                .await
                .unwrap();

            let contract_balance_before =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let amount = 1u64;

            let call_params = CallParameters::new(amount, asset, 5_000_000);

            // Transfer remote
            let call = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
                .call_params(call_params)
                .unwrap()
                .with_contract_ids(&[
                    warp_route_id.into(),
                    mailbox.into(),
                    post_dispatch_id.into(),
                ])
                .call()
                .await
                .unwrap();

            let logs = call
                .decode_logs_with_type::<SentTransferRemoteEvent>()
                .unwrap();
            let log = logs[0].clone();
            assert_eq!(log.destination, TEST_REMOTE_DOMAIN);
            assert_eq!(log.recipient, recipient);
            assert_eq!(log.amount, amount);

            let contract_balance_after =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            let wallet_balance_after = get_balance(provider, wallet.address(), asset)
                .await
                .unwrap();

            assert_eq!(contract_balance_before + amount, contract_balance_after);
            assert_eq!(wallet_balance_before - amount, wallet_balance_after);
        }

        /// ============ handle_message_collateral ============
        #[tokio::test]
        async fn test_handle_message() {
            let (_, warp_route, _, _, _) = get_collateral_contract_instance().await;

            let wallet = warp_route.account();
            let sender = Bits256(Address::from(wallet.address()).into());
            let amount = 1_000_000_000;

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let recipient_address = Address::from_str(TEST_RECIPIENT).unwrap();
            let body = build_message_body(recipient, amount);

            let (_, _) = wallet
                .force_transfer_to_contract(
                    warp_route.contract_id(),
                    amount,
                    get_collateral_asset(),
                    TxPolicies::default(),
                )
                .await
                .unwrap();

            let provider = wallet.provider().unwrap();
            let recipient_balance_before =
                get_balance(provider, &recipient_address.into(), get_collateral_asset())
                    .await
                    .unwrap();
            let contract_balance_before =
                get_contract_balance(provider, warp_route.contract_id(), get_collateral_asset())
                    .await
                    .unwrap();

            let call = warp_route
                .methods()
                .handle(TEST_LOCAL_DOMAIN, sender, body)
                .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
                .call()
                .await
                .unwrap();

            let recipient_balance =
                get_balance(provider, &recipient_address.into(), get_collateral_asset())
                    .await
                    .unwrap();
            let contract_balance =
                get_contract_balance(provider, warp_route.contract_id(), get_collateral_asset())
                    .await
                    .unwrap();

            assert_eq!(
                recipient_balance_before + amount / 1_000_000_000,
                recipient_balance
            );
            assert_eq!(
                contract_balance_before,
                contract_balance + amount / 1_000_000_000
            );

            let logs = call
                .decode_logs_with_type::<ReceivedTransferRemoteEvent>()
                .unwrap();
            assert_eq!(
                logs,
                vec![ReceivedTransferRemoteEvent {
                    origin: TEST_LOCAL_DOMAIN,
                    recipient,
                    amount: amount / 1_000_000_000,
                }]
            );
        }

        /// ============ claim_as_owner ============
        #[tokio::test]
        async fn test_claim_as_owner() {
            let (config, warp_route, warp_route_id, mailbox, post_dispatch_id) =
                get_collateral_contract_instance().await;

            let wallet = warp_route.account();
            let provider = wallet.provider().unwrap();
            let asset = config.asset_id.unwrap();

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let amount = 190;

            let call_params = CallParameters::new(amount, asset, 5_000_000);

            // Transfer remote
            warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
                .call_params(call_params)
                .unwrap()
                .with_contract_ids(&[
                    warp_route_id.into(),
                    mailbox.into(),
                    post_dispatch_id.into(),
                ])
                .call()
                .await
                .unwrap();

            let contract_balance_before =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            // Claim the balance as the owner
            warp_route
                .methods()
                .claim()
                .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
                .call()
                .await
                .unwrap();

            let contract_balance_after =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            assert_eq!(contract_balance_before - amount, contract_balance_after);
        }

        /// ============ transfer_remote_with_wrong_asset ============
        #[tokio::test]
        async fn test_transfer_remote_with_wrong_asset() {
            let (_, warp_route, _, _, _) = get_collateral_contract_instance().await;

            let asset = get_native_asset();
            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let amount = 1;

            let call_params = CallParameters::new(amount, asset, 1_000_000_000);

            // Transfer remote
            let call = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
                .call_params(call_params)
                .unwrap()
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(get_revert_reason(call.unwrap_err()), "PaymentError");
        }

        /// ============ handle_with_precision_loss ============
        // #[tokio::test]
        // async fn test_handle_with_precision_loss() {
        //     let (_, warp_route, _, _, _) = get_collateral_contract_instance().await;

        //     let wallet = warp_route.account();
        //     let sender = Bits256(Address::from(wallet.address()).into());
        //     let amount = 1_000_000_000_000_100_000;

        //     let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
        //     let body = build_message_body(recipient, amount);

        //     let call = warp_route
        //         .methods()
        //         .handle(TEST_LOCAL_DOMAIN, sender, body)
        //         .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        //         .call()
        //         .await;

        //     assert!(call.is_err());
        //     assert_eq!(get_revert_reason(call.unwrap_err()), "PrecisionLoss");
        // }

        /// ============ transfer_remote_with_insufficient_funds ============
        #[tokio::test]
        async fn test_transfer_remote_with_insufficient_funds() {
            let (config, warp_route, _, _, _) = get_collateral_contract_instance().await;

            let asset = config.asset_id.unwrap();
            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let amount = 1_000_000_000_000u64;
            let call_params = CallParameters::new(1_000_000_000, asset, 1_000_000_000);

            let call = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
                .call_params(call_params)
                .unwrap()
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(get_revert_reason(call.unwrap_err()), "InsufficientFunds");
        }

        #[tokio::test]
        async fn test_zero_and_negative_amount_transfer_remote() {
            let (config, warp_route, _, _, _) = get_collateral_contract_instance().await;

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();

            // Test with a zero transfer
            let amount_zero = 0u64;
            let call_params_zero =
                CallParameters::new(amount_zero, config.asset_id.unwrap(), 1_000_000_000);

            let call_zero = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount_zero)
                .call_params(call_params_zero)
                .unwrap()
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .call()
                .await;

            assert!(call_zero.is_err());
            assert_eq!(
                get_revert_reason(call_zero.unwrap_err()),
                "TransferZeroCoins"
            );
        }

        #[tokio::test]
        async fn test_pause_and_unpause() {
            let (config, warp_route, warp_route_id, mailbox, post_dispatch_id) =
                get_collateral_contract_instance().await;

            // Pause the contract
            warp_route.methods().pause().call().await.unwrap();

            let is_paused = warp_route.methods().is_paused().call().await.unwrap().value;
            assert!(is_paused);

            let amount = 1;
            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();

            // Attempt an operation that should fail when paused
            let call = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
                .call()
                .await;
            assert_eq!(get_revert_reason(call.unwrap_err()), "Paused");

            // Unpause the contract
            warp_route.methods().unpause().call().await.unwrap();

            let call_params = CallParameters::new(amount, config.asset_id.unwrap(), 1_000_000_000);

            let call = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
                .call_params(call_params)
                .unwrap()
                .with_contract_ids(&[
                    warp_route_id.into(),
                    mailbox.into(),
                    post_dispatch_id.into(),
                ])
                .call()
                .await;

            assert!(call.is_ok());
        }
    }
    /// Bridged Token Mode Test Cases
    #[cfg(test)]
    mod bridged {
        use super::*;

        static BRIDGED_CONFIG: Lazy<Mutex<WarpRouteConfig>> = Lazy::new(|| {
            Mutex::new(WarpRouteConfig {
                token_mode: WarpRouteTokenMode::BRIDGED,
                token_name: TOKEN_NAME.to_string(),
                token_symbol: TOKEN_SYMBOL.to_string(),
                decimals: DECIMALS,
                total_supply: TOTAL_SUPPLY,
                asset_id: Some(get_native_asset()),
            })
        });

        async fn get_bridged_contract_instance() -> (
            WarpRouteConfig,
            WarpRoute<WalletUnlocked>,
            ContractId,
            ContractId,
            ContractId,
            ContractId,
        ) {
            let (warp_route, contract_id, mailbox_id, post_dispatch_id, recipient_id) =
                get_contract_instance(&BRIDGED_CONFIG).await;

            let token_info = warp_route
                .methods()
                .get_token_info()
                .call()
                .await
                .unwrap()
                .value;

            let mut config = BRIDGED_CONFIG.lock().await.clone();
            config.asset_id = Some(token_info.asset_id);

            (
                config,
                warp_route,
                contract_id,
                mailbox_id,
                post_dispatch_id,
                recipient_id,
            )
        }

        #[tokio::test]
        async fn test_get_token_info() {
            let (mut config, warp_route, _, _, _, _) = get_bridged_contract_instance().await;

            let token_info = warp_route
                .methods()
                .get_token_info()
                .call()
                .await
                .unwrap()
                .value;

            config.asset_id = Some(token_info.asset_id);

            assert_eq!(token_info.name, config.token_name);
            assert_eq!(token_info.symbol, config.token_symbol);
            assert_eq!(token_info.decimals, config.decimals);
            assert_eq!(token_info.total_supply, config.total_supply);
        }

        /// ============ get_token_mode ============
        #[tokio::test]
        async fn test_get_token_mode() {
            let (config, warp_route, _, _, _, _) = get_bridged_contract_instance().await;

            let token_mode = warp_route
                .methods()
                .get_token_mode()
                .call()
                .await
                .unwrap()
                .value;
            assert_eq!(token_mode, config.token_mode);
        }

        // ============ transfer_remote ============
        #[tokio::test]
        async fn test_transfer_remote() {
            let (config, warp_route, warp_route_id, mailbox, post_dispatch_id, _) =
                get_bridged_contract_instance().await;

            let wallet = warp_route.account();
            let provider = wallet.provider().unwrap();
            let asset = config.asset_id.unwrap();
            let mint_amount = 100_000_000;

            let wallet_balance_before_mint = get_balance(provider, wallet.address(), asset)
                .await
                .unwrap();

            assert_eq!(wallet_balance_before_mint, 0);

            // Mint tokens for the test wallet
            warp_route
                .methods()
                .mint_tokens(Address::from(wallet.address()), mint_amount)
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .determine_missing_contracts(Some(5))
                .await
                .unwrap()
                .call()
                .await
                .unwrap();

            let wallet_balance = get_balance(provider, wallet.address(), asset)
                .await
                .unwrap();

            assert_eq!(wallet_balance_before_mint + mint_amount, wallet_balance);

            //For gas payment
            let (_, _) = wallet
                .force_transfer_to_contract(
                    warp_route.contract_id(),
                    10_000_000,
                    get_native_asset(),
                    TxPolicies::default(),
                )
                .await
                .unwrap();

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let amount = 100;

            let call_params = CallParameters::new(amount, asset, 2_000_000);

            let call = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
                .call_params(call_params)
                .unwrap()
                .with_contract_ids(&[
                    warp_route_id.into(),
                    mailbox.into(),
                    post_dispatch_id.into(),
                ])
                .call()
                .await
                .unwrap();

            let logs = call
                .decode_logs_with_type::<SentTransferRemoteEvent>()
                .unwrap();
            let log = logs[0].clone();
            assert_eq!(log.destination, TEST_REMOTE_DOMAIN);
            assert_eq!(log.recipient, recipient);

            let wallet_balance_after = get_balance(provider, wallet.address(), asset)
                .await
                .unwrap();

            assert_eq!(wallet_balance - amount, wallet_balance_after);
        }

        #[tokio::test]
        async fn test_handle_message() {
            // Get the contract instance and the config
            let (config, warp_route, _, _, _, _) = get_bridged_contract_instance().await;

            let wallet = warp_route.account();
            let sender = Bits256(Address::from(wallet.address()).into());
            let amount = 100_000_000_000_000_000;

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let recipient_address = Address::from_str(TEST_RECIPIENT).unwrap();
            let body = build_message_body(recipient, amount);

            let provider = wallet.provider().unwrap();
            let recipient_balance_before = get_balance(
                provider,
                &recipient_address.into(),
                config.asset_id.unwrap(),
            )
            .await
            .unwrap();

            let call = warp_route
                .methods()
                .handle(TEST_LOCAL_DOMAIN, sender, body)
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .call()
                .await
                .unwrap();

            let logs = call
                .decode_logs_with_type::<ReceivedTransferRemoteEvent>()
                .unwrap();
            assert_eq!(
                logs,
                vec![ReceivedTransferRemoteEvent {
                    origin: TEST_LOCAL_DOMAIN,
                    recipient,
                    amount: amount / 1_000_000_000,
                }]
            );

            // Validate balances after the transaction
            let recipient_balance = get_balance(
                provider,
                &recipient_address.into(),
                config.asset_id.unwrap(),
            )
            .await
            .unwrap();

            assert_eq!(
                recipient_balance_before + amount / 1_000_000_000,
                recipient_balance
            );
        }

        #[tokio::test]
        async fn test_get_cumulative_supply_before_and_after_mint() {
            let (_, warp_route, _, _, _, _) = get_bridged_contract_instance().await;

            // Assert that the initial cumulative supply is 0
            let initial_cumulative_supply = warp_route
                .methods()
                .get_cumulative_supply()
                .call()
                .await
                .unwrap()
                .value;
            assert_eq!(
                initial_cumulative_supply, 0,
                "Initial cumulative supply should be 0"
            );

            // Mint some tokens and verify the updated cumulative supply
            let mint_amount = 100_000u64;
            warp_route
                .methods()
                .mint_tokens(Address::from(warp_route.account().address()), mint_amount)
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .determine_missing_contracts(Some(5))
                .await
                .unwrap()
                .call()
                .await
                .unwrap();

            // Fetch the updated cumulative supply after minting
            let updated_cumulative_supply = warp_route
                .methods()
                .get_cumulative_supply()
                .call()
                .await
                .unwrap()
                .value;
            assert_eq!(
                updated_cumulative_supply, mint_amount,
                "Cumulative supply should be updated after minting"
            );
        }

        #[tokio::test]
        async fn test_over_burn() {
            let (config, warp_route, _, _, _, _) = get_bridged_contract_instance().await;

            let wallet = warp_route.account();
            let asset = config.asset_id.unwrap();

            // Mint some tokens for testing burn
            warp_route
                .methods()
                .mint_tokens(Address::from(wallet.address()), 1_000)
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .call()
                .await
                .unwrap();

            // Attempt to burn more than the total supply
            let call = warp_route
                .methods()
                .transfer_remote(
                    TEST_REMOTE_DOMAIN,
                    Bits256::from_hex_str(TEST_RECIPIENT).unwrap(),
                    2_000,
                ) // Amount exceeds minted tokens
                .call_params(CallParameters::new(1_000, asset, 1_000_000_000))
                .unwrap()
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(get_revert_reason(call.unwrap_err()), "InsufficientFunds");
        }

        /// ============ handle_with_precision_loss ============
        // #[tokio::test]
        // async fn test_handle_with_precision_loss() {
        //     let (_, warp_route, _, _, _, _) = get_bridged_contract_instance().await;

        //     let wallet = warp_route.account();
        //     let sender = Bits256(Address::from(wallet.address()).into());
        //     let amount = 1_000_000_000_000_100_000;

        //     let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
        //     let body = build_message_body(recipient, amount);

        //     let call = warp_route
        //         .methods()
        //         .handle(TEST_LOCAL_DOMAIN, sender, body)
        //         .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        //         .call()
        //         .await;

        //     assert!(call.is_err());
        //     assert_eq!(get_revert_reason(call.unwrap_err()), "PrecisionLoss");
        // }

        #[tokio::test]
        async fn test_max_supply_enforcement_handle_message() {
            let (_, warp_route, _, _, _, _) = get_bridged_contract_instance().await;
            let wallet = warp_route.account();

            warp_route
                .methods()
                .mint_tokens(Address::from(wallet.address()), MAX_SUPPLY - 1)
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .call()
                .await
                .unwrap();

            // Assert that the initial cumulative supply is just below the max
            let initial_cumulative_supply = warp_route
                .methods()
                .get_cumulative_supply()
                .call()
                .await
                .unwrap()
                .value;
            assert_eq!(initial_cumulative_supply, MAX_SUPPLY - 1);

            let call = warp_route
                .methods()
                .mint_tokens(Address::from(wallet.address()), 5)
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(get_revert_reason(call.unwrap_err()), "MaxMinted");

            let cumulative_supply = warp_route
                .methods()
                .get_cumulative_supply()
                .call()
                .await
                .unwrap()
                .value;
            assert_eq!(cumulative_supply, MAX_SUPPLY - 1);
        }
    }
    mod native {
        use super::*;

        static NATIVE_CONFIG: Lazy<Mutex<WarpRouteConfig>> = Lazy::new(|| {
            Mutex::new(WarpRouteConfig {
                token_mode: WarpRouteTokenMode::COLLATERAL,
                token_name: "ETH".to_string(),
                token_symbol: "ETH".to_string(),
                decimals: 9,
                total_supply: MAX_SUPPLY,
                asset_id: Some(get_native_asset()),
            })
        });

        async fn get_native_contract_instance() -> (
            WarpRouteConfig,
            WarpRoute<WalletUnlocked>,
            ContractId,
            ContractId,
            ContractId,
        ) {
            let (warp_route, contract_id, mailbox_id, post_dispatch_id, _) =
                get_contract_instance(&NATIVE_CONFIG).await;
            let config = NATIVE_CONFIG.lock().await.clone();

            (
                config,
                warp_route,
                contract_id,
                mailbox_id,
                post_dispatch_id,
            )
        }

        #[tokio::test]
        async fn test_transfer_remote_native() {
            let (config, warp_route, warp_route_id, mailbox, post_dispatch_id) =
                get_native_contract_instance().await;

            let wallet = warp_route.account();
            let provider = wallet.provider().unwrap();
            let asset = config.asset_id.unwrap();

            let contract_balance_before =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let amount = 180;

            let call_params = CallParameters::new(amount, asset, 5_000_000);

            // Transfer remote
            let call = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
                .call_params(call_params)
                .unwrap()
                .with_contract_ids(&[
                    warp_route_id.into(),
                    mailbox.into(),
                    post_dispatch_id.into(),
                ])
                .call()
                .await
                .unwrap();

            let logs = call
                .decode_logs_with_type::<SentTransferRemoteEvent>()
                .unwrap();
            let log = logs[0].clone();
            assert_eq!(log.destination, TEST_REMOTE_DOMAIN);
            assert_eq!(log.recipient, recipient);
            assert_eq!(log.amount, amount);

            let contract_balance_after =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            assert_eq!(contract_balance_before + amount, contract_balance_after);
        }

        #[tokio::test]
        async fn test_handle_message_native() {
            let (_, warp_route, _, _, _) = get_native_contract_instance().await;

            let wallet = warp_route.account();
            let sender = Bits256(Address::from(wallet.address()).into());
            let amount = 18_000_000_000;

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let recipient_address = Address::from_str(TEST_RECIPIENT).unwrap();
            let body = build_message_body(recipient, amount);

            let (_, _) = wallet
                .force_transfer_to_contract(
                    warp_route.contract_id(),
                    amount,
                    get_native_asset(),
                    TxPolicies::default(),
                )
                .await
                .unwrap();

            let provider = wallet.provider().unwrap();
            let recipient_balance_before =
                get_balance(provider, &recipient_address.into(), get_native_asset())
                    .await
                    .unwrap();

            let call = warp_route
                .methods()
                .handle(TEST_REMOTE_DOMAIN, sender, body)
                .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
                .call()
                .await
                .unwrap();

            let logs = call
                .decode_logs_with_type::<ReceivedTransferRemoteEvent>()
                .unwrap();
            assert_eq!(
                logs,
                vec![ReceivedTransferRemoteEvent {
                    origin: TEST_REMOTE_DOMAIN,
                    recipient,
                    amount: amount / 1_000_000_000,
                }]
            );

            let recipient_balance_after =
                get_balance(provider, &recipient_address.into(), get_native_asset())
                    .await
                    .unwrap();

            assert_eq!(
                recipient_balance_before + amount / 1_000_000_000,
                recipient_balance_after
            );
        }

        /// ============ handle_with_precision_loss ============
        // #[tokio::test]
        // async fn test_handle_with_precision_loss() {
        //     let (_, warp_route, _, _, _) = get_native_contract_instance().await;

        //     let wallet = warp_route.account();
        //     let sender = Bits256(Address::from(wallet.address()).into());
        //     let amount = 1_000_000_000_000_100_000;

        //     let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
        //     let body = build_message_body(recipient, amount);

        //     let call = warp_route
        //         .methods()
        //         .handle(TEST_LOCAL_DOMAIN, sender, body)
        //         .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        //         .call()
        //         .await;

        //     assert!(call.is_err());
        //     assert_eq!(get_revert_reason(call.unwrap_err()), "PrecisionLoss");
        // }
        #[tokio::test]
        async fn test_claim_native() {
            let (_, warp_route, warp_route_id, mailbox, post_dispatch_id) =
                get_native_contract_instance().await;

            let wallet = warp_route.account();
            let provider = wallet.provider().unwrap();
            let asset = get_native_asset();

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let amount = 1800;

            let call_params = CallParameters::new(amount, asset, 5_000_000);

            // Transfer remote
            warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
                .call_params(call_params)
                .unwrap()
                .with_contract_ids(&[
                    warp_route_id.into(),
                    mailbox.into(),
                    post_dispatch_id.into(),
                ])
                .call()
                .await
                .unwrap();

            let contract_balance_before_claim =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            // Claim the balance
            warp_route
                .methods()
                .claim()
                .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
                .call()
                .await
                .unwrap();

            let contract_balance_after =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            // Only the actual transfer amount should be claimed, not the gas fee
            assert_eq!(
                contract_balance_before_claim,
                contract_balance_after + amount
            );
        }
    }
}
