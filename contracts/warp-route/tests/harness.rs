#[cfg(test)]
mod warp_route {
    use fuels::{
        prelude::*,
        types::{Bits256, Identity, U256},
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
            name = "TestInterchainSecurityModule",
            abi = "contracts/test/ism-test/out/debug/ism-test-abi.json",
        ),
        Contract(
            name = "SRC20Test",
            abi = "contracts/test/src20-test/out/debug/src20-test-abi.json",
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
        "0x2407159311d2abbf43ef472a9fd20a526abeadb048116b2ab5c93f7d1c733682";

    const TOKEN_NAME: &str = "TestToken";
    const TOKEN_SYMBOL: &str = "TT";
    const DECIMALS: u8 = 9;
    const TOTAL_SUPPLY: u64 = 100_000_000_000_000;
    const MAX_SUPPLY: u64 = 100_000_000_000_000;

    const COLLATERAL_ASSET_ID: &str =
        "f8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07";

    /// Helper functions
    fn get_collateral_asset() -> AssetId {
        AssetId::from_str(COLLATERAL_ASSET_ID).unwrap()
    }

    fn get_native_asset() -> AssetId {
        AssetId::BASE
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
            name: config.token_name.unwrap(),
            symbol: config.token_symbol.unwrap(),
            decimals: config.decimals.unwrap(),
            total_supply: config.total_supply.unwrap(),
            asset_id: config.asset_id.unwrap(),
            sub_id: AssetId::zeroed().into(),
        }
    }

    // For testing the synthetic asset, we actually need to have the tokens
    // Since the asset is managed by the warp route - we can mock the asset minting with handle call
    // So in order to have a test wallet with 100 tokens with 6 decimals, we will mock someone sending 100*10^(remote_decimals - 6) tokens
    // We will also need to mock the mailbox to be the wallet address since only mailbox can send authorized token recieve messages
    async fn mock_mailbox_setup(wallet: WalletUnlocked, warp_route: WarpRoute<WalletUnlocked>) {
        let address_b256 = Bits256(Address::from(wallet.address()).into());
        let address_contract_id = ContractId::from(address_b256.0);

        let update_mailbox = warp_route
            .methods()
            .set_mailbox(address_contract_id)
            .call()
            .await;
        assert!(update_mailbox.is_ok(), "Failed to update mailbox.");

        let query_mailbox = warp_route
            .methods()
            .get_mailbox()
            .call()
            .await
            .unwrap()
            .value;
        assert_eq!(query_mailbox, address_contract_id);
    }

    async fn mock_recieve_for_mint(
        wallet: WalletUnlocked,
        warp_route: WarpRoute<WalletUnlocked>,
        amount: u64,
        remote_decimals: u32,
        local_decimals: u32,
    ) {
        mock_mailbox_setup(wallet.clone(), warp_route.clone()).await;

        let remote_adjusted_amount = amount * 10u64.pow(remote_decimals - local_decimals);

        let body = build_message_body(
            Bits256(Address::from(wallet.address()).into()),
            remote_adjusted_amount,
        );

        warp_route
            .methods()
            .handle(
                TEST_REMOTE_DOMAIN,
                Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap(),
                body,
            )
            .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
            .determine_missing_contracts(Some(5))
            .await
            .unwrap()
            .call()
            .await
            .unwrap();
    }

    // Storing Test Configuration
    #[derive(Clone, Debug)]
    struct WarpRouteConfig {
        token_mode: WarpRouteTokenMode,
        token_name: Option<String>,
        token_symbol: Option<String>,
        decimals: Option<u8>,
        total_supply: Option<u64>,
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
        AssetId,
    ) {
        let mut wallets = launch_custom_provider_and_get_wallets(
            WalletsConfig::new_multiple_assets(
                1,
                vec![
                    AssetConfig {
                        id: get_native_asset(),
                        num_coins: 1,                    /* Single coin (UTXO) */
                        coin_amount: 10 * 10u64.pow(18), /* Amount per coin */
                    },
                    AssetConfig {
                        id: get_collateral_asset(),
                        num_coins: 1,                    /* Single coin (UTXO) */
                        coin_amount: 10 * 10u64.pow(18), /* Amount per coin */
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

        let collateral_token_contract_id = Contract::load_from(
            "../test/src20-test/out/debug/src20-test.bin",
            LoadConfiguration::default(),
        )
        .unwrap()
        .deploy(&wallet, TxPolicies::default())
        .await
        .unwrap();

        let collateral_token_contract =
            SRC20Test::new(collateral_token_contract_id.clone(), wallet.clone());

        let _ = collateral_token_contract
            .methods()
            .mint(
                Identity::Address(wallet.address().into()),
                Some(Bits256::zeroed()),
                TOTAL_SUPPLY,
            )
            .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
            .call()
            .await
            .unwrap();

        let collateral_token_id = collateral_token_contract_id.asset_id(&Bits256::zeroed());

        let balance = get_balance(
            wallet.provider().unwrap(),
            wallet.address(),
            collateral_token_id,
        )
        .await
        .unwrap();

        assert_eq!(balance, TOTAL_SUPPLY);

        let mut asset_id = Some(config.asset_id.unwrap());
        let mut asset_contract_id = None;

        if config.token_mode == WarpRouteTokenMode::COLLATERAL {
            asset_id = Some(collateral_token_id);
            asset_contract_id = Some(Bits256(collateral_token_contract_id.hash().into()));
        }

        let mut call_handler = warp_route.methods().initialize(
            owner,
            mailbox_address,
            config.token_mode.clone(),
            hook_address,
            Some(config.token_name.clone().unwrap()),
            Some(config.token_symbol.clone().unwrap()),
            Some(config.decimals.unwrap()),
            Some(config.total_supply.unwrap()),
            asset_id,
            asset_contract_id,
        );

        if config.token_mode == WarpRouteTokenMode::COLLATERAL {
            call_handler = call_handler.with_contract_ids(&[collateral_token_contract_id]);
        }

        let warp_init_res = call_handler.call().await;
        assert!(warp_init_res.is_ok(), "Failed to initialize Warp Route.");

        let mailbox_init_res = mailbox
            .methods()
            .initialize(owner, default_ism_address, hook_address, hook_address)
            .call()
            .await;
        assert!(mailbox_init_res.is_ok(), "Failed to initialize Mailbox.");

        //For all cases warp route requires a remote wr adress and corresponding decimals to send assets
        let enroll_router_res = warp_route
            .methods()
            .enroll_remote_router(
                TEST_REMOTE_DOMAIN,
                Bits256(Address::from_str(REMOTE_ROUTER_ADDRESS).unwrap().into()),
            )
            .call()
            .await;
        assert!(enroll_router_res.is_ok(), "Failed to enroll remote router.");

        let enroll_router_decimals_res = warp_route
            .methods()
            .set_remote_router_decimals(
                Bits256(Address::from_str(REMOTE_ROUTER_ADDRESS).unwrap().into()),
                18,
            )
            .call()
            .await;
        assert!(
            enroll_router_decimals_res.is_ok(),
            "Failed to enroll remote router decimals."
        );

        (
            warp_route,
            warp_route_id.into(),
            mailbox_id.into(),
            post_dispatch_id.into(),
            recipient_id.into(),
            collateral_token_id,
        )
    }

    #[cfg(test)]
    mod collateral {
        use super::*;

        static COLLATERAL_CONFIG: Lazy<Mutex<WarpRouteConfig>> = Lazy::new(|| {
            Mutex::new(WarpRouteConfig {
                token_mode: WarpRouteTokenMode::COLLATERAL,
                token_name: Some(TOKEN_NAME.to_string()),
                token_symbol: Some(TOKEN_SYMBOL.to_string()),
                decimals: Some(DECIMALS),
                total_supply: Some(TOTAL_SUPPLY),
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
            let (warp_route, contract_id, mailbox_id, post_dispatch_id, _, collateral_token_id) =
                get_contract_instance(&COLLATERAL_CONFIG).await;

            let mut config = COLLATERAL_CONFIG.lock().await.clone();
            config.asset_id = Some(collateral_token_id);

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

            assert_eq!(token_info.name, config.token_name.unwrap());
            assert_eq!(token_info.symbol, config.token_symbol.unwrap());
            assert_eq!(token_info.decimals, config.decimals.unwrap());
            assert_eq!(token_info.total_supply, config.total_supply.unwrap());
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

        /// ============ get_all_domains_and_routers ============
        #[tokio::test]
        async fn test_get_all_domains_and_routers() {
            let (_, warp_route, _, _, _) = get_collateral_contract_instance().await;

            // Insert test data
            let test_domains = [1, 2, 3];
            let test_routers = [
                Bits256::from_hex_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                )
                .unwrap(),
                Bits256::from_hex_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000002",
                )
                .unwrap(),
                Bits256::from_hex_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000003",
                )
                .unwrap(),
            ];

            for (domain, router) in test_domains.iter().zip(test_routers.iter()) {
                warp_route
                    .methods()
                    .enroll_remote_router(*domain, *router)
                    .call()
                    .await
                    .unwrap();
            }

            // Retrieve all domains
            let domains = warp_route
                .methods()
                .all_domains()
                .call()
                .await
                .unwrap()
                .value;
            assert_eq!(
                domains,
                [
                    TEST_REMOTE_DOMAIN,
                    test_domains[0],
                    test_domains[1],
                    test_domains[2]
                ],
                "Domains do not match expected values."
            );

            // Retrieve all routers
            let routers = warp_route
                .methods()
                .all_routers()
                .call()
                .await
                .unwrap()
                .value;
            assert_eq!(
                routers,
                [
                    Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap(),
                    test_routers[0],
                    test_routers[1],
                    test_routers[2]
                ],
                "Routers do not match expected values."
            );
        }

        /// ============ set_and_get_hook ============
        #[tokio::test]
        async fn test_set_get_hook() {
            let (_, warp_route, _, _, post_dispatch_id) = get_collateral_contract_instance().await;

            let hook = warp_route.methods().get_hook().call().await.unwrap().value;

            assert_eq!(hook, post_dispatch_id);

            //invalid update hook
            let call = warp_route
                .methods()
                .set_hook(ContractId::zeroed())
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(get_revert_reason(call.err().unwrap()), "InvalidAddress");

            let test_hook_address = ContractId::from_str(TEST_HOOK_ADDRESS).unwrap();

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

            assert_eq!(mailbox, mailbox_id);

            //update mailbox
            let call = warp_route
                .methods()
                .set_mailbox(ContractId::zeroed())
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(get_revert_reason(call.err().unwrap()), "InvalidAddress");

            let test_mailbox_address = ContractId::from_str(TEST_HOOK_ADDRESS).unwrap();

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
                .set_mailbox(ContractId::zeroed())
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(get_revert_reason(call.err().unwrap()), "NotOwner");
        }

        /// ============ transfer_remote_collateral ============
        #[tokio::test]
        async fn test_transfer_remote() {
            let (_, warp_route, warp_route_id, mailbox, post_dispatch_id) =
                get_collateral_contract_instance().await;

            let wallet = warp_route.account();
            let provider = wallet.provider().unwrap();
            let asset = warp_route
                .methods()
                .get_token_info()
                .call()
                .await
                .unwrap()
                .value
                .asset_id;

            let wallet_balance_before = get_balance(provider, wallet.address(), asset)
                .await
                .unwrap();

            let contract_balance_before =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let amount = 123;

            let remote_decimals = warp_route
                .methods()
                .remote_router_decimals(Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap())
                .call()
                .await
                .unwrap()
                .value;

            let (_, _) = wallet
                .force_transfer_to_contract(
                    warp_route.contract_id(),
                    amount,
                    asset,
                    TxPolicies::default(),
                )
                .await
                .unwrap();

            let call = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
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
            assert_eq!(log.amount, amount * 10u64.pow(remote_decimals as u32 - 9));

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
            let sender = Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap();
            let remote_decimals = 18;

            let local_decimals = warp_route
                .methods()
                .get_token_info()
                .call()
                .await
                .unwrap()
                .value
                .decimals as u32;

            let asset = warp_route
                .methods()
                .get_token_info()
                .call()
                .await
                .unwrap()
                .value
                .asset_id;

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let recipient_address = Address::from_str(TEST_RECIPIENT).unwrap();
            let amount = 2 * 10u64.pow(remote_decimals);
            let body = build_message_body(recipient, amount);

            let (_, _) = wallet
                .force_transfer_to_contract(
                    warp_route.contract_id(),
                    2 * 10u64.pow(remote_decimals - local_decimals),
                    asset,
                    TxPolicies::default(),
                )
                .await
                .unwrap();

            let provider = wallet.provider().unwrap();
            let recipient_balance_before = get_balance(provider, &recipient_address.into(), asset)
                .await
                .unwrap();
            let contract_balance_before =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            //only mailbox can send authorized token recieve messages which triggers handle_message
            mock_mailbox_setup(wallet.clone(), warp_route.clone()).await;

            let call = warp_route
                .methods()
                .handle(TEST_LOCAL_DOMAIN, sender, body)
                .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
                .call()
                .await
                .unwrap();

            let recipient_balance = get_balance(provider, &recipient_address.into(), asset)
                .await
                .unwrap();
            let contract_balance = get_contract_balance(provider, warp_route.contract_id(), asset)
                .await
                .unwrap();

            let divider = remote_decimals - local_decimals;
            assert_eq!(
                recipient_balance_before + amount / 10u64.pow(divider),
                recipient_balance
            );
            assert_eq!(
                contract_balance_before,
                contract_balance + amount / 10u64.pow(divider)
            );

            let logs = call
                .decode_logs_with_type::<ReceivedTransferRemoteEvent>()
                .unwrap();
            assert_eq!(
                logs,
                vec![ReceivedTransferRemoteEvent {
                    origin: TEST_LOCAL_DOMAIN,
                    recipient,
                    amount: amount / 10u64.pow(divider),
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
            let asset = warp_route
                .methods()
                .get_token_info()
                .call()
                .await
                .unwrap()
                .value
                .asset_id;

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let amount = 190;

            let (_, _) = wallet
                .force_transfer_to_contract(
                    warp_route.contract_id(),
                    amount,
                    asset,
                    TxPolicies::default(),
                )
                .await
                .unwrap();

            // Transfer remote
            warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
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
                .claim(config.asset_id.unwrap())
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

        /// ============ transfer_remote_with_zero_amount ============
        #[tokio::test]
        async fn test_zero_and_negative_amount_transfer_remote() {
            let (_, warp_route, _, mailbox, post_dispatch_id) =
                get_collateral_contract_instance().await;

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let _asset = warp_route
                .methods()
                .get_token_info()
                .call()
                .await
                .unwrap()
                .value
                .asset_id;

            // Test with a zero transfer
            let amount_zero = 0u64;

            let call_zero = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount_zero)
                .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
                .with_contract_ids(&[mailbox.into(), post_dispatch_id.into()])
                .call()
                .await;

            assert!(call_zero.is_err());
            assert_eq!(
                get_revert_reason(call_zero.unwrap_err()),
                "TransferZeroCoins"
            );
        }

        /// ============ pause_and_unpause ============
        #[tokio::test]
        async fn test_pause_and_unpause() {
            let (_, warp_route, warp_route_id, mailbox, post_dispatch_id) =
                get_collateral_contract_instance().await;

            let wallet = warp_route.account();
            let asset = warp_route
                .methods()
                .get_token_info()
                .call()
                .await
                .unwrap()
                .value
                .asset_id;

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

            let (_, _) = wallet
                .force_transfer_to_contract(
                    warp_route.contract_id(),
                    amount,
                    asset,
                    TxPolicies::default(),
                )
                .await
                .unwrap();

            let call = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
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
    /// SYNTHETIC Token Mode Test Cases
    #[cfg(test)]
    mod synthetic {
        use super::*;

        static SYNTHETIC_CONFIG: Lazy<Mutex<WarpRouteConfig>> = Lazy::new(|| {
            Mutex::new(WarpRouteConfig {
                token_mode: WarpRouteTokenMode::SYNTHETIC,
                token_name: Some(TOKEN_NAME.to_string()),
                token_symbol: Some(TOKEN_SYMBOL.to_string()),
                decimals: Some(DECIMALS),
                total_supply: Some(TOTAL_SUPPLY),
                asset_id: Some(get_native_asset()),
            })
        });

        async fn get_synthetic_contract_instance() -> (
            WarpRouteConfig,
            WarpRoute<WalletUnlocked>,
            ContractId,
            ContractId,
            ContractId,
            ContractId,
        ) {
            let (warp_route, contract_id, mailbox_id, post_dispatch_id, recipient_id, _) =
                get_contract_instance(&SYNTHETIC_CONFIG).await;

            let token_info = warp_route
                .methods()
                .get_token_info()
                .call()
                .await
                .unwrap()
                .value;

            let mut config = SYNTHETIC_CONFIG.lock().await.clone();
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

        /// ============ get_token_info ============
        #[tokio::test]
        async fn test_get_token_info() {
            let (mut config, warp_route, _, _, _, _) = get_synthetic_contract_instance().await;

            let token_info = warp_route
                .methods()
                .get_token_info()
                .call()
                .await
                .unwrap()
                .value;

            config.asset_id = Some(token_info.asset_id);

            assert_eq!(token_info.name, config.token_name.unwrap());
            assert_eq!(token_info.symbol, config.token_symbol.unwrap());
            assert_eq!(token_info.decimals, config.decimals.unwrap());
            assert_eq!(token_info.total_supply, config.total_supply.unwrap());
        }

        /// ============ get_token_mode ============
        #[tokio::test]
        async fn test_get_token_mode() {
            let (config, warp_route, _, _, _, _) = get_synthetic_contract_instance().await;

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
            let (config, warp_route, _, mailbox, post_dispatch_id, _) =
                get_synthetic_contract_instance().await;

            let wallet = warp_route.account();
            let provider = wallet.provider().unwrap();
            let asset = config.asset_id.unwrap();
            let local_decimals = config.decimals.unwrap() as u32;

            let remote_decimals = warp_route
                .methods()
                .remote_router_decimals(Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap())
                .call()
                .await
                .unwrap()
                .value;

            let amount = 100;

            let wallet_balance_before_mint = get_balance(provider, wallet.address(), asset)
                .await
                .unwrap();

            assert_eq!(wallet_balance_before_mint, 0);
            let actual_mailbox = warp_route
                .methods()
                .get_mailbox()
                .call()
                .await
                .unwrap()
                .value;

            mock_recieve_for_mint(
                wallet.clone(),
                warp_route.clone(),
                amount * 2,
                remote_decimals as u32,
                local_decimals,
            )
            .await;

            // Reset mailbox to original value
            warp_route
                .methods()
                .set_mailbox(actual_mailbox)
                .call()
                .await
                .unwrap();

            let wallet_balance = get_balance(provider, wallet.address(), asset)
                .await
                .unwrap();

            assert_eq!(wallet_balance_before_mint + amount * 2, wallet_balance);

            let (_, _) = wallet
                .force_transfer_to_contract(
                    warp_route.contract_id(),
                    amount,
                    asset,
                    TxPolicies::default(),
                )
                .await
                .unwrap();

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();

            let call = warp_route
                .methods()
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount)
                .with_contract_ids(&[mailbox.into(), post_dispatch_id.into()])
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

        /// ============ handle_message ============
        #[tokio::test]
        async fn test_handle_message() {
            // Get the contract instance and the config
            let (config, warp_route, _, _, _, _) = get_synthetic_contract_instance().await;

            let wallet = warp_route.account();
            let sender = Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap();
            let amount = 100_000_000_000_000_000;

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let recipient_address = Address::from_str(TEST_RECIPIENT).unwrap();
            let body = build_message_body(recipient, amount);

            let remote_decimals = warp_route
                .methods()
                .remote_router_decimals(sender)
                .call()
                .await
                .unwrap()
                .value as u32;

            let local_decimals = config.decimals.unwrap() as u32;

            let provider = wallet.provider().unwrap();
            let recipient_balance_before = get_balance(
                provider,
                &recipient_address.into(),
                config.asset_id.unwrap(),
            )
            .await
            .unwrap();

            //only mailbox can send authorized token recieve messages which triggers handle_message
            mock_mailbox_setup(wallet.clone(), warp_route.clone()).await;

            let call = warp_route
                .methods()
                .handle(TEST_LOCAL_DOMAIN, sender, body)
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
                    origin: TEST_LOCAL_DOMAIN,
                    recipient,
                    amount: amount / 10u64.pow(remote_decimals - local_decimals),
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
                recipient_balance_before + amount / 10u64.pow(remote_decimals - local_decimals),
                recipient_balance
            );
        }

        /// ============ get_cumulative_supply_before_and_after_mint ============
        #[tokio::test]
        async fn test_get_cumulative_supply_before_and_after_mint() {
            let (config, warp_route, _, _, _, _) = get_synthetic_contract_instance().await;
            let wallet = warp_route.account();
            let local_decimals = config.decimals.unwrap() as u32;
            let remote_decimals = warp_route
                .methods()
                .remote_router_decimals(Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap())
                .call()
                .await
                .unwrap()
                .value;

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

            mock_recieve_for_mint(
                wallet.clone(),
                warp_route.clone(),
                mint_amount,
                remote_decimals as u32,
                local_decimals,
            )
            .await;

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

        /// ============ sending_more_than_minted ============
        #[tokio::test]
        async fn test_sending_more_than_minted() {
            let (config, warp_route, _, mailbox, post_dispatch_id, _) =
                get_synthetic_contract_instance().await;

            let wallet = warp_route.account();
            let mint_amount = 1_000;
            let local_decimals = config.decimals.unwrap() as u32;
            let remote_decimals = warp_route
                .methods()
                .remote_router_decimals(Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap())
                .call()
                .await
                .unwrap()
                .value;

            let actual_mailbox = warp_route
                .methods()
                .get_mailbox()
                .call()
                .await
                .unwrap()
                .value;

            mock_recieve_for_mint(
                wallet.clone(),
                warp_route.clone(),
                mint_amount,
                remote_decimals as u32,
                local_decimals,
            )
            .await;

            // Reset mailbox to original value
            warp_route
                .methods()
                .set_mailbox(actual_mailbox)
                .call()
                .await
                .unwrap();

            let call = warp_route
                .methods()
                .transfer_remote(
                    TEST_REMOTE_DOMAIN,
                    Bits256::from_hex_str(TEST_RECIPIENT).unwrap(),
                    2_000,
                ) // Amount exceeds minted tokens
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .with_contract_ids(&[mailbox.into(), post_dispatch_id.into()])
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(get_revert_reason(call.unwrap_err()), "NotEnoughCoins");
        }

        /// ============ max_supply_enforcement_handle_message ============
        #[tokio::test]
        async fn test_max_supply_enforcement_handle_message() {
            let (config, warp_route, _, _, _, _) = get_synthetic_contract_instance().await;
            let wallet = warp_route.account();
            let local_decimals = config.decimals.unwrap() as u32;

            warp_route
                .methods()
                .set_remote_router_decimals(
                    Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap(),
                    local_decimals as u8,
                )
                .call()
                .await
                .map_err(|e| format!("Error occured while setting decimals: {:?}", e))
                .unwrap();

            mock_recieve_for_mint(
                wallet.clone(),
                warp_route.clone(),
                MAX_SUPPLY - 1,
                local_decimals,
                local_decimals,
            )
            .await;

            // Assert that the initial cumulative supply is just below the max
            let initial_cumulative_supply = warp_route
                .methods()
                .get_cumulative_supply()
                .call()
                .await
                .unwrap()
                .value;
            assert_eq!(initial_cumulative_supply, MAX_SUPPLY - 1);

            let body = build_message_body(Bits256(Address::from(wallet.address()).into()), 5);

            let call = warp_route
                .methods()
                .handle(
                    TEST_REMOTE_DOMAIN,
                    Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap(),
                    body,
                )
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
                token_mode: WarpRouteTokenMode::NATIVE,
                token_name: Some("ETH".to_string()),
                token_symbol: Some("ETH".to_string()),
                decimals: Some(9),
                total_supply: Some(MAX_SUPPLY),
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
            let (warp_route, contract_id, mailbox_id, post_dispatch_id, _, _) =
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

        /// ============ transfer_remote_native ============  
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
            let amount = 180_000_000;

            let remote_decimals = warp_route
                .methods()
                .remote_router_decimals(Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap())
                .call()
                .await
                .unwrap()
                .value;

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
            assert_eq!(log.amount, amount * 10u64.pow(remote_decimals as u32 - 9));

            let contract_balance_after =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            assert_eq!(contract_balance_before + amount, contract_balance_after);
        }

        /// ============ handle_message_native ============
        #[tokio::test]
        async fn test_handle_message_native() {
            let (_, warp_route, _, _, _) = get_native_contract_instance().await;

            let wallet = warp_route.account();
            let sender = Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap();
            let amount = 181_555_123_444_000_000;

            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
            let recipient_address = Address::from_str(TEST_RECIPIENT).unwrap();
            let body = build_message_body(recipient, amount);

            let remote_decimals = warp_route
                .methods()
                .remote_router_decimals(sender)
                .call()
                .await
                .unwrap()
                .value;

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

            //only mailbox can send authorized token recieve messages which triggers handle_message
            mock_mailbox_setup(wallet.clone(), warp_route.clone()).await;

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
                    amount: amount / 10u64.pow(remote_decimals as u32 - 9),
                }]
            );

            let recipient_balance_after =
                get_balance(provider, &recipient_address.into(), get_native_asset())
                    .await
                    .unwrap();

            assert_eq!(
                recipient_balance_before + amount / 10u64.pow(remote_decimals as u32 - 9),
                recipient_balance_after
            );
        }

        /// ============ claim_native ============  
        #[tokio::test]
        async fn test_claim_native() {
            let (config, warp_route, warp_route_id, mailbox, post_dispatch_id) =
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
                .claim(config.asset_id.unwrap())
                .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
                .call()
                .await
                .unwrap();

            let contract_balance_after =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            assert_eq!(
                contract_balance_before_claim,
                contract_balance_after + amount
            );
        }
    }
}
