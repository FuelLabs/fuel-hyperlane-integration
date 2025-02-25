#[cfg(test)]
mod warp_route {

    use fuels::{
        prelude::*,
        types::{Bits256, Identity, U256},
    };
    use hyperlane_core::{Encode, HyperlaneMessage, H256};
    use once_cell::sync::Lazy;
    use rand::{thread_rng, Rng};
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

    const TEST_RECIPIENT: &str =
        "0x2407159311d2abbf43ef472a9fd20a526abeadb048116b2ab5c93f7d1c733682";

    const COLLATERAL_ASSET_ID: &str =
        "f8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07";

    const TEST_LOCAL_DOMAIN: u32 = 1717982312;
    const TEST_REMOTE_DOMAIN: u32 = 11155111;

    const TOKEN_NAME: &str = "TestToken";
    const TOKEN_SYMBOL: &str = "TT";
    const DECIMALS: u8 = 9;
    const REMOTE_DECIMALS: u8 = 18;
    const TOTAL_SUPPLY: u64 = 100_000_000_000_000;
    const MAX_SUPPLY: u64 = 100_000_000_000_000;

    /// Helper functions
    fn get_collateral_asset() -> AssetId {
        AssetId::from_str(COLLATERAL_ASSET_ID).unwrap()
    }

    fn get_native_asset() -> AssetId {
        AssetId::BASE
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

    /// Asset recieve messages are only allowed when they are sent from mailbox
    pub fn _mock_asset_recieve_message(
        recipient: &Bech32ContractId,
        amount: u64,
        recipient_user: Bits256,
        sender: Bits256,
    ) -> HyperlaneMessage {
        let message_body = build_message_body(recipient_user, amount);

        HyperlaneMessage {
            version: 3u8,
            nonce: thread_rng().gen_range(0..1000000) as u32,
            origin: TEST_REMOTE_DOMAIN,
            sender: H256::from(sender.0),
            destination: TEST_LOCAL_DOMAIN,
            recipient: H256::from_slice(recipient.hash().as_slice()),
            body: message_body.into(),
        }
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

    async fn trigger_handle_by_sending_message_from_mailbox(
        mailbox: &Mailbox<WalletUnlocked>,
        warp_route: &WarpRoute<WalletUnlocked>,
        contract_ids: Vec<Bech32ContractId>,
        amount: u64,
        recipient: Option<Bits256>,
    ) {
        let remote_router_address =
            Bits256(Address::from_str(REMOTE_ROUTER_ADDRESS).unwrap().into());

        let recipient_b256 = match recipient {
            Some(r) => r,
            None => Bits256::from_hex_str(TEST_RECIPIENT).unwrap(),
        };

        let message = _mock_asset_recieve_message(
            &warp_route.contract_id().clone(),
            amount,
            recipient_b256,
            remote_router_address,
        );

        let _call = mailbox
            .methods()
            .process(Bytes(message.to_vec()), Bytes(message.to_vec()))
            .with_contract_ids(&contract_ids)
            .with_variable_output_policy(VariableOutputPolicy::Exactly(10))
            .call()
            .await
            .map_err(|e| format!("Failed send message from mailbox: {:?}", e));
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
        Mailbox<WalletUnlocked>,
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

        let owner = Identity::from(wallet.address());
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

        let mut call_handler = warp_route
            .methods()
            .initialize(
                owner,
                mailbox_address,
                config.token_mode.clone(),
                hook_address,
                default_ism_address,
                Some(config.token_name.clone().unwrap()),
                Some(config.token_symbol.clone().unwrap()),
                Some(config.decimals.unwrap()),
                Some(config.total_supply.unwrap()),
                asset_id,
                asset_contract_id,
            )
            .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum);

        if config.token_mode == WarpRouteTokenMode::COLLATERAL {
            call_handler = call_handler.with_contract_ids(&[collateral_token_contract_id]);
        }

        let warp_init_res = call_handler.call().await;
        assert!(warp_init_res.is_ok(), "Failed to initialize Warp Route.");

        let owner_identity = Identity::Address(wallet.address().into());
        let mailbox_init_res = mailbox
            .methods()
            .initialize(
                owner_identity,
                default_ism_address,
                hook_address,
                hook_address,
            )
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
                REMOTE_DECIMALS,
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
            mailbox,
            mailbox_id.into(),
            post_dispatch_id.into(),
            recipient_id.into(),
            default_ism_id.into(),
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
            Mailbox<WalletUnlocked>,
            ContractId,
            ContractId,
            ContractId,
        ) {
            let (
                warp_route,
                contract_id,
                mailbox,
                mailbox_id,
                post_dispatch_id,
                _,
                default_ism_id,
                collateral_token_id,
            ) = get_contract_instance(&COLLATERAL_CONFIG).await;

            let mut config = COLLATERAL_CONFIG.lock().await.clone();
            config.asset_id = Some(collateral_token_id);

            (
                config,
                warp_route,
                contract_id,
                mailbox,
                mailbox_id,
                post_dispatch_id,
                default_ism_id,
            )
        }

        /// ============ enroll_unenroll_router ============
        #[tokio::test]
        async fn test_enroll_unenroll_router() {
            let (_, warp_route, ..) = get_collateral_contract_instance().await;

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
            let (config, warp_route, ..) = get_collateral_contract_instance().await;

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
            let (config, warp_route, ..) = get_collateral_contract_instance().await;

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
            let (_, warp_route, ..) = get_collateral_contract_instance().await;

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
            let (_, warp_route, _, _, _, post_dispatch_id, _) =
                get_collateral_contract_instance().await;

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
            let (_, warp_route, _, _, mailbox_id, ..) = get_collateral_contract_instance().await;

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
            let (_, warp_route, ..) = get_collateral_contract_instance().await;
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
            let (_, warp_route, warp_route_id, _, mailbox_id, post_dispatch_id, _) =
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
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount, None, None)
                .with_contract_ids(&[
                    warp_route_id.into(),
                    mailbox_id.into(),
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
            let (
                _,
                warp_route,
                warp_route_id,
                mailbox,
                mailbox_id,
                post_dispatch_id,
                default_ism_id,
            ) = get_collateral_contract_instance().await;

            let wallet = warp_route.account();

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

            let remote_decimals = REMOTE_DECIMALS as u32;
            let recipient_address = Address::from_str(TEST_RECIPIENT).unwrap();
            let amount = 2 * 10u64.pow(REMOTE_DECIMALS as u32);

            let (_, _) = wallet
                .force_transfer_to_contract(
                    warp_route.contract_id(),
                    2 * 10u64.pow(REMOTE_DECIMALS as u32 - local_decimals),
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

            trigger_handle_by_sending_message_from_mailbox(
                &mailbox,
                &warp_route,
                vec![
                    warp_route_id.into(),
                    mailbox_id.into(),
                    post_dispatch_id.into(),
                    default_ism_id.into(),
                ],
                amount,
                None,
            )
            .await;

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
        }

        /// ============ claim_as_owner ============
        #[tokio::test]
        async fn test_claim_as_owner() {
            let (config, warp_route, warp_route_id, _, mailbox_id, post_dispatch_id, _) =
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
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount, None, None)
                .with_contract_ids(&[
                    warp_route_id.into(),
                    mailbox_id.into(),
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
                .claim(Some(config.asset_id.unwrap()))
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
            let (_, warp_route, .., mailbox_id, post_dispatch_id, _) =
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
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount_zero, None, None)
                .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
                .with_contract_ids(&[mailbox_id.into(), post_dispatch_id.into()])
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
            let (_, warp_route, warp_route_id, _, mailbox_id, post_dispatch_id, _) =
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
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount, None, None)
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
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount, None, None)
                .with_contract_ids(&[
                    warp_route_id.into(),
                    mailbox_id.into(),
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
            Mailbox<WalletUnlocked>,
            ContractId,
            ContractId,
            ContractId,
            ContractId,
        ) {
            let (
                warp_route,
                contract_id,
                mailbox,
                mailbox_id,
                post_dispatch_id,
                recipient_id,
                ism_id,
                _,
            ) = get_contract_instance(&SYNTHETIC_CONFIG).await;

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
                mailbox,
                mailbox_id,
                post_dispatch_id,
                recipient_id,
                ism_id,
            )
        }

        /// ============ get_token_info ============
        #[tokio::test]
        async fn test_get_token_info() {
            let (mut config, warp_route, ..) = get_synthetic_contract_instance().await;

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
            let (config, warp_route, ..) = get_synthetic_contract_instance().await;

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
            let (
                config,
                warp_route,
                _,
                mailbox,
                mailbox_id,
                post_dispatch_id,
                recipient_id,
                ism_id,
            ) = get_synthetic_contract_instance().await;

            let wallet = warp_route.account();
            let provider = wallet.provider().unwrap();
            let asset = config.asset_id.unwrap();

            let local_decimals = config.decimals.unwrap() as u32;
            let remote_decimals = REMOTE_DECIMALS as u32;
            let remote_decimal_amount = 10_u64.pow(remote_decimals);

            let amount = 10_u64.pow(remote_decimals - local_decimals);
            let recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();

            let wallet_balance_before_mint = get_balance(provider, wallet.address(), asset)
                .await
                .unwrap();

            assert_eq!(wallet_balance_before_mint, config.total_supply.unwrap());

            // For testing the synthetic asset, we actually need to have the tokens
            // Since the asset is managed by the warp route - we can mock the asset minting with handle call
            // in order to have `amount` we need to send `remote_decimal_amount` message to local warp route

            trigger_handle_by_sending_message_from_mailbox(
                &mailbox,
                &warp_route,
                vec![
                    warp_route.contract_id().into(),
                    mailbox.contract_id().into(),
                    post_dispatch_id.into(),
                    ism_id.into(),
                    recipient_id.into(),
                ],
                remote_decimal_amount,
                Some(Bits256(Address::from(wallet.address()).into())),
            )
            .await;

            let wallet_balance = get_balance(provider, wallet.address(), asset)
                .await
                .unwrap();

            assert_eq!(wallet_balance_before_mint + amount, wallet_balance);

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
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount, None, None)
                .with_contract_ids(&[mailbox_id.into(), post_dispatch_id.into()])
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
            let (config, warp_route, contract_id, mailbox, mailbox_id, post_dispatch_id, _, ism_id) =
                get_synthetic_contract_instance().await;

            let wallet = warp_route.account();
            let sender = Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap();
            let amount = 100_000_000_000_000_000;

            let recipient_address = Address::from_str(TEST_RECIPIENT).unwrap();

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

            trigger_handle_by_sending_message_from_mailbox(
                &mailbox,
                &warp_route,
                vec![
                    contract_id.into(),
                    mailbox_id.into(),
                    post_dispatch_id.into(),
                    ism_id.into(),
                ],
                amount,
                None,
            )
            .await;

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

        /// ============ sending_more_than_minted ============
        #[tokio::test]
        async fn test_sending_more_than_minted() {
            let (_, warp_route, _, _, mailbox_id, post_dispatch_id, _, _) =
                get_synthetic_contract_instance().await;

            let call = warp_route
                .methods()
                .transfer_remote(
                    TEST_REMOTE_DOMAIN,
                    Bits256::from_hex_str(TEST_RECIPIENT).unwrap(),
                    2_000,
                    None,
                    None,
                ) // Amount exceeds minted tokens
                .with_variable_output_policy(VariableOutputPolicy::Exactly(5))
                .with_contract_ids(&[mailbox_id.into(), post_dispatch_id.into()])
                .call()
                .await;

            assert!(call.is_err());
            assert_eq!(
                get_revert_reason(call.unwrap_err()),
                "AssetNotReceivedForTransfer"
            );
        }
    }
    mod native {
        use super::*;

        static NATIVE_CONFIG: Lazy<Mutex<WarpRouteConfig>> = Lazy::new(|| {
            Mutex::new(WarpRouteConfig {
                token_mode: WarpRouteTokenMode::NATIVE,
                token_name: Some("ETH".to_string()),
                token_symbol: Some("ETH".to_string()),
                decimals: Some(DECIMALS),
                total_supply: Some(MAX_SUPPLY),
                asset_id: Some(get_native_asset()),
            })
        });

        async fn get_native_contract_instance() -> (
            WarpRouteConfig,
            WarpRoute<WalletUnlocked>,
            ContractId,
            Mailbox<WalletUnlocked>,
            ContractId,
            ContractId,
            ContractId,
        ) {
            let (warp_route, contract_id, mailbox, mailbox_id, post_dispatch_id, _, ism_id, _) =
                get_contract_instance(&NATIVE_CONFIG).await;
            let config = NATIVE_CONFIG.lock().await.clone();

            (
                config,
                warp_route,
                contract_id,
                mailbox,
                mailbox_id,
                post_dispatch_id,
                ism_id,
            )
        }

        /// ============ transfer_remote_native ============  
        #[tokio::test]
        async fn test_transfer_remote_native() {
            let (config, warp_route, contract_id, _, mailbox_id, post_dispatch_id, _) =
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
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount, None, None)
                .call_params(call_params)
                .unwrap()
                .with_contract_ids(&[
                    contract_id.into(),
                    mailbox_id.into(),
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
            assert_eq!(
                log.amount,
                amount * 10u64.pow(remote_decimals as u32 - DECIMALS as u32)
            );

            let contract_balance_after =
                get_contract_balance(provider, warp_route.contract_id(), asset)
                    .await
                    .unwrap();

            assert_eq!(contract_balance_before + amount, contract_balance_after);
        }

        /// ============ handle_message_native ============
        #[tokio::test]
        async fn test_handle_message_native() {
            let (_, warp_route, contract_id, mailbox, mailbox_id, post_dispatch_id, ism_id) =
                get_native_contract_instance().await;

            let wallet = warp_route.account();
            let sender = Bits256::from_hex_str(REMOTE_ROUTER_ADDRESS).unwrap();
            let amount = 181_555_123_444_000_000;

            let recipient_address = Address::from_str(TEST_RECIPIENT).unwrap();

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

            trigger_handle_by_sending_message_from_mailbox(
                &mailbox,
                &warp_route,
                vec![
                    contract_id.into(),
                    mailbox_id.into(),
                    post_dispatch_id.into(),
                    ism_id.into(),
                ],
                amount,
                None,
            )
            .await;

            let recipient_balance_after =
                get_balance(provider, &recipient_address.into(), get_native_asset())
                    .await
                    .unwrap();

            assert_eq!(
                recipient_balance_before
                    + amount / 10u64.pow(remote_decimals as u32 - DECIMALS as u32),
                recipient_balance_after
            );
        }

        /// ============ claim_native ============  
        #[tokio::test]
        async fn test_claim_native() {
            let (config, warp_route, contract_id, _, mailbox_id, post_dispatch_id, _) =
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
                .transfer_remote(TEST_REMOTE_DOMAIN, recipient, amount, None, None)
                .call_params(call_params)
                .unwrap()
                .with_contract_ids(&[
                    contract_id.into(),
                    mailbox_id.into(),
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
                .claim(Some(config.asset_id.unwrap()))
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
