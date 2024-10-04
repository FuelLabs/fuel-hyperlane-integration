use fuels::{
    prelude::*,
    types::{Bits256, EvmAddress},
};

use crate::{
    setup::{
        abis::*, deploy_all_hooks, deploy_all_isms, deploy_core_contracts, deploy_test_contracts,
        get_loaded_wallet,
    },
    utils::constants::*,
    utils::token::{
        get_native_asset, get_token_metadata,
        send_gas_to_contract,
    },
};

use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};

pub struct ContractRegistry {
    pub mailbox: Mailbox<WalletUnlocked>,
    pub warp_route: WarpRoute<WalletUnlocked>,
    pub igp: InterchainGasPaymaster<WalletUnlocked>,
    pub gas_oracle: GasOracle<WalletUnlocked>,
    pub igp_hook: IGPHook<WalletUnlocked>,
    pub merkle_tree_hook: MerkleTreeHook<WalletUnlocked>,
    pub aggregation_ism: AggregationISM<WalletUnlocked>,
    pub multisig_ism: MessageIdMultisigISM<WalletUnlocked>,
    pub message_id_multisig_ism: MerkleRootMultisigISM<WalletUnlocked>,
    pub routing_ism: DomainRoutingISM<WalletUnlocked>,
    pub optimism_ism: DefaultFallbackDomainRoutingISM<WalletUnlocked>,
    pub msg_recipient: MsgRecipient<WalletUnlocked>,
}

impl Clone for ContractRegistry {
    fn clone(&self) -> Self {
        ContractRegistry {
            mailbox: self.mailbox.clone(),
            warp_route: self.warp_route.clone(),
            igp: self.igp.clone(),
            gas_oracle: self.gas_oracle.clone(),
            igp_hook: self.igp_hook.clone(),
            merkle_tree_hook: self.merkle_tree_hook.clone(),
            aggregation_ism: self.aggregation_ism.clone(),
            multisig_ism: self.multisig_ism.clone(),
            message_id_multisig_ism: self.message_id_multisig_ism.clone(),
            routing_ism: self.routing_ism.clone(),
            optimism_ism: self.optimism_ism.clone(),
            msg_recipient: self.msg_recipient.clone(),
        }
    }
}

pub static CONTRACT_REGISTRY: Lazy<Mutex<Option<Arc<ContractRegistry>>>> =
    Lazy::new(|| Mutex::new(None));

pub async fn initialize_contract_registry() -> Arc<ContractRegistry> {
    let mut guard = CONTRACT_REGISTRY.lock().expect("Failed to acquire lock");
    if guard.is_none() {
        let wallet = get_loaded_wallet().await;
        let registry = Arc::new(initialize_all_contracts(&wallet).await);
        *guard = Some(Arc::clone(&registry));
    }
    Arc::clone(guard.as_ref().unwrap())
}

pub fn get_contract_registry() -> Arc<ContractRegistry> {
    let guard = CONTRACT_REGISTRY.lock().expect("Failed to acquire lock");
    if let Some(registry) = guard.as_ref() {
        Arc::clone(registry)
    } else {
        drop(guard); // Release the lock before initializing
        tokio::runtime::Runtime::new()
            .expect("Failed to create runtime")
            .block_on(initialize_contract_registry())
    }
}

pub async fn initialize_all_contracts(wallet: &WalletUnlocked) -> ContractRegistry {
    let (mailbox, warp_route, igp, gas_oracle) = deploy_core_contracts().await;
    let (igp_hook, merkle_tree_hook) = deploy_all_hooks().await;
    let (aggregation_ism, multisig_ism, message_id_multisig_ism, routing_ism, optimism_ism) =
        deploy_all_isms().await;
    let msg_recipient = deploy_test_contracts().await;

    let owner = Bits256(Address::from(wallet.address()).into());
    let hook_address = Bits256(ContractId::from(igp_hook.contract_id()).into());

    let gas_configs = get_test_remote_gas_data_configs();
    let token_config = get_token_metadata();

    aggregation_ism
        .methods()
        .initialize(owner)
        .call()
        .await
        .unwrap();

    igp.methods()
        .initialize(
            owner,
            owner,
            TOKEN_EXCHANGE_RATE,
            BASE_ASSET_DECIMALS,
            DEFAULT_LOCAL_GAS,
        )
        .call()
        .await
        .unwrap();

    gas_oracle
        .methods()
        .initialize_ownership(wallet.address().into())
        .call()
        .await
        .unwrap();

    gas_oracle
        .methods()
        .set_remote_gas_data_configs(gas_configs.clone())
        .call()
        .await
        .unwrap();

    igp.methods()
        .set_gas_oracle(
            TEST_REMOTE_DOMAIN,
            Bits256(gas_oracle.contract_id().hash().into()),
        )
        .call()
        .await
        .unwrap();

    igp.methods()
        .set_gas_oracle(
            TEST_LOCAL_DOMAIN,
            Bits256(gas_oracle.contract_id().hash().into()),
        )
        .call()
        .await
        .unwrap();

    igp_hook
        .methods()
        .initialize(igp.contract_id())
        .call()
        .await
        .unwrap();

    mailbox
        .methods()
        .initialize(
            owner,
            Bits256(ContractId::from(aggregation_ism.contract_id()).into()),
            hook_address,
            hook_address,
        )
        .call()
        .await
        .unwrap();

    warp_route
        .methods()
        .initialize(
            owner,
            Bits256(mailbox.contract_id().hash().into()),
            WarpRouteTokenMode::COLLATERAL,
            hook_address,
            token_config.name,
            token_config.symbol,
            token_config.decimals,
            token_config.total_supply,
            Some(get_native_asset()),
        )
        .call()
        .await
        .unwrap();

    aggregation_ism
        .methods()
        .set_threshold(0)
        .call()
        .await
        .unwrap();

    //TODO: Check ISMS initialization

    let multisig_threshold = 1; // Example threshold
    message_id_multisig_ism
        .methods()
        .set_threshold(multisig_threshold)
        .call()
        .await
        .unwrap();

    multisig_ism
        .methods()
        .set_threshold(multisig_threshold)
        .call()
        .await
        .unwrap();

    routing_ism
        .methods()
        .initialize(owner)
        .call()
        .await
        .unwrap();

    let validator_address = wallet.address(); // Replace with actual validator addresses
    message_id_multisig_ism
        .methods()
        .enroll_validator(EvmAddress::from(Bits256(validator_address.hash().into())))
        .call()
        .await
        .unwrap();

    multisig_ism
        .methods()
        .enroll_validator(EvmAddress::from(Bits256(validator_address.hash().into())))
        .call()
        .await
        .unwrap();

    routing_ism
        .methods()
        .set(
            TEST_LOCAL_DOMAIN,
            Bits256(message_id_multisig_ism.contract_id().hash().into()),
        )
        .call()
        .await
        .unwrap();

    send_gas_to_contract(
        wallet.clone(),
        warp_route.contract_id(),
        WARP_ROUTE_GAS_AMOUNT,
    )
    .await;

    send_gas_to_contract(wallet.clone(), igp.contract_id(), WARP_ROUTE_GAS_AMOUNT).await;

    ContractRegistry {
        mailbox,
        warp_route,
        igp,
        gas_oracle,
        igp_hook,
        merkle_tree_hook,
        aggregation_ism,
        multisig_ism,
        message_id_multisig_ism,
        routing_ism,
        optimism_ism,
        msg_recipient,
    }
}
