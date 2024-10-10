use super::config::{
    get_contract_data, get_deployment_config, HyperlaneContract as HyperlaneContractVariant,
};
use super::{abis::*, get_loaded_wallet};
use fuels::prelude::*;

pub async fn deploy(
    variant: HyperlaneContractVariant,
) -> Result<(Bech32ContractId, WalletUnlocked)> {
    let binary_filepath = get_contract_data(variant).bin_path;

    let config = get_deployment_config();
    let contract = Contract::load_from(binary_filepath, config.clone()).unwrap();

    let wallet = get_loaded_wallet().await;

    Ok((
        contract.deploy(&wallet, TxPolicies::default()).await?,
        wallet,
    ))
}

// pub async fn deploy_with_wallet(
//     variant: HyperlaneContractVariant,
//     wallet: &WalletUnlocked,
// ) -> Bech32ContractId {
//     let binary_filepath = get_contract_data(variant).bin_path;

//     let config = get_deployment_config();
//     let contract = Contract::load_from(binary_filepath, config.clone()).unwrap();

//     contract
//         .deploy(wallet, TxPolicies::default())
//         .await
//         .unwrap()
// }

// pub async fn instantiate_mailbox() -> Result<(Mailbox<WalletUnlocked>, Bech32ContractId)> {
//     let (contract_id, wallet) = deploy(HyperlaneContractVariant::Mailbox).await?;
//     Ok((Mailbox::new(contract_id.clone(), wallet), contract_id))
// }

pub async fn deploy_test_contracts() -> MsgRecipient<WalletUnlocked> {
    let (contract_id, wallet) = deploy(HyperlaneContractVariant::MsgRecipient)
        .await
        .unwrap();

    MsgRecipient::new(contract_id.clone(), wallet)
}

pub async fn deploy_core_contracts() -> (
    Mailbox<WalletUnlocked>,
    WarpRoute<WalletUnlocked>,
    InterchainGasPaymaster<WalletUnlocked>,
    GasOracle<WalletUnlocked>,
) {
    let (contract_id, wallet) = deploy(HyperlaneContractVariant::Mailbox).await.unwrap();
    let mailbox = Mailbox::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::WarpRoute).await.unwrap();
    let warp_route = WarpRoute::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::InterchainGasPaymaster)
        .await
        .unwrap();

    let igp = InterchainGasPaymaster::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::GasOracle).await.unwrap();
    let gas_oracle = GasOracle::new(contract_id.clone(), wallet);

    (mailbox, warp_route, igp, gas_oracle)
}

pub async fn deploy_all_hooks() -> (IGPHook<WalletUnlocked>, MerkleTreeHook<WalletUnlocked>) {
    let (contract_id, wallet) = deploy(HyperlaneContractVariant::IGPHook).await.unwrap();
    let igp_hook = IGPHook::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::MerkleTreeHook)
        .await
        .unwrap();
    let merkle_tree_hook = MerkleTreeHook::new(contract_id.clone(), wallet);

    (igp_hook, merkle_tree_hook)
}

pub async fn deploy_all_isms() -> (
    AggregationISM<WalletUnlocked>,
    MessageIdMultisigISM<WalletUnlocked>,
    MerkleRootMultisigISM<WalletUnlocked>,
    DomainRoutingISM<WalletUnlocked>,
    DefaultFallbackDomainRoutingISM<WalletUnlocked>,
) {
    let (contract_id, wallet) = deploy(HyperlaneContractVariant::AggregationISM)
        .await
        .unwrap();
    let aggregation_ism = AggregationISM::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::MessageIdMultisigISM)
        .await
        .unwrap();
    let message_id_multisig_ism = MessageIdMultisigISM::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::MerkleRootMultisigISM)
        .await
        .unwrap();
    let merkle_root_multisig_ism = MerkleRootMultisigISM::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::DomainRoutingISM)
        .await
        .unwrap();
    let domain_routing_ism = DomainRoutingISM::new(contract_id.clone(), wallet);

    let (contract_id, wallet) = deploy(HyperlaneContractVariant::DefaultFallbackDomainRoutingISM)
        .await
        .unwrap();
    let default_fallback_domain_routing_ism =
        DefaultFallbackDomainRoutingISM::new(contract_id.clone(), wallet);

    (
        aggregation_ism,
        message_id_multisig_ism,
        merkle_root_multisig_ism,
        domain_routing_ism,
        default_fallback_domain_routing_ism,
    )
}
