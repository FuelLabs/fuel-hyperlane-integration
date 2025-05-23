use crate::{
    cases::TestCase,
    evm::{get_evm_wallet, monitor_fuel_for_delivery, SepoliaContracts},
    setup::{
        abis::{Mailbox, WarpRoute},
        get_loaded_wallet,
    },
    utils::{
        get_fuel_domain, get_fuel_test_recipient,
        local_contracts::{get_contract_address_from_yaml, load_remote_wr_addresses},
    },
};
use alloy::primitives::{FixedBytes, U256};
use fuels::types::Bits256;
use tokio::time::Instant;

async fn synthetic_asset_recieve() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;
    let warp_route_id = get_contract_address_from_yaml("warpRouteSynthetic");
    let mailbox_id = get_contract_address_from_yaml("mailbox");

    let warp_route_instance = WarpRoute::new(warp_route_id, wallet.clone());
    let mailbox_instance = Mailbox::new(mailbox_id, wallet.clone());

    //get token info
    let token_metadata = warp_route_instance
        .methods()
        .get_token_info()
        .call()
        .await
        .map_err(|e| format!("Failed to get token info: {:?}", e))?;

    let is_paused = warp_route_instance
        .methods()
        .is_paused()
        .call()
        .await
        .unwrap();
    assert!(!is_paused.value, "Warp route is paused");

    let remote_wr = load_remote_wr_addresses("NTR").unwrap();
    let remote_wr_hex = hex::decode(remote_wr.strip_prefix("0x").unwrap()).unwrap();

    let mut remote_wr_array = [0u8; 32];
    remote_wr_array[12..].copy_from_slice(&remote_wr_hex);

    let _ = warp_route_instance
        .methods()
        .set_remote_router_decimals(Bits256(remote_wr_array), 18)
        .call()
        .await
        .unwrap();

    let _asset_id = token_metadata.value.asset_id;
    let decimals = token_metadata.value.decimals;

    let amount = 100_000_000_000_000;

    let remote_wallet = get_evm_wallet().await;
    let contracts = SepoliaContracts::initialize(remote_wallet).await;
    let remote_wr = contracts.warp_route_synthetic;

    let fuel_domain = get_fuel_domain();
    let recipient = get_fuel_test_recipient();
    let fuel_wr_parsed = FixedBytes::from_slice(warp_route_id.as_slice());

    warp_route_instance
        .methods()
        .set_remote_router_decimals(Bits256(remote_wr_array), 18)
        .call()
        .await
        .unwrap();

    let _ = remote_wr
        .enrollRemoteRouter(fuel_domain, fuel_wr_parsed)
        .send()
        .await
        .unwrap()
        .watch()
        .await
        .map_err(|e| format!("Failed enroll router: {:?}", e))?;

    let quote_dispatch = remote_wr
        .quoteGasPayment(fuel_domain)
        .call()
        .await
        .unwrap()
        ._0;

    let _ = remote_wr
        .transferRemote_1(fuel_domain, recipient, U256::from(amount))
        .value(quote_dispatch + U256::from(amount))
        .send()
        .await
        .unwrap()
        .watch()
        .await
        .map_err(|e| format!("Failed enroll router: {:?}", e))?;

    let remote_mailbox = contracts.mailbox;
    let msg_id = remote_mailbox.latestDispatchedId().call().await.unwrap()._0;

    if FixedBytes::const_is_zero(&msg_id) {
        return Err("Failed to deliver message".to_string());
    }

    let res = monitor_fuel_for_delivery(mailbox_instance.clone(), msg_id).await;

    assert!(res, "Failed to recieve message from remote");

    let amount_18dec_to_local = amount / 10u64.pow((18 - decimals).into());

    //ensure circulating supply is increased by amount
    let token_metadata_final = warp_route_instance
        .methods()
        .get_token_info()
        .call()
        .await
        .map_err(|e| format!("Failed to get token metadata: {:?}", e))?;

    if token_metadata_final.value.total_supply
        != token_metadata.value.total_supply + amount_18dec_to_local
    {
        return Err(format!(
            "Circulating supply mismatch. Expected: {}, Got: {}",
            token_metadata.value.total_supply + amount_18dec_to_local,
            token_metadata_final.value.total_supply
        ));
    }

    println!("✅ synthetic_asset_recieve test passed");

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("synthetic_asset_recieve", synthetic_asset_recieve)
}
