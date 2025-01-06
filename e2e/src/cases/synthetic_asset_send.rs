use crate::{
    cases::TestCase,
    evm::{get_evm_wallet, monitor_fuel_for_delivery, SepoliaContracts},
    setup::{
        abis::{Mailbox, WarpRoute},
        get_loaded_wallet,
    },
    utils::{
        get_local_domain, get_remote_domain,
        local_contracts::{get_contract_address_from_yaml, load_remote_wr_addresses},
        token::{get_balance, get_contract_balance, send_gas_to_contract_2},
        TEST_RECIPIENT,
    },
};
use alloy::primitives::{FixedBytes, U256};
use fuels::types::{transaction_builders::VariableOutputPolicy, Bits256};
use tokio::time::Instant;

async fn synthetic_asset_send() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;
    let warp_route_id = get_contract_address_from_yaml("warpRouteSynthetic");
    let fuel_mailbox_id = get_contract_address_from_yaml("mailbox");
    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let gas_oracle_id = get_contract_address_from_yaml("gasOracle");
    let post_dispatch_hook_id = get_contract_address_from_yaml("postDispatch");
    let ism_id = get_contract_address_from_yaml("interchainSecurityModule");

    let warp_route_instance = WarpRoute::new(warp_route_id, wallet.clone());
    let mailbox_instance = Mailbox::new(fuel_mailbox_id, wallet.clone());

    let remote_domain = get_remote_domain();
    let test_recipient = Bits256::from_hex_str(TEST_RECIPIENT).unwrap();
    let remote_wr = load_remote_wr_addresses("NTR").unwrap();
    let remote_wr_hex = hex::decode(remote_wr.strip_prefix("0x").unwrap()).unwrap();

    let mut remote_wr_array = [0u8; 32];
    remote_wr_array[12..].copy_from_slice(&remote_wr_hex);

    //get token info
    let token_info = warp_route_instance
        .methods()
        .get_token_info()
        .call()
        .await
        .map_err(|e| format!("Failed to get token info: {:?}", e))?;

    let asset_id = token_info.value.asset_id;

    let wallet_balance_before_mint =
        get_balance(wallet.provider().unwrap(), wallet.address(), asset_id)
            .await
            .unwrap();

    // ------------------------------------------------------------------------------------------------
    //MOCK TOKEN MINTING
    //minting is same as recieving remote adjusted amount
    //if 1*10^18 is sent, the minted amount is 1*10^(18-local_decimals)

    warp_route_instance
        .methods()
        .enroll_remote_router(remote_domain, Bits256(remote_wr_array))
        .call()
        .await
        .map_err(|e| format!("Failed to enroll remote router: {:?}", e))?;

    warp_route_instance
        .methods()
        .set_remote_router_decimals(Bits256(remote_wr_array), 9)
        .call()
        .await
        .map_err(|e| format!("Failed to set remote router decimals: {:?}", e))?;

    // warp_route_instance
    //     .methods()
    //     .set_remote_router_decimals(test_recipient, 9)
    //     .call()
    //     .await
    //     .unwrap();

    let local_decimals = token_info.value.decimals;
    // let remote_adjusted_amount = amount * 10u64.pow(18 - local_decimals as u32);

    let amount = 100_000_000_000_000;

    let remote_wallet = get_evm_wallet().await;
    let contracts = SepoliaContracts::initialize(remote_wallet).await;
    let remote_wr = contracts.warp_route_synthetic;

    let fuel_domain = get_local_domain();
    let recipient = FixedBytes::from_slice(wallet.address().hash.as_slice());
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

    let remote_adjusted_amount = amount / 10u64.pow((18 - local_decimals).into());

    let wallet_balance = get_balance(wallet.provider().unwrap(), wallet.address(), asset_id)
        .await
        .unwrap();

    if wallet_balance - wallet_balance_before_mint != remote_adjusted_amount {
        return Err(format!(
            "Wallet balance after mint does not match mint amount: {:?}",
            wallet_balance - wallet_balance_before_mint
        ));
    }

    //get updated token info
    let token_info_updated = warp_route_instance
        .methods()
        .get_token_info()
        .call()
        .await
        .unwrap();

    if token_info_updated.value.total_supply
        != token_info.value.total_supply + remote_adjusted_amount
    {
        return Err(format!(
            "Total supply after mint does not match mint amount: {:?}",
            token_info_updated.value.total_supply
        ));
    }

    // ------------------------------------------------------------------------------------------------

    let _ = send_gas_to_contract_2(
        wallet.clone(),
        warp_route_instance.contract_id(),
        remote_adjusted_amount,
        asset_id,
    )
    .await;

    let _ = warp_route_instance
        .methods()
        .transfer_remote(remote_domain, test_recipient, remote_adjusted_amount)
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .with_contract_ids(&[
            fuel_mailbox_id.into(),
            igp_id.into(),
            gas_oracle_id.into(),
            post_dispatch_hook_id.into(),
            ism_id.into(),
        ])
        .call()
        .await
        .map_err(|e| format!("Failed to transfer remote message: {:?}", e))?;

    let warp_balance_after = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route_instance.contract_id(),
        asset_id,
    )
    .await
    .unwrap();

    if warp_balance_after != 0 {
        return Err(format!(
            "Warp balance after is not 0: {:?}",
            warp_balance_after
        ));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("synthetic_asset_send", synthetic_asset_send)
}
