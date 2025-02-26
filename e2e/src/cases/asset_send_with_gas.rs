use test_utils::get_revert_reason;
use tokio::time::Instant;

use fuels::{
    programs::calls::CallParameters,
    types::{transaction_builders::VariableOutputPolicy, AssetId, Bits256, Bytes},
};

use crate::{
    cases::TestCase,
    setup::{
        abis::{InterchainGasPaymaster, Mailbox, PostDispatchHook, WarpRoute},
        get_loaded_wallet,
    },
    utils::{
        get_remote_domain, get_remote_test_recipient,
        local_contracts::{get_contract_address_from_yaml, load_remote_wr_addresses},
        token::{get_contract_balance, get_local_fuel_base_asset},
    },
};

async fn asset_send_claim_gas() -> Result<f64, String> {
    let start = Instant::now();

    let wallet = get_loaded_wallet().await;
    let warp_route_id = get_contract_address_from_yaml("warpRouteNative");
    let fuel_mailbox_id = get_contract_address_from_yaml("mailbox");
    let igp_id = get_contract_address_from_yaml("interchainGasPaymaster");
    let post_dispatch_hook_id = get_contract_address_from_yaml("postDispatch");
    let gas_oracle_id = get_contract_address_from_yaml("gasOracle");

    let mailbox_instance = Mailbox::new(fuel_mailbox_id, wallet.clone());
    let fuel_igp_instance = InterchainGasPaymaster::new(igp_id, wallet.clone());
    let warp_route_instance = WarpRoute::new(warp_route_id, wallet.clone());
    let post_dispatch = PostDispatchHook::new(post_dispatch_hook_id, wallet.clone());

    let remote_domain = get_remote_domain();
    let remote_wr = load_remote_wr_addresses("CTR").unwrap();
    let base_asset: AssetId = get_local_fuel_base_asset();
    let test_recipient = get_remote_test_recipient();

    let amount = 1000;

    warp_route_instance
        .methods()
        .set_hook(igp_id)
        .call()
        .await
        .map_err(|e| format!("Failed to set igp hook to wr: {:?}", e))?;

    mailbox_instance
        .methods()
        .set_default_hook(igp_id)
        .call()
        .await
        .map_err(|e| format!("Failed to set default hook to mailbox: {:?}", e))?;

    mailbox_instance
        .methods()
        .set_required_hook(post_dispatch_hook_id)
        .call()
        .await
        .map_err(|e| format!("Failed to set required hook to mailbox: {:?}", e))?;

    let quote = fuel_igp_instance
        .methods()
        .quote_gas_payment(remote_domain, 5000)
        .with_contract_ids(&[gas_oracle_id.into(), igp_id.into()])
        .call()
        .await
        .map_err(|e| format!("Failed to get quote: {:?}", e))?;

    let post_dispatch_qoute = post_dispatch
        .methods()
        .quote_dispatch(Bytes(vec![]), Bytes(vec![]))
        .with_contract_ids(&[igp_id.into(), gas_oracle_id.into()])
        .call()
        .await
        .map_err(|e| format!("Failed to get quote: {:?}", e))?;

    let remote_wr_hex = hex::decode(remote_wr.strip_prefix("0x").unwrap()).unwrap();
    let mut remote_wr_array = [0u8; 32];
    remote_wr_array[12..].copy_from_slice(&remote_wr_hex);

    let mailbox_qoute = mailbox_instance
        .methods()
        .quote_dispatch(
            remote_domain,
            Bits256(remote_wr_array),
            Bytes(vec![]),
            Bytes(vec![]),
            igp_id,
        )
        .with_contract_ids(&[
            igp_id.into(),
            gas_oracle_id.into(),
            post_dispatch_hook_id.into(),
            igp_id.into(),
        ])
        .call()
        .await
        .map_err(|e| format!("Failed to get quote from mailbox: {:?}", e))?;

    assert!(
        mailbox_qoute.value == quote.value + post_dispatch_qoute.value,
        "Mailbox quote is not the sum of IGP and post dispatch quotes"
    );

    let wr_quote = warp_route_instance
        .methods()
        .quote_gas_payment(remote_domain)
        .determine_missing_contracts(Some(6))
        .await
        .unwrap()
        .call()
        .await
        .map_err(|e| format!("Failed to get quote from warp route: {:?}", e))?;

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

    let warp_balance_before = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    let igp_balance_before =
        get_contract_balance(wallet.provider().unwrap(), &igp_id.into(), base_asset)
            .await
            .unwrap();

    //Attempt to send remote message with overpayment should fail
    let gas_overpayment = warp_route_instance
        .methods()
        .transfer_remote(remote_domain, test_recipient, amount, None, None)
        .call_params(CallParameters::new(
            amount + wr_quote.value + 1,
            base_asset,
            10_000_000,
        ))
        .unwrap()
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .with_contract_ids(&[
            fuel_mailbox_id.into(),
            igp_id.into(),
            gas_oracle_id.into(),
            post_dispatch_hook_id.into(),
        ])
        .call()
        .await;

    assert!(gas_overpayment.is_err());
    assert_eq!(
        get_revert_reason(gas_overpayment.unwrap_err()),
        "PaymentNotEqualToRequired"
    );

    let _ = warp_route_instance
        .methods()
        .transfer_remote(remote_domain, test_recipient, amount, None, None)
        .call_params(CallParameters::new(
            amount + wr_quote.value,
            base_asset,
            10_000_000,
        ))
        .unwrap()
        .with_variable_output_policy(VariableOutputPolicy::EstimateMinimum)
        .with_contract_ids(&[
            fuel_mailbox_id.into(),
            igp_id.into(),
            gas_oracle_id.into(),
            post_dispatch_hook_id.into(),
        ])
        .call()
        .await
        .map_err(|e| format!("Failed to transfer remote message: {:?}", e))?;

    let warp_balance_after = get_contract_balance(
        wallet.provider().unwrap(),
        warp_route_instance.contract_id(),
        base_asset,
    )
    .await
    .unwrap();

    if warp_balance_after != warp_balance_before + amount {
        return Err(format!(
            "Warp balance is increased by {:?}, expected {:?}",
            warp_balance_after - warp_balance_before,
            amount
        ));
    }

    let igp_balance_after =
        get_contract_balance(wallet.provider().unwrap(), &igp_id.into(), base_asset)
            .await
            .unwrap();

    if igp_balance_after != igp_balance_before + wr_quote.value {
        return Err(format!(
            "IGP balance is increased by {:?}, expected {:?}",
            igp_balance_after - igp_balance_before,
            wr_quote.value
        ));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("asset_send_with_gas", asset_send_claim_gas)
}
