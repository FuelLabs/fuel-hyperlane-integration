script;

use std::{
    asset::transfer,
    bytes::Bytes,
    call_frames::msg_asset_id,
    context::{
        balance_of,
        msg_amount,
        this_balance,
    },
    contract_id::ContractId,
    convert::Into,
    hash::*,
    revert::revert,
    storage::storage_map::*,
    storage::storage_string::*,
    storage::storage_vec::*,
    string::String,
    u128::U128,
};

use interfaces::{mailbox::mailbox::*, warp_route::WarpRoute};

fn main(
    warp_route_address: b256,
    destination: u32,
    recipient: b256,
    amount: u64,
    asset_id: b256,
    gas_payment: u64,
) -> b256 {
    let warp_route = abi(WarpRoute, warp_route_address);
    transfer(
        Identity::ContractId(ContractId::from(warp_route_address)),
        AssetId::from(asset_id),
        amount,
    );

    let msg_id = warp_route.transfer_remote {
        asset_id: b256::from(AssetId::base()),
        coins: gas_payment,
    }(destination, recipient, amount, None, None);

    msg_id
}
