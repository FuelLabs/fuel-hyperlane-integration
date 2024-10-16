use crate::setup::abis::{RemoteGasData, RemoteGasDataConfig};

pub const TEST_LOCAL_DOMAIN: u32 = 0x6675656c;
pub const TEST_REMOTE_DOMAIN: u32 = 9913371;
pub const TEST_RECIPIENT: &str =
    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub const TEST_MESSAGE_ID: &str =
    "0x6ae9a99190641b9ed0c07143340612dde0e9cb7deaa5fe07597858ae9ba5fd7f";

//WARP ROUTE
pub const WARP_ROUTE_GAS_AMOUNT: u64 = 10_000_000_000;
pub const BRIDGED_ASSET_ID: &str =
    "6fa0fecded4a4b1f57b908435dc44d2f0b77834414d385d744c5c96cc2296471";

//GAS
pub const TEST_GAS_AMOUNT: u64 = 30_000;
pub const TOKEN_EXCHANGE_RATE: u64 = 1;
pub const BASE_ASSET_DECIMALS: u8 = 6;
pub const DEFAULT_LOCAL_GAS: u64 = 50_000;

pub fn get_test_remote_gas_data_configs() -> Vec<RemoteGasDataConfig> {
    vec![
        RemoteGasDataConfig {
            domain: TEST_LOCAL_DOMAIN,
            remote_gas_data: RemoteGasData {
                token_exchange_rate: TOKEN_EXCHANGE_RATE.into(),
                gas_price: DEFAULT_LOCAL_GAS.into(),
                token_decimals: BASE_ASSET_DECIMALS,
            },
        },
        RemoteGasDataConfig {
            domain: TEST_REMOTE_DOMAIN,
            remote_gas_data: RemoteGasData {
                token_exchange_rate: TOKEN_EXCHANGE_RATE.into(),
                gas_price: TEST_GAS_AMOUNT.into(),
                token_decimals: 9u8,
            },
        },
    ]
}
