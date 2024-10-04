// use super::TestCase;
// use crate::setup::{abis::Mailbox, get_loaded_wallet, get_mailbox};
// use fuels::accounts::wallet::WalletUnlocked;
// use tokio::time::Instant;

// async fn mailbox_get_domain() -> Result<f64, String> {
//     let start = Instant::now();

//     let res = get_loaded_wallet().await;
//     println!("res: {:?}", res);
//     println!("res: {:?}", res);

//     println!("test_2_test");
//     let mailbox: Mailbox<WalletUnlocked> = match get_mailbox().await {
//         Ok(mailbox) => mailbox,
//         Err(err) => {
//             return Err(err.to_string());
//         }
//     };

//     let domain_res = mailbox.methods().local_domain().call().await;

//     if domain_res.is_err() {
//         // unwrap errror and return it as string
//         let err = domain_res.unwrap_err();
//         Err(err.to_string())
//     } else {
//         let domain_res = domain_res.unwrap();

//         println!("Domain: {:?}", domain_res.value);
//         if domain_res.value == 0 {
//             return Err("Domain is not 0".to_string());
//         }

//         Ok(start.elapsed().as_secs_f64())
//     }
// }

// pub fn test() -> TestCase {
//     TestCase::new("mailbox_get_domain", mailbox_get_domain)
// }
