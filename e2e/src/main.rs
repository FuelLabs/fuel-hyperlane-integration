mod cases;
mod setup;
mod utils;

use cases::{pull_test_cases, FailedTestCase};
use setup::{cleanup, setup};
use tokio::{sync::mpsc, task, time::Instant};
use utils::summary;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let fuel_node = setup().await;
    println!("\nRunning E2E tests\n");
    let start = Instant::now();

    let all_test_cases = pull_test_cases();
    let mut failed_test_cases: Vec<FailedTestCase> = vec![];
    let test_amount = all_test_cases.len();

    let (tx, mut rx) = mpsc::channel(test_amount);

    for test in all_test_cases {
        let tx = tx.clone();
        let test_name = test.name().clone();
        let result = test.run().await;
        tx.send((test_name, result)).await.unwrap();
    }
    drop(tx);

    while let Some((name, case_result)) = rx.recv().await {
        match case_result {
            Ok(duration) => {
                println!("{} passed - {:.3} sec", name, duration);
            }
            Err(e) => {
                println!("{} failed: {:?}", name, e);
                failed_test_cases.push(FailedTestCase::new(name, e));
            }
        }
    }

    summary(test_amount, failed_test_cases, start);
    // cleanup(fuel_node).await;
}

//For mock e2e tests
//let registry = get_contract_registry();

// let (tx, mut rx) = mpsc::channel(1); // Limit to 1 concurrent test

// for test_case in all_test_cases {
//     let tx = tx.clone();
//     let registry = Arc::clone(&registry);
//     task::spawn(async move {
//         let name = test_case.name();
//         tokio::time::sleep(tokio::time::Duration::from_millis(100)).await; // Add a small delay

//         // Reset wallet state here if needed
//         setup::get_loaded_wallet().await;

//         let result = test_case.run(registry).await;
//         tx.send((name, result)).await.unwrap();
//     });
// }
// drop(tx);
