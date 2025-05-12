mod cases;
mod evm;
mod setup;
mod utils;

use cases::{pull_test_cases, FailedTestCase};
use dotenv::dotenv;
use tokio::{sync::mpsc, time::Instant};
use utils::summary;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    dotenv().ok();
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
}
