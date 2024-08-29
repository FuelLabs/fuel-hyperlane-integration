use std::time::Duration;

use crate::cases::TestCase;
use tokio::time::{sleep, Instant};

async fn example_test() -> Result<f64, String> {
    let start = Instant::now();

    println!("example_test");
    sleep(Duration::from_secs(1)).await;

    if start.elapsed().as_micros() % 2 == 0 {
        return Err("Example Fail".to_string());
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("example_test", example_test)
}
