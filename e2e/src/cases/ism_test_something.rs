use crate::cases::TestCase;
use tokio::time::Instant;

async fn test_something_with_ism() -> Result<f64, String> {
    let start = Instant::now();

    println!("test_ism_test");

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("mailbox_get_domain", test_something_with_ism)
}
