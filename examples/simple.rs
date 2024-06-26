extern crate futures;
extern crate tokio;
extern crate tokio_icmp_echo;

use std::time::Duration;

use tokio_icmp_echo::PingFutureKind;

#[tokio::main]
async fn main() {
    let addr = std::env::args().nth(1).unwrap().parse().unwrap();

    let pinger = tokio_icmp_echo::Pinger::new().await.unwrap();
    let ping_result = pinger.ping(addr, 0, 0, Duration::from_secs(2)).await;
    match ping_result {
        PingFutureKind::Normal(time) => {
            println!("time={:?}", time)
        }
        PingFutureKind::NoResponse => {
            println!("timeout")
        }
        _ => {
            println!("error: {:?}", ping_result)
        }
    }
}
