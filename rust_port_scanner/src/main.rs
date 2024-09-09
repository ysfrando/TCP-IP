use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::env;
use futures::future::join_all;

async fn scan_port(host: &str, port: u16) -> bool {
    let addr = format!("{}:{}", host, port);
    match timeout(Duration::from_millis(300), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <host> <start-port> <end-port>", args[0]);
        std::process::exit(1);
    }

    let host = &args[1];
    let start_port: u16 = args[2].parse().expect("Invalid start port");
    let end_port: u16 = args[3].parse().expect("Invalid end port");

    println!("Scanning {} from port {} to {}", host, start_port, end_port);

    let mut tasks = vec![];

    for port in start_port..=end_port {
        let host = host.clone();
        tasks.push(tokio::spawn(async move {
            if scan_port(&host, port).await {
                println!("Port {} is open", port);
            }
        }));
    }

    // Await all tasks
    let _ = join_all(tasks).await;
}
