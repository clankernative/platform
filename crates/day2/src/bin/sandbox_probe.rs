#![forbid(unsafe_code)]
// Native test canary, deliberately more capable than the Roc platform.
use anyhow::{Context, Result};
use std::{
    io::{self, BufRead},
    net::{SocketAddr, TcpStream},
    process::Command,
    time::Duration,
};
fn main() -> Result<()> {
    let raw = io::stdin().lock().lines().next().context("probe input")??;
    let input: serde_json::Value = serde_json::from_str(&raw)?;
    match input["mode"].as_str() {
        Some("hang") => loop {
            std::hint::black_box(1);
        },
        Some("oversize") => {
            println!("{}", "x".repeat(1_048_577));
            return Ok(());
        }
        _ => {}
    }
    let read = input["read"].as_str().context("read path")?;
    let write = input["write"].as_str().context("write path")?;
    let address: SocketAddr = input["address"].as_str().context("address")?.parse()?;
    println!(
        "{}",
        serde_json::json!({
            "read": std::fs::read_to_string(read).is_ok(),
            "write": std::fs::write(write,b"canary").is_ok(),
            "network": TcpStream::connect_timeout(&address,Duration::from_millis(500)).is_ok(),
            "exec": Command::new("/usr/bin/true").status().is_ok_and(|status|status.success()),
            "environment": std::env::var("DAY2_PROBE_SECRET").is_ok(),
        })
    );
    Ok(())
}
