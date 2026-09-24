use anyhow::{Result, ensure};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    num::NonZeroU16,
    time::Duration,
};

fn check() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    ensure!(arguments.len() == 1, "usage: day2-health PUBLISHED_PORT");
    let published: NonZeroU16 = arguments[0].parse()?;
    let mut socket = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)),
        Duration::from_secs(2),
    )?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(
        socket,
        "GET /health/ready HTTP/1.1\r\nHost: 127.0.0.1:{published}\r\nConnection: close\r\n\r\n"
    )?;
    let mut line = String::new();
    BufReader::new(socket).take(1024).read_line(&mut line)?;
    ensure!(
        line.starts_with("HTTP/1.1 204 ") && line.ends_with("\r\n"),
        "not ready"
    );
    Ok(())
}

fn main() {
    if check().is_err() {
        std::process::exit(1);
    }
}
