use anyhow::{Result, ensure};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    num::NonZeroU16,
    time::Duration,
};

fn check() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() == 2 && arguments[1] == "--drain-delay" {
        std::thread::sleep(Duration::from_secs(30));
        return Ok(());
    }
    ensure!(
        arguments.len() == 1 || (arguments.len() == 2 && arguments[1] == "--candidate"),
        "usage: day2-health PUBLISHED_PORT [--candidate]"
    );
    let path = if arguments.len() == 2 {
        "/health/candidate"
    } else {
        "/health/ready"
    };
    let published: NonZeroU16 = arguments[0].parse()?;
    let mut socket = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)),
        Duration::from_secs(2),
    )?;
    socket.set_read_timeout(Some(Duration::from_secs(if arguments.len() == 2 {
        30
    } else {
        2
    })))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(
        socket,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{published}\r\nConnection: close\r\n\r\n"
    )?;
    let mut line = String::new();
    BufReader::new(socket).take(1024).read_line(&mut line)?;
    ensure!(
        line.starts_with("HTTP/1.1 200 ") && line.ends_with("\r\n"),
        "not ready"
    );
    Ok(())
}

fn main() {
    if check().is_err() {
        std::process::exit(1);
    }
}
