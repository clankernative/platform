use anyhow::{Result, ensure};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    num::NonZeroU16,
    time::Duration,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainStatus {
    generation: String,
    admitting: bool,
    inflight: u64,
    streams: u64,
    quiesced: bool,
}

fn drain_response(bytes: &[u8]) -> Result<DrainStatus> {
    ensure!(bytes.len() <= 8192, "drain response budget");
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("drain response invalid"))?;
    ensure!(bytes.starts_with(b"HTTP/1.1 200 "), "not ready");
    let status: DrainStatus = serde_json::from_slice(&bytes[split + 4..])
        .map_err(|_| anyhow::anyhow!("drain response invalid"))?;
    ensure!(
        status
            .generation
            .strip_prefix("sha256:")
            .is_some_and(|hash| hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())),
        "drain generation invalid"
    );
    Ok(status)
}

fn check(arguments: &[String]) -> Result<()> {
    if arguments == ["--help"] {
        println!("usage: day2-health PUBLISHED_PORT [--candidate | --drain | --drain-delay]");
        return Ok(());
    }
    if arguments.len() == 2 && arguments[1] == "--drain-delay" {
        std::thread::sleep(Duration::from_secs(30));
        return Ok(());
    }
    ensure!(
        arguments.len() == 1
            || (arguments.len() == 2 && matches!(arguments[1].as_str(), "--candidate" | "--drain")),
        "usage: day2-health PUBLISHED_PORT [--candidate | --drain]"
    );
    let draining = arguments.get(1).is_some_and(|mode| mode == "--drain");
    let path = if draining {
        "/health/drain"
    } else if arguments.len() == 2 {
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
    if draining {
        let mut bytes = Vec::new();
        socket.take(8193).read_to_end(&mut bytes)?;
        println!("{}", serde_json::to_string(&drain_response(&bytes)?)?);
        return Ok(());
    }
    let mut line = String::new();
    BufReader::new(socket).take(1024).read_line(&mut line)?;
    ensure!(
        line.starts_with("HTTP/1.1 200 ") && line.ends_with("\r\n"),
        "not ready"
    );
    Ok(())
}

#[test]
fn drain_metadata_is_closed_bounded_and_never_echoes_malformed_private_values() {
    let body = serde_json::json!({"generation":format!("sha256:{}","a".repeat(64)),"admitting":true,"inflight":2,"streams":0,"quiesced":false});
    let bytes = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{body}");
    assert_eq!(drain_response(bytes.as_bytes()).unwrap().inflight, 2);
    assert!(drain_response(&vec![b'x'; 8193]).is_err());
    let error = drain_response(b"HTTP/1.1 200 OK\r\n\r\n{\"private-value\":\"secret\"}")
        .err()
        .unwrap();
    assert_eq!(format!("{error:#}"), "drain response invalid");
}

fn main() {
    if check(&std::env::args().skip(1).collect::<Vec<_>>()).is_err() {
        std::process::exit(1);
    }
}

#[test]
fn help_does_not_turn_malformed_health_probes_into_success() {
    assert!(check(&["--help".into()]).is_ok());
    for arguments in [
        vec![],
        vec!["0".into()],
        vec!["--unknown".into()],
        vec!["--help".into(), "--candidate".into()],
    ] {
        assert!(check(&arguments).is_err());
    }
}
