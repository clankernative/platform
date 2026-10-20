//! Idle lifecycle health DATA only. This has no current/native authority.
use anyhow::Result;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener},
    time::Duration,
};

pub(super) struct Health {
    listener: TcpListener,
}

impl Health {
    pub(super) fn bind() -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 8080))?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener })
    }

    pub(super) fn serve_one(&self) -> Result<()> {
        let (mut connection, _) = match self.listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        connection.set_read_timeout(Some(Duration::from_millis(100)))?;
        connection.set_write_timeout(Some(Duration::from_millis(100)))?;
        let mut request = [0u8; 512];
        // Malformed/slow health peers cannot cause a role/permission action.
        // A single request has a bounded buffer and configured OS timeouts;
        // neither these nor scheduling imply a hard elapsed-time guarantee.
        if let Ok(size) = connection.read(&mut request) {
            let response = response(&request[..size]);
            let _ = connection.write_all(response);
        }
        Ok(())
    }
}

fn response(request: &[u8]) -> &'static [u8] {
    if request.starts_with(b"GET /health/ready HTTP/1.")
        || request.starts_with(b"GET /health/live HTTP/1.")
    {
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    } else {
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    }
}

#[cfg(test)]
mod tests {
    use super::response;

    #[test]
    fn health_has_only_fixed_read_only_routes() {
        assert!(response(b"GET /health/ready HTTP/1.1\r\n\r\n").starts_with(b"HTTP/1.1 200"));
        assert!(response(b"GET /health/live HTTP/1.0\r\n\r\n").starts_with(b"HTTP/1.1 200"));
        for request in [
            b"POST /health/ready HTTP/1.1".as_slice(),
            b"GET /health/ready/foreign HTTP/1.1",
            b"GET /admin HTTP/1.1",
            b"",
        ] {
            assert!(response(request).starts_with(b"HTTP/1.1 404"));
        }
    }
}
