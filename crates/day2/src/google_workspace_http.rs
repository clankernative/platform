//! Native Google Workspace HTTPS port. Every origin, method and header is fixed
//! here: no resource, application field or provider response can select one.
//! [`crate::google_workspace`] owns order, bounds and classification; this port
//! sends exactly the exchange or request it is given over one fixed-origin
//! client that follows no redirect, retries nothing and uses no proxy.
use crate::google_auth::{self, AccessToken, Exchange, Origins, Reply, Unreached};
use crate::google_workspace::{ApiRequest, CALENDAR_ORIGIN, DIRECTORY_ORIGIN, GooglePort, Service};
use anyhow::Result;

pub struct NativeGooglePort {
    client: reqwest::blocking::Client,
    origins: Origins,
    directory: reqwest::Url,
    calendar: reqwest::Url,
}

impl NativeGooglePort {
    pub fn new() -> Result<Self> {
        let timing = crate::request_timing::span("provider_client");
        // The metadata server is plain HTTP on the link-local network; every
        // other origin is a fixed HTTPS Google route.
        let client = google_auth::native_client(false)
            .map_err(|_| anyhow::anyhow!("google_workspace_unavailable"))?;
        drop(timing);
        Ok(Self {
            client,
            origins: Origins::production()?,
            directory: reqwest::Url::parse(DIRECTORY_ORIGIN)?,
            calendar: reqwest::Url::parse(CALENDAR_ORIGIN)?,
        })
    }

    /// Loopback origins for request-exact transport tests only.
    #[cfg(test)]
    pub(crate) fn transport_fixture(origin: &str) -> Result<Self> {
        let url = reqwest::Url::parse(origin)?;
        anyhow::ensure!(
            url.scheme() == "http"
                && matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
                && (url.path().is_empty() || url.path() == "/"),
            "invalid_google_workspace_fixture_origin"
        );
        Ok(Self {
            client: google_auth::native_client(false)?,
            origins: Origins::fixture(url.clone(), url.clone(), url.join("/token")?),
            directory: url.clone(),
            calendar: url,
        })
    }
}

impl GooglePort for NativeGooglePort {
    fn authenticate(
        &mut self,
        exchange: &Exchange<'_>,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        google_auth::send_native(
            &self.client,
            &self.origins,
            "google_workspace",
            exchange,
            max_bytes,
        )
    }

    fn call(
        &mut self,
        request: &ApiRequest,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        let mut url = match request.service {
            Service::Directory => self.directory.clone(),
            Service::Calendar => self.calendar.clone(),
        };
        url.path_segments_mut()
            .map_err(|_| Unreached::default())?
            .clear()
            .extend(&request.segments);
        url.set_query(request.query_string().as_deref());
        let mut authorization =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.bearer()))
                .map_err(|_| Unreached::default())?;
        authorization.set_sensitive(true);
        let mut timing = crate::request_timing::provider("google_workspace", request.endpoint);
        let response = self
            .client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .map_err(|_| Unreached::default())?;
        timing.status(response.status().as_u16());
        google_auth::read_native(response, max_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_request(stream: &mut std::net::TcpStream) -> Result<String> {
        use std::io::Read;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut chunk)?;
            bytes.push(chunk[0]);
            anyhow::ensure!(bytes.len() <= 32 * 1024, "fixture request too large");
        }
        let header_end = bytes.len();
        let length = String::from_utf8_lossy(&bytes)
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        bytes.resize(header_end + length, 0);
        stream.read_exact(&mut bytes[header_end..])?;
        Ok(String::from_utf8(bytes)?)
    }

    fn respond(
        stream: &mut std::net::TcpStream,
        status: &str,
        extra: &str,
        body: &str,
    ) -> Result<()> {
        use std::io::Write;
        write!(
            stream,
            "HTTP/1.1 {status}\r\n{extra}Content-Type: application/json; charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        stream.flush()?;
        Ok(())
    }

    /// The membership read sends exactly the reviewed exchanges and routes, in
    /// order, with the fixed scopes and no other header carrying a token.
    #[test]
    fn native_membership_read_uses_fixed_routes_scopes_and_order() -> Result<()> {
        use std::{net::TcpListener, thread};
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let origin = format!("http://{}", listener.local_addr()?);
        let server = thread::spawn(move || -> Result<Vec<String>> {
            let mut lines = Vec::new();
            for _ in 0..4 {
                let (mut stream, _) = listener.accept()?;
                let request = http_request(&mut stream)?;
                let first = request.lines().next().unwrap_or_default().to_owned();
                if first.starts_with("GET /computeMetadata/v1/instance/service-accounts/default/token ") {
                    anyhow::ensure!(
                        request.to_ascii_lowercase().contains("metadata-flavor: google"),
                        "metadata flavor missing"
                    );
                    respond(
                        &mut stream,
                        "200 OK",
                        "Metadata-Flavor: Google\r\n",
                        r#"{"access_token":"workload-token","token_type":"Bearer","expires_in":3600}"#,
                    )?;
                } else if first.starts_with(
                    "POST /v1/projects/-/serviceAccounts/workspace-reader@synthetic-project.iam.gserviceaccount.com:generateAccessToken ",
                ) {
                    let body = request.split_once("\r\n\r\n").map(|(_, body)| body).unwrap_or_default();
                    let input: serde_json::Value = serde_json::from_str(body)?;
                    anyhow::ensure!(
                        request.contains("Bearer workload-token")
                            && input
                                == serde_json::json!({"lifetime":"3600s","scope":[
                                    crate::google_workspace::GROUP_READ_SCOPE,
                                    crate::google_workspace::GROUP_MEMBER_READ_SCOPE]}),
                        "direct token request invalid"
                    );
                    respond(&mut stream, "200 OK", "", r#"{"accessToken":"directory-token","expireTime":"2030-01-01T00:00:00Z"}"#)?;
                } else if first.starts_with(
                    "GET /admin/directory/v1/groups/engineering@synthetic.example?fields=id%2Cemail%2Cname ",
                ) {
                    anyhow::ensure!(request.contains("Bearer directory-token"), "bearer missing");
                    respond(&mut stream, "200 OK", "", r#"{"id":"g1","email":"engineering@synthetic.example","name":"Engineering"}"#)?;
                } else if first.starts_with(
                    "GET /admin/directory/v1/groups/engineering@synthetic.example/hasMember/ada@synthetic.example ",
                ) {
                    anyhow::ensure!(request.contains("Bearer directory-token"), "bearer missing");
                    respond(&mut stream, "200 OK", "", r#"{"isMember":true}"#)?;
                } else {
                    anyhow::bail!("unexpected request: {first}")
                }
                lines.push(first);
            }
            Ok(lines)
        });
        let plan = crate::google_workspace::tests::plan_for(
            day2_capabilities::resources::Action::GoogleWorkspaceGroupMember,
            r#"{"handle":"h","group_email":"engineering@synthetic.example","member_email":"ada@synthetic.example"}"#,
        )?;
        let mut port = NativeGooglePort::transport_fixture(&origin)?;
        let (result, meter) = crate::google_workspace::observe(&plan, &mut port, 100);
        let lines = server.join().expect("fixture server panicked")?;
        assert_eq!(result?, r#""Member""#);
        assert_eq!(lines.len(), 4);
        assert_eq!(meter.calls, 4);
        Ok(())
    }
}
