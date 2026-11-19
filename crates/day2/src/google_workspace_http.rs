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
                } else if first
                    == "GET /admin/directory/v1/groups/engineering@synthetic.example?fields=id%2Cemail%2Cname&prettyPrint=false HTTP/1.1"
                {
                    anyhow::ensure!(request.contains("Bearer directory-token"), "bearer missing");
                    respond(&mut stream, "200 OK", "", r#"{"id":"g1","email":"engineering@synthetic.example","name":"Engineering"}"#)?;
                } else if first
                    == "GET /admin/directory/v1/groups/engineering@synthetic.example/hasMember/ada@synthetic.example?prettyPrint=false HTTP/1.1"
                {
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

    /// The three Calendar reads send exactly the reviewed exchanges, routes and
    /// queries, in order: a token delegated to the grant's reader with the two
    /// Calendar scopes, the reader's own rule first, and compact responses.
    #[test]
    fn native_calendar_reads_use_fixed_routes_queries_scopes_and_order() -> Result<()> {
        use base64::Engine;
        use std::{net::TcpListener, thread};
        const READER: &str = "calendar-reader@synthetic.example";
        const CALENDAR: &str = "GET /calendar/v3/calendars/c_engineering@group.calendar.google.com";
        const EVENT: &str = r#"{"id":"standup0001","status":"confirmed","start":{"dateTime":"2026-01-05T17:00:00Z"},"end":{"dateTime":"2026-01-05T17:30:00Z"},"conferenceData":{"conferenceId":"abc-defg-hij","conferenceSolution":{"key":{"type":"hangoutsMeet"}}}}"#;
        let auth = [
            "GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1".to_owned(),
            "POST /v1/projects/-/serviceAccounts/workspace-reader@synthetic-project.iam.gserviceaccount.com:signJwt HTTP/1.1".to_owned(),
            "POST /token HTTP/1.1".to_owned(),
        ];
        let rule = format!(
            "{CALENDAR}/acl/user:{READER}?fields=scope%28type%2Cvalue%29%2Crole&prettyPrint=false HTTP/1.1"
        );
        let reader_rule =
            format!(r#"{{"scope":{{"type":"user","value":"{READER}"}},"role":"writer"}}"#);
        // Each action's API requests, after its own three exchanges.
        let actions: Vec<Vec<(String, String)>> = vec![
            vec![
                (rule.clone(), reader_rule.clone()),
                (
                    format!("{CALENDAR}?fields=id%2Csummary&prettyPrint=false HTTP/1.1"),
                    r#"{"id":"c_engineering@group.calendar.google.com","summary":"Engineering"}"#.into(),
                ),
                (
                    format!("{CALENDAR}/acl?maxResults=250&fields=items%28scope%28type%2Cvalue%29%2Crole%29%2CnextPageToken&prettyPrint=false HTTP/1.1"),
                    r#"{"items":[{"scope":{"type":"group","value":"engineering@synthetic.example"},"role":"reader"}]}"#.into(),
                ),
            ],
            vec![
                (rule.clone(), reader_rule.clone()),
                (
                    format!("{CALENDAR}/events?singleEvents=true&orderBy=startTime&showDeleted=true&maxResults=25&timeMin=2026-01-01T00%3A00%3A00Z&timeMax=2026-01-31T00%3A00%3A00Z&pageToken=next&fields=items%28id%2CoriginalStartTime%2Cstart%2Cend%2Cstatus%2Cvisibility%2Ccreator%2Femail%2Corganizer%2Femail%2CconferenceData%28conferenceId%2CconferenceSolution%2Fkey%2Ftype%29%2ChangoutLink%29%2CnextPageToken&prettyPrint=false HTTP/1.1"),
                    format!(r#"{{"items":[{EVENT}]}}"#),
                ),
            ],
            vec![
                (rule.clone(), reader_rule),
                (
                    format!("{CALENDAR}/events/standup0001?fields=id%2CoriginalStartTime%2Cstart%2Cend%2Cstatus%2Cvisibility%2Ccreator%2Femail%2Corganizer%2Femail%2CconferenceData%28conferenceId%2CconferenceSolution%2Fkey%2Ftype%29%2ChangoutLink&prettyPrint=false HTTP/1.1"),
                    EVENT.into(),
                ),
            ],
        ];
        let expected: Vec<String> = actions
            .iter()
            .flat_map(|calls| {
                auth.iter()
                    .cloned()
                    .chain(calls.iter().map(|(line, _)| line.clone()))
            })
            .collect();
        let replies: Vec<String> = actions
            .into_iter()
            .flat_map(|calls| calls.into_iter().map(|(_, body)| body))
            .collect();
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let origin = format!("http://{}", listener.local_addr()?);
        let count = expected.len();
        let server = thread::spawn(move || -> Result<Vec<String>> {
            let mut lines = Vec::new();
            let mut replies = replies.into_iter();
            let mut signed = String::new();
            for _ in 0..count {
                let (mut stream, _) = listener.accept()?;
                let request = http_request(&mut stream)?;
                let first = request.lines().next().unwrap_or_default().to_owned();
                let body = request
                    .split_once("\r\n\r\n")
                    .map(|(_, body)| body)
                    .unwrap_or_default();
                if first.starts_with("GET /computeMetadata/") {
                    respond(
                        &mut stream,
                        "200 OK",
                        "Metadata-Flavor: Google\r\n",
                        r#"{"access_token":"workload-token","token_type":"Bearer","expires_in":3600}"#,
                    )?;
                } else if first.starts_with("POST /v1/projects/") {
                    // Exactly the reader, both scopes and the fixed lifetime.
                    let input: serde_json::Value = serde_json::from_str(body)?;
                    let payload = input["payload"].as_str().unwrap_or_default();
                    anyhow::ensure!(
                        request.contains("Bearer workload-token")
                            && serde_json::from_str::<serde_json::Value>(payload)?
                                == serde_json::json!({
                                    "iss":"workspace-reader@synthetic-project.iam.gserviceaccount.com",
                                    "sub":READER,
                                    "aud":"https://oauth2.googleapis.com/token",
                                    "iat":100,"exp":400,
                                    "scope":"https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/calendar.acls.readonly"}),
                        "delegated claims invalid: {payload}"
                    );
                    let part = |bytes: &[u8]| {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
                    };
                    signed = format!(
                        "{}.{}.{}",
                        part(br#"{"alg":"RS256","kid":"key-1"}"#),
                        part(payload.as_bytes()),
                        part(&[7; 64])
                    );
                    respond(
                        &mut stream,
                        "200 OK",
                        "",
                        &serde_json::json!({"keyId":"key-1","signedJwt":signed}).to_string(),
                    )?;
                } else if first.starts_with("POST /token ") {
                    anyhow::ensure!(
                        body == crate::google_auth::assertion_form(&signed),
                        "assertion form invalid"
                    );
                    respond(
                        &mut stream,
                        "200 OK",
                        "",
                        r#"{"access_token":"calendar-token","token_type":"Bearer","expires_in":3600}"#,
                    )?;
                } else {
                    anyhow::ensure!(request.contains("Bearer calendar-token"), "bearer missing");
                    let reply = replies
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("unexpected request: {first}"))?;
                    respond(&mut stream, "200 OK", "", &reply)?;
                }
                lines.push(first);
            }
            Ok(lines)
        });
        let plan =
            |action, request: &str| crate::google_workspace::tests::plan_for(action, request);
        use day2_capabilities::resources::Action;
        let plans = [
            plan(
                Action::GoogleWorkspaceCalendar,
                r#"{"handle":"h","calendar_id":"c_engineering@group.calendar.google.com","group_email":"engineering@synthetic.example"}"#,
            )?,
            plan(
                Action::GoogleWorkspaceCalendarEvents,
                r#"{"handle":"h","calendar_id":"c_engineering@group.calendar.google.com","time_min":"2026-01-01T00:00:00Z","time_max":"2026-01-31T00:00:00Z","page_token":{"Some":"next"}}"#,
            )?,
            plan(
                Action::GoogleWorkspaceCalendarEvent,
                r#"{"handle":"h","calendar_id":"c_engineering@group.calendar.google.com","event_id":"standup0001"}"#,
            )?,
        ];
        let mut port = NativeGooglePort::transport_fixture(&origin)?;
        let mut results = Vec::new();
        for plan in &plans {
            let (result, meter) = crate::google_workspace::observe(plan, &mut port, 100);
            assert!(meter.calls <= plan.planned_calls());
            results.push(serde_json::from_str::<serde_json::Value>(&result?)?);
        }
        let lines = server.join().expect("fixture server panicked")?;
        assert_eq!(lines, expected);
        assert_eq!(
            results[0],
            serde_json::json!({"Found":{"id":"c_engineering@group.calendar.google.com","summary":"Engineering","group_role":"Reader"}})
        );
        assert_eq!(
            results[1]["Found"]["events"][0]["meeting_code"],
            serde_json::json!({"Some":"abc-defg-hij"})
        );
        assert_eq!(results[2]["Found"]["id"], "standup0001");
        Ok(())
    }
}
