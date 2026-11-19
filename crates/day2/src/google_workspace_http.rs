//! Native Google Workspace HTTPS port. Every origin, method and header is fixed
//! here: no resource, application field or provider response can select one.
//! [`crate::google_workspace`] owns order, bounds and classification; this port
//! sends exactly the exchange or request it is given over one fixed-origin
//! client that follows no redirect, retries nothing and uses no proxy.
use crate::google_auth::{self, AccessToken, Exchange, Origins, Reply, Unreached};
use crate::google_workspace::{
    ApiRequest, CALENDAR_ORIGIN, DIRECTORY_ORIGIN, DRIVE_ORIGIN, GooglePort, MEET_ORIGIN, Service,
};
use anyhow::Result;

pub struct NativeGooglePort {
    client: reqwest::blocking::Client,
    origins: Origins,
    directory: reqwest::Url,
    calendar: reqwest::Url,
    meet: reqwest::Url,
    drive: reqwest::Url,
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
            meet: reqwest::Url::parse(MEET_ORIGIN)?,
            drive: reqwest::Url::parse(DRIVE_ORIGIN)?,
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
            calendar: url.clone(),
            meet: url.clone(),
            drive: url,
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
            Service::Meet => self.meet.clone(),
            Service::Drive => self.drive.clone(),
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
        // A request with a body is the one write, a JSON POST; every other
        // request is a GET.
        let response = match request.body() {
            Some(body) => self
                .client
                .post(url)
                .header(reqwest::header::AUTHORIZATION, authorization)
                .header(reqwest::header::ACCEPT, "application/json")
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_owned())
                .send(),
            None => self
                .client
                .get(url)
                .header(reqwest::header::AUTHORIZATION, authorization)
                .header(reqwest::header::ACCEPT, "application/json")
                .send(),
        }
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
                    format!("{CALENDAR}/acl?maxResults=100&fields=items%28scope%28type%2Cvalue%29%2Crole%29%2CnextPageToken&prettyPrint=false HTTP/1.1"),
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

    const READER: &str = "calendar-reader@synthetic.example";
    const OWNER: &str = "ada@synthetic.example";
    const CALENDAR: &str = "GET /calendar/v3/calendars/c_engineering@group.calendar.google.com";
    const AUTH: [&str; 3] = [
        "GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1",
        "POST /v1/projects/-/serviceAccounts/workspace-reader@synthetic-project.iam.gserviceaccount.com:signJwt HTTP/1.1",
        "POST /token HTTP/1.1",
    ];
    const CALENDAR_SCOPES: &str = "https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/calendar.acls.readonly";

    /// One API request a fixture expects: its request line, the subject whose
    /// token it must carry, and the reply.
    type Expected = (String, &'static str, String);

    /// The reader's rule and the event, as every Meet action reads them first.
    fn reader_reads() -> Vec<Expected> {
        let event = format!(
            r#"{{"id":"standup0001","status":"confirmed","start":{{"dateTime":"2026-01-05T17:00:00Z"}},"end":{{"dateTime":"2026-01-05T17:30:00Z"}},"organizer":{{"email":"{OWNER}"}},"creator":{{"email":"{OWNER}"}},"conferenceData":{{"conferenceId":"abc-defg-hij","conferenceSolution":{{"key":{{"type":"hangoutsMeet"}}}}}}}}"#
        );
        vec![
            (
                format!("{CALENDAR}/acl/user:{READER}?fields=scope%28type%2Cvalue%29%2Crole&prettyPrint=false HTTP/1.1"),
                READER,
                format!(r#"{{"scope":{{"type":"user","value":"{READER}"}},"role":"writer"}}"#),
            ),
            (
                format!("{CALENDAR}/events/standup0001?fields=id%2CoriginalStartTime%2Cstart%2Cend%2Cstatus%2Cvisibility%2Ccreator%2Femail%2Corganizer%2Femail%2CconferenceData%28conferenceId%2CconferenceSolution%2Fkey%2Ftype%29%2ChangoutLink&prettyPrint=false HTTP/1.1"),
                READER,
                event,
            ),
            (
                "GET /v2/conferenceRecords?pageSize=5&filter=space.meeting_code+%3D+%22abc-defg-hij%22+AND+start_time+%3E%3D+%222026-01-05T16%3A30%3A00Z%22+AND+start_time+%3C%3D+%222026-01-05T18%3A00%3A00Z%22&fields=conferenceRecords%28name%2Cspace%2CstartTime%2CendTime%29%2CnextPageToken&prettyPrint=false HTTP/1.1".into(),
                OWNER,
                r#"{"conferenceRecords":[{"name":"conferenceRecords/conf-1","space":"spaces/space1","startTime":"2026-01-05T17:01:00.123Z","endTime":"2026-01-05T17:29:00Z"}]}"#.into(),
            ),
        ]
    }

    /// Serve the reader's and then the owner's exchanges, checking each
    /// delegation's subject and scopes and each request's bearer, and the API
    /// requests in order. Returns every request line and every request body.
    fn delegated(
        plan: &crate::google_workspace::Plan,
        mut api: Vec<Expected>,
        owner_scopes: &'static str,
        group: Option<Expected>,
    ) -> Result<(Result<String>, Vec<String>, Vec<String>)> {
        use base64::Engine;
        use std::{net::TcpListener, thread};
        // A share resolves its group as the service account itself between
        // the reader's reads and the owner's.
        let directory: Vec<String> = group
            .iter()
            .flat_map(|(line, ..)| [
                AUTH[0].to_owned(),
                "POST /v1/projects/-/serviceAccounts/workspace-reader@synthetic-project.iam.gserviceaccount.com:generateAccessToken HTTP/1.1".to_owned(),
                line.clone(),
            ])
            .collect();
        let expected: Vec<String> = AUTH
            .iter()
            .map(|line| (*line).to_owned())
            .chain(api[..2].iter().map(|(line, ..)| line.clone()))
            .chain(directory)
            .chain(AUTH.iter().map(|line| (*line).to_owned()))
            .chain(api[2..].iter().map(|(line, ..)| line.clone()))
            .collect();
        if let Some(group) = group {
            api.insert(2, group);
        }
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let origin = format!("http://{}", listener.local_addr()?);
        let count = expected.len();
        let server = thread::spawn(move || -> Result<(Vec<String>, Vec<String>)> {
            let (mut lines, mut bodies) = (Vec::new(), Vec::new());
            let mut api = api.into_iter();
            let mut delegations = [(READER, CALENDAR_SCOPES), (OWNER, owner_scopes)].into_iter();
            let (mut signed, mut subject) = (String::new(), "");
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
                } else if first.contains(":generateAccessToken ") {
                    // Exactly the Directory scope, as the service account.
                    anyhow::ensure!(
                        serde_json::from_str::<serde_json::Value>(body)?
                            == serde_json::json!({"lifetime":"3600s","scope":[
                                crate::google_workspace::GROUP_READ_SCOPE]}),
                        "directory token request invalid"
                    );
                    subject = "directory";
                    respond(
                        &mut stream,
                        "200 OK",
                        "",
                        r#"{"accessToken":"token-for-directory","expireTime":"2030-01-01T00:00:00Z"}"#,
                    )?;
                } else if first.starts_with("POST /v1/projects/") {
                    let (sub, scope) = delegations
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("an unplanned delegation"))?;
                    let input: serde_json::Value = serde_json::from_str(body)?;
                    let payload = input["payload"].as_str().unwrap_or_default();
                    anyhow::ensure!(
                        serde_json::from_str::<serde_json::Value>(payload)?
                            == serde_json::json!({
                                "iss":"workspace-reader@synthetic-project.iam.gserviceaccount.com",
                                "sub":sub,"aud":"https://oauth2.googleapis.com/token",
                                "iat":100,"exp":400,"scope":scope}),
                        "delegated claims invalid: {payload}"
                    );
                    subject = sub;
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
                        &serde_json::json!({"access_token":format!("token-for-{subject}"),
                            "token_type":"Bearer","expires_in":3600})
                        .to_string(),
                    )?;
                } else {
                    let (_, bearer, reply) = api
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("unexpected request: {first}"))?;
                    anyhow::ensure!(
                        request.contains(&format!("Bearer token-for-{bearer}")),
                        "{first} carried another subject's token"
                    );
                    bodies.push(body.to_owned());
                    respond(&mut stream, "200 OK", "", &reply)?;
                }
                lines.push(first);
            }
            Ok((lines, bodies))
        });
        let mut port = NativeGooglePort::transport_fixture(&origin)?;
        let (result, meter) = crate::google_workspace::observe(plan, &mut port, 100);
        let (lines, bodies) = server.join().expect("fixture server panicked")?;
        assert_eq!(lines, expected);
        assert_eq!(meter.calls, count as u64);
        Ok((result, lines, bodies))
    }

    /// An event's conferences: the reader's exchanges, rule and event; then
    /// exchanges for the event's owner alone, with Meet's read scope alone;
    /// then the pinned records filter and each record's three artifact lists.
    #[test]
    fn native_event_conferences_delegate_to_the_reader_then_only_the_owner() -> Result<()> {
        const RECORD: &str = "GET /v2/conferenceRecords/conf-1";
        let mut api = reader_reads();
        api.extend([
            (
                format!("{RECORD}/recordings?pageSize=5&fields=recordings%28name%2Cstate%2CdriveDestination%28file%29%29%2CnextPageToken&prettyPrint=false HTTP/1.1"),
                OWNER,
                r#"{"recordings":[{"name":"conferenceRecords/conf-1/recordings/rec-1","state":"FILE_GENERATED","driveDestination":{"file":"1fileId"}}]}"#.into(),
            ),
            (
                format!("{RECORD}/smartNotes?pageSize=5&fields=smartNotes%28name%2Cstate%2CdocsDestination%28document%29%29%2CnextPageToken&prettyPrint=false HTTP/1.1"),
                OWNER,
                "{}".into(),
            ),
            (
                format!("{RECORD}/transcripts?pageSize=5&fields=transcripts%28name%2Cstate%2CdocsDestination%28document%29%29%2CnextPageToken&prettyPrint=false HTTP/1.1"),
                OWNER,
                r#"{"transcripts":[{"name":"conferenceRecords/conf-1/transcripts/tr-1","state":"STARTED"}]}"#.into(),
            ),
        ]);
        let plan = crate::google_workspace::tests::plan_for(
            day2_capabilities::resources::Action::GoogleWorkspaceEventConferences,
            r#"{"handle":"h","calendar_id":"c_engineering@group.calendar.google.com","event_id":"standup0001"}"#,
        )?;
        let (result, ..) = delegated(
            &plan,
            api,
            "https://www.googleapis.com/auth/meetings.space.readonly",
            None,
        )?;
        let found: serde_json::Value = serde_json::from_str(&result?)?;
        assert_eq!(found["Found"]["owner"], OWNER);
        assert_eq!(
            found["Found"]["records"][0]["recordings"][0]["file_id"],
            serde_json::json!({"Some":"1fileId"})
        );
        assert_eq!(
            found["Found"]["records"][0]["transcripts"][0]["state"],
            "Started"
        );
        Ok(())
    }

    /// The share: the group is resolved as the service account with the
    /// Directory scope alone, the owner is delegated with Meet's read scope and Drive's,
    /// the artifact is read by its exact name, the file's permissions are
    /// listed, and only then is the one reviewed permission created, with
    /// exactly the reviewed body.
    #[test]
    fn native_share_lists_before_it_creates_the_one_reviewed_permission() -> Result<()> {
        const FILES: &str = "/drive/v3/files/1fileId/permissions";
        let mut api = reader_reads();
        api.extend([
            (
                "GET /v2/conferenceRecords/conf-1/recordings/rec-1?fields=name%2Cstate%2CdriveDestination%28file%29&prettyPrint=false HTTP/1.1".into(),
                OWNER,
                r#"{"name":"conferenceRecords/conf-1/recordings/rec-1","state":"FILE_GENERATED","driveDestination":{"file":"1fileId"}}"#.into(),
            ),
            (
                format!("GET {FILES}?supportsAllDrives=true&pageSize=100&fields=permissions%28id%2Ctype%2Crole%2CemailAddress%2Cdeleted%29%2CnextPageToken&prettyPrint=false HTTP/1.1"),
                OWNER,
                format!(r#"{{"permissions":[{{"id":"1","type":"user","role":"owner","emailAddress":"{OWNER}","deleted":false}}]}}"#),
            ),
            (
                format!("POST {FILES}?supportsAllDrives=true&sendNotificationEmail=false&fields=id%2Ctype%2Crole%2CemailAddress&prettyPrint=false HTTP/1.1"),
                OWNER,
                r#"{"id":"0987654321","type":"group","role":"reader","emailAddress":"engineering@synthetic.example"}"#.into(),
            ),
        ]);
        let plan = crate::google_workspace::tests::plan_for(
            day2_capabilities::resources::Action::GoogleWorkspaceShareArtifact,
            r#"{"handle":"h","calendar_id":"c_engineering@group.calendar.google.com","event_id":"standup0001","artifact":"conferenceRecords/conf-1/recordings/rec-1","group_email":"engineering@synthetic.example"}"#,
        )?;
        let (result, _, bodies) = delegated(
            &plan,
            api,
            "https://www.googleapis.com/auth/meetings.space.readonly https://www.googleapis.com/auth/drive",
            Some((
                "GET /admin/directory/v1/groups/engineering@synthetic.example?fields=id%2Cemail%2Cname&prettyPrint=false HTTP/1.1".into(),
                "directory",
                r#"{"id":"g1","email":"engineering@synthetic.example","name":"Engineering"}"#.into(),
            )),
        )?;
        assert_eq!(result?, r#"{"Shared":{"permission_id":"0987654321"}}"#);
        assert_eq!(
            bodies.last().map(String::as_str),
            Some(
                r#"{"type":"group","role":"reader","emailAddress":"engineering@synthetic.example"}"#
            )
        );
        assert!(bodies[..bodies.len() - 1].iter().all(String::is_empty));
        Ok(())
    }
}
