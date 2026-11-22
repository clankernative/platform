//! Explicit operator-only provider recordings, never invoked by verification
//! or an application workflow. Roc owns request order. Only redacted DATA can
//! leave this session; raw replies and credentials have no output API.
mod redact;

use crate::carta_live::{AccessToken, CapturePlan, CartaPort, Collection};
use crate::integrations::{HttpTransport, Transport};
use day2_capabilities::{
    integrations::{CartaEnvironment, LiveConnection},
    resources::{CartaChildren, VersionRef},
};
use std::{
    fmt,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const OPENAI_MODEL: &str = "gpt-6-luna";
pub const MAX_BODY: usize = 4 * 1_048_576;

fn source_bindings() -> serde_json::Value {
    let files: &[(&str, &[u8])] = &[
        (
            "provider_recording.rs",
            include_bytes!("provider_recording.rs"),
        ),
        (
            "provider_recording/redact.rs",
            include_bytes!("provider_recording/redact.rs"),
        ),
        ("carta_live.rs", include_bytes!("carta_live.rs")),
        ("carta_http.rs", include_bytes!("carta_http.rs")),
        (
            "integrations/openai.rs",
            include_bytes!("integrations/openai.rs"),
        ),
        (
            "integrations/transport.rs",
            include_bytes!("integrations/transport.rs"),
        ),
        ("json.rs", include_bytes!("json.rs")),
    ];
    serde_json::json!({"adapter_sources":files.iter().map(|(name,bytes)|(*name,crate::digest(bytes))).collect::<std::collections::BTreeMap<_,_>>(),"recipe_sources":crate::automation::source_digest()})
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Carta,
    OpenAi,
}

impl Provider {
    pub fn parse(value: &str) -> Result<Self, Failure> {
        match value {
            "carta" => Ok(Self::Carta),
            "openai" => Ok(Self::OpenAi),
            _ => Err(Failure::Input),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Carta => "carta",
            Self::OpenAi => "openai",
        }
    }
}

/// Closed diagnostics only: never provider text, parser errors or credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Input,
    Order,
    Expired,
    Transport,
    Status(u16),
    Json,
    Bounds,
    UnsupportedField,
    UnsupportedLiteral,
    SecretInOutput,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Input => "provider_recording_input",
            Self::Order => "provider_recording_order",
            Self::Expired => "provider_recording_expired",
            Self::Transport => "provider_recording_transport",
            Self::Status(_) => "provider_recording_http_status",
            Self::Json => "provider_recording_json",
            Self::Bounds => "provider_recording_bounds",
            Self::UnsupportedField => "provider_recording_unknown_field",
            Self::UnsupportedLiteral => "provider_recording_unknown_protocol_literal",
            Self::SecretInOutput => "provider_recording_output_refused",
        })
    }
}
impl std::error::Error for Failure {}

/// DATA constructed only after fail-closed redaction. No raw reply constructor.
pub struct Recording {
    name: &'static str,
    bytes: Vec<u8>,
    status: u16,
    response_bytes: usize,
}

impl Recording {
    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn status(&self) -> u16 {
        self.status
    }
    pub fn response_bytes(&self) -> usize {
        self.response_bytes
    }
}

/// A complete redacted recording set and manifest, never provider authority.
pub struct Bundle {
    recordings: Vec<Recording>,
    provenance: Vec<u8>,
}

impl Bundle {
    pub fn recordings(&self) -> &[Recording] {
        &self.recordings
    }
    pub fn provenance(&self) -> &[u8] {
        &self.provenance
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Token,
    Stakeholders,
    Grants,
    OpenAi,
    Publish,
    Failed,
}

enum Live {
    Carta {
        port: Box<dyn CartaPort>,
        token: Option<AccessToken>,
    },
    OpenAi {
        project: String,
        transport: Box<dyn Transport>,
    },
}

/// Opaque, one-shot credential owner. No Debug/Clone/Serialize or material getter.
pub struct Session {
    provider: Provider,
    live: Live,
    phase: Phase,
    started: Instant,
    secret: Zeroizing<String>,
    redactor: redact::Redactor,
    recordings: Vec<Recording>,
}

impl Session {
    pub fn carta(client: String, issuer: String, secret: String) -> Result<Self, Failure> {
        let connection = LiveConnection::Carta {
            credential_ref: VersionRef {
                id: "operator-recording".into(),
                revision: 1,
            },
            client_id: client.clone(),
            environment: CartaEnvironment::Playground,
            max_pages_per_collection: 1,
        };
        let plan = CapturePlan::authorize(
            "operator-recording",
            &VersionRef {
                id: "operator-recording".into(),
                revision: 1,
            },
            &connection,
            &issuer,
            CartaChildren::Include,
            false,
        )
        .map_err(|_| Failure::Input)?;
        let native = crate::carta_http::NativeCartaPort::new(
            &plan,
            &client,
            crate::carta_http::CartaClientSecret::new(secret.clone())
                .map_err(|_| Failure::Input)?,
        )
        .map_err(|_| Failure::Transport)?;
        let mut session = Self::with(
            Provider::Carta,
            Live::Carta {
                port: Box::new(native),
                token: None,
            },
            secret,
            Phase::Token,
        );
        session.redactor = redact::Redactor::carta(&issuer);
        Ok(session)
    }

    pub fn openai(project: String, secret: String) -> Result<Self, Failure> {
        crate::integrations::Credentials::validate(&secret).map_err(|_| Failure::Input)?;
        let connection = LiveConnection::OpenAi {
            credential_ref: VersionRef {
                id: "operator-recording".into(),
                revision: 1,
            },
            project_id: project.clone(),
            organization_id: None,
        };
        connection.validate().map_err(|_| Failure::Input)?;
        let transport = HttpTransport::new().map_err(|_| Failure::Transport)?;
        Ok(Self::with(
            Provider::OpenAi,
            Live::OpenAi {
                project,
                transport: Box::new(transport),
            },
            secret,
            Phase::OpenAi,
        ))
    }

    fn with(provider: Provider, live: Live, secret: String, phase: Phase) -> Self {
        Self {
            provider,
            live,
            phase,
            started: Instant::now(),
            secret: Zeroizing::new(secret),
            redactor: redact::Redactor::default(),
            recordings: Vec::new(),
        }
    }

    fn enter(&mut self, expected: Phase) -> Result<(), Failure> {
        let old = self.phase;
        self.phase = Phase::Failed;
        if old != expected {
            return Err(Failure::Order);
        }
        if self.started.elapsed() >= Duration::from_secs(180) {
            return Err(Failure::Expired);
        }
        Ok(())
    }

    fn record(
        &mut self,
        name: &'static str,
        status: u16,
        json: bool,
        body: &[u8],
    ) -> Result<(), Failure> {
        if status != 200 {
            return Err(Failure::Status(status));
        }
        if !json {
            return Err(Failure::Json);
        }
        let bytes = self.redactor.body(self.provider, body)?;
        if bytes
            .windows(self.secret.len())
            .any(|v| v == self.secret.as_bytes())
        {
            return Err(Failure::SecretInOutput);
        }
        if let Live::Carta {
            token: Some(token), ..
        } = &self.live
            && bytes
                .windows(token.bearer().len())
                .any(|v| v == token.bearer().as_bytes())
        {
            return Err(Failure::SecretInOutput);
        }
        self.recordings.push(Recording {
            name,
            bytes,
            status,
            response_bytes: body.len(),
        });
        Ok(())
    }

    pub fn token(&mut self) -> Result<(), Failure> {
        self.enter(Phase::Token)?;
        let Live::Carta { port, .. } = &mut self.live else {
            return Err(Failure::Order);
        };
        let reply = port
            .token(
                &crate::carta_live::token_form(),
                crate::carta_live::MAX_TOKEN_RESPONSE_BYTES,
            )
            .map_err(|_| Failure::Transport)?;
        if reply.status != 200 {
            return Err(Failure::Status(reply.status));
        }
        if !reply.json || reply.body.len() > crate::carta_live::MAX_TOKEN_RESPONSE_BYTES {
            return Err(Failure::Bounds);
        }
        let token = crate::carta_live::parse_token(&reply.body).map_err(|_| Failure::Json)?;
        let Live::Carta { token: held, .. } = &mut self.live else {
            return Err(Failure::Order);
        };
        *held = Some(token);
        self.record(
            "carta.access_token.json",
            reply.status,
            reply.json,
            &reply.body,
        )?;
        self.phase = Phase::Stakeholders;
        Ok(())
    }

    pub fn stakeholders(&mut self) -> Result<(), Failure> {
        self.page(Collection::Stakeholders)
    }
    pub fn grants(&mut self) -> Result<(), Failure> {
        self.page(Collection::OptionGrants)
    }

    fn page(&mut self, collection: Collection) -> Result<(), Failure> {
        let (expected, next, name) = match collection {
            Collection::Stakeholders => (
                Phase::Stakeholders,
                Phase::Grants,
                "carta.stakeholders.json",
            ),
            Collection::OptionGrants => (Phase::Grants, Phase::Publish, "carta.optionGrants.json"),
        };
        self.enter(expected)?;
        let Live::Carta { port, token } = &mut self.live else {
            return Err(Failure::Order);
        };
        let reply = port
            .page(
                collection,
                None,
                token.as_ref().ok_or(Failure::Order)?,
                MAX_BODY,
            )
            .map_err(|_| Failure::Transport)?;
        self.record(name, reply.status, reply.json, &reply.body)?;
        self.phase = next;
        Ok(())
    }

    pub fn openai_response(&mut self) -> Result<(), Failure> {
        self.enter(Phase::OpenAi)?;
        let Live::OpenAi { project, transport } = &self.live else {
            return Err(Failure::Order);
        };
        let reply = crate::integrations::openai_recording_exchange(
            project,
            &self.secret,
            transport.as_ref(),
        )
        .map_err(|_| Failure::Transport)?;
        self.record(
            "openai.responses.json",
            reply.status,
            reply.json_content_type,
            &reply.body,
        )?;
        self.phase = Phase::Publish;
        Ok(())
    }

    pub fn finish(mut self) -> Result<Bundle, Failure> {
        self.enter(Phase::Publish)?;
        self.redactor.validate_identities(self.provider)?;
        use serde_json::json;
        let files:Vec<_>=self.recordings.iter().map(|r|json!({"name":r.name(),"sha256":crate::digest(r.bytes()),"bytes":r.bytes().len(),"http_status":r.status(),"response_bytes":r.response_bytes()})).collect();
        let request = match self.provider {
            Provider::Carta => {
                json!({"environment":"playground","selected_issuer":self.redactor.selected_issuer()?,"calls":3,"pagination_followed":false,"login_origin":"https://login.playground.carta.team","api_origin":"https://api.playground.carta.team","paths":["/o/access_token/","/v1alpha1/issuers/{issuer}/stakeholders","/v1alpha1/issuers/{issuer}/optionGrants"]})
            }
            Provider::OpenAi => {
                crate::integrations::openai_recording_request().map_err(|_| Failure::Input)?
            }
        };
        let provenance = json!({"format":1,"provider":self.provider.name(),"captured_at":crate::oauth::effects::wall_time().map_err(|_|Failure::Expired)?,"provider_qualified":false,"redaction_policy":"closed-schema-values-v1","sources":source_bindings(),"coverage":match self.provider {Provider::Carta=>"playground-first-page-per-collection",Provider::OpenAi=>"one-production-prepared-responses-request"},"request":request,"files":files});
        let bytes = serde_json::to_vec_pretty(&provenance).map_err(|_| Failure::Json)?;
        if bytes
            .windows(self.secret.len())
            .any(|v| v == self.secret.as_bytes())
        {
            return Err(Failure::SecretInOutput);
        }
        Ok(Bundle {
            recordings: std::mem::take(&mut self.recordings),
            provenance: bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carta_live::{Reply, TransportFailure};
    use crate::integrations::{Authorization, TransportError, WireRequest, WireResponse};
    use serde_json::{Value, json};
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    const SECRET: &str = "SYNTHETIC_RECORDING_SECRET_NEVER_EXPORT";
    const TOKEN: &str = "SYNTHETIC_RECORDING_BEARER_NEVER_EXPORT";

    struct CartaFixture {
        replies: VecDeque<Reply>,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl CartaPort for CartaFixture {
        fn token(&mut self, form: &str, max: usize) -> Result<Reply, TransportFailure> {
            assert_eq!(form, crate::carta_live::token_form());
            assert_eq!(max, crate::carta_live::MAX_TOKEN_RESPONSE_BYTES);
            self.calls.lock().unwrap().push("token");
            Ok(self.replies.pop_front().unwrap())
        }
        fn page(
            &mut self,
            collection: Collection,
            query: Option<&str>,
            token: &AccessToken,
            max: usize,
        ) -> Result<Reply, TransportFailure> {
            assert!(query.is_none(), "recording never follows pagination");
            assert_eq!(token.bearer(), TOKEN);
            assert_eq!(max, MAX_BODY);
            self.calls.lock().unwrap().push(collection.segment());
            Ok(self.replies.pop_front().unwrap())
        }
    }

    fn carta() -> (Session, Arc<Mutex<Vec<&'static str>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let replies = [
            json!({"access_token":TOKEN,"token_type":"Bearer","expires_in":3600,"scope":"read_issuer_stakeholders read_issuer_securities"}),
            json!({"stakeholders":[{"id":"private-holder","issuerId":"9999","fullName":"PRIVATE NAME","email":"private@example.com"}],"nextPageToken":"private-continuation"}),
            json!({"optionGrants":[{"id":"private-grant","issuerId":"9999","stakeholderId":"private-holder","quantity":{"value":"987654321"}}],"nextPageToken":null}),
        ].into_iter().map(|v| Reply { status:200, json:true, body:serde_json::to_vec(&v).unwrap(), retry_after_seconds:None }).collect();
        let port = CartaFixture {
            replies,
            calls: calls.clone(),
        };
        let mut session = Session::with(
            Provider::Carta,
            Live::Carta {
                port: Box::new(port),
                token: None,
            },
            SECRET.into(),
            Phase::Token,
        );
        session.redactor = redact::Redactor::carta("9999");
        (session, calls)
    }

    #[test]
    fn carta_records_three_actual_port_replies_with_private_values_removed() {
        let (mut session, calls) = carta();
        session.token().unwrap();
        session.stakeholders().unwrap();
        session.grants().unwrap();
        let bundle = session.finish().unwrap();
        let files = bundle.recordings();
        assert_eq!(
            *calls.lock().unwrap(),
            ["token", "stakeholders", "optionGrants"]
        );
        assert_eq!(files.len(), 3);
        let manifest: Value = serde_json::from_slice(bundle.provenance()).unwrap();
        let people: Value = serde_json::from_slice(files[1].bytes()).unwrap();
        assert_eq!(
            manifest["request"]["selected_issuer"],
            people["stakeholders"][0]["issuerId"]
        );
        for f in files {
            let text = std::str::from_utf8(f.bytes()).unwrap();
            for private in [
                SECRET,
                TOKEN,
                "private-holder",
                "private@example.com",
                "PRIVATE NAME",
                "private-continuation",
                "987654321",
            ] {
                assert!(!text.contains(private));
            }
        }
    }

    #[test]
    fn carta_constructor_binds_the_selected_issuer_without_sending() {
        let session =
            Session::carta("synthetic-client".into(), "987654321".into(), SECRET.into()).unwrap();
        assert_eq!(session.redactor.selected_issuer().unwrap(), "1001");
        assert!(session.finish().is_err());
    }

    #[test]
    fn out_of_order_replay_expiry_and_failure_permanently_close() {
        let (mut session, calls) = carta();
        assert_eq!(session.grants(), Err(Failure::Order));
        assert_eq!(session.token(), Err(Failure::Order));
        assert!(calls.lock().unwrap().is_empty());
        let (mut session, _) = carta();
        session.token().unwrap();
        assert_eq!(session.token(), Err(Failure::Order));
        assert!(session.finish().is_err());
        let (mut session, calls) = carta();
        session.started = Instant::now() - Duration::from_secs(180);
        assert_eq!(session.token(), Err(Failure::Expired));
        assert!(calls.lock().unwrap().is_empty());
    }

    struct OpenAiFixture {
        calls: Arc<Mutex<usize>>,
        status: u16,
    }
    impl Transport for OpenAiFixture {
        fn send(
            &self,
            _request: &WireRequest,
            _: Authorization<'_>,
            max: u64,
        ) -> Result<WireResponse, TransportError> {
            *self.calls.lock().unwrap() += 1;
            assert_eq!(max, MAX_BODY as u64);
            Ok(WireResponse {status:self.status,json_content_type:true,body:serde_json::to_vec(&json!({"id":"resp_private","object":"response","model":OPENAI_MODEL,"store":false,"background":false,"tools":[],"service_tier":"default","status":"completed","output":[{"type":"message","id":"msg_private","role":"assistant","status":"completed","content":[{"type":"output_text","text":SECRET,"annotations":[]}]}],"usage":{"input_tokens":7,"output_tokens":2,"total_tokens":9}})).unwrap(),request_id:Some("private-request-id".into()),metadata:vec![]})
        }
    }

    #[test]
    fn openai_uses_the_production_prepared_request_once_and_preserves_protocol() {
        let calls = Arc::new(Mutex::new(0));
        let mut s = Session::with(
            Provider::OpenAi,
            Live::OpenAi {
                project: "proj_synthetic".into(),
                transport: Box::new(OpenAiFixture {
                    calls: calls.clone(),
                    status: 200,
                }),
            },
            SECRET.into(),
            Phase::OpenAi,
        );
        s.openai_response().unwrap();
        let bundle = s.finish().unwrap();
        let files = bundle.recordings();
        assert_eq!(*calls.lock().unwrap(), 1);
        let v: Value = serde_json::from_slice(files[0].bytes()).unwrap();
        assert_eq!(v["store"], false);
        assert_eq!(v["model"], OPENAI_MODEL);
        assert_eq!(v["usage"]["total_tokens"], 9);
        let text = std::str::from_utf8(files[0].bytes()).unwrap();
        for private in [SECRET, "resp_private", "msg_private", "private-request-id"] {
            assert!(!text.contains(private));
        }
        let manifest: Value = serde_json::from_slice(bundle.provenance()).unwrap();
        assert_eq!(manifest["provider_qualified"], false);
        assert_eq!(
            manifest["files"][0]["sha256"],
            crate::digest(files[0].bytes())
        );
        let text = std::str::from_utf8(bundle.provenance()).unwrap();
        for private in [SECRET, "proj_synthetic", "private-request-id"] {
            assert!(!text.contains(private));
        }
    }

    #[test]
    fn failed_http_is_not_retried_or_publishable() {
        let calls = Arc::new(Mutex::new(0));
        let mut s = Session::with(
            Provider::OpenAi,
            Live::OpenAi {
                project: "proj_synthetic".into(),
                transport: Box::new(OpenAiFixture {
                    calls: calls.clone(),
                    status: 401,
                }),
            },
            SECRET.into(),
            Phase::OpenAi,
        );
        assert_eq!(s.openai_response(), Err(Failure::Status(401)));
        assert_eq!(s.openai_response(), Err(Failure::Order));
        assert!(s.finish().is_err());
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[test]
    fn a_synthetic_identifier_collision_never_produces_a_bundle() {
        let (mut session, _) = carta();
        session.redactor = redact::Redactor::carta("1001");
        session.token().unwrap();
        session.stakeholders().unwrap();
        session.grants().unwrap();
        assert!(matches!(session.finish(), Err(Failure::SecretInOutput)));
    }

    #[test]
    fn an_actual_token_matching_a_protocol_literal_is_still_refused() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let reply = Reply {
            status: 200,
            json: true,
            body: serde_json::to_vec(
                &json!({"access_token":"Bearer","token_type":"Bearer","expires_in":3600}),
            )
            .unwrap(),
            retry_after_seconds: None,
        };
        let port = CartaFixture {
            replies: VecDeque::from([reply]),
            calls: calls.clone(),
        };
        let mut session = Session::with(
            Provider::Carta,
            Live::Carta {
                port: Box::new(port),
                token: None,
            },
            SECRET.into(),
            Phase::Token,
        );
        assert_eq!(session.token(), Err(Failure::SecretInOutput));
        assert_eq!(session.token(), Err(Failure::Order));
        assert!(session.finish().is_err());
        assert_eq!(*calls.lock().unwrap(), ["token"]);
    }
}
