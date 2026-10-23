//! Trusted credential mounts and transport selection. Credential bytes are read
//! only at dispatch and never copied into instance files, app artifacts or audit.
use crate::integrations::{
    self, AdapterError, CredentialResolver, Credentials, HttpTransport, Transport,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{integrations::LiveConnection, resources::VersionRef};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

pub(crate) struct Host {
    resolver: Arc<dyn CredentialResolver>,
    transport: Arc<dyn Transport>,
    /// Whether provider capabilities use committed worlds rather than native
    /// provider adapters. Independent from app-call composition: hybrid
    /// qualification may use native app calls while provider effects stay offline.
    simulated_providers: bool,
    /// Existing delegation semantics: whether calls remain within this process.
    simulated: bool,
}

impl Host {
    pub(crate) fn local(instance: &Path) -> Result<Self> {
        Ok(Self {
            resolver: Arc::new(MountedCredentials {
                database: database(instance)?,
            }),
            transport: Arc::new(LazyTransport(OnceLock::new())),
            simulated_providers: false,
            simulated: false,
        })
    }

    /// Offline mode. Every live adapter is served from its committed simulated
    /// world instead of the network: no credential mount is consulted and no
    /// socket is opened, so a deterministic campaign or a local development
    /// instance runs with no provider secrets present at all. `database` is the
    /// app database; the worlds sit beside it, as the synthetic People stores do.
    ///
    /// This is the whole point of the mandate being enforceable. Before the
    /// simulations existed, a campaign that reached Slack, Snowflake or OpenAI
    /// had no offline path and simply failed at the socket.
    pub(crate) fn simulated(database: &Path, scope: &str) -> Self {
        Self {
            resolver: Arc::new(integrations::simulated::SimulatedCredentials::new(true)),
            transport: Arc::new(integrations::simulated::SimulatedTransport::new(
                database, scope,
            )),
            simulated_providers: true,
            simulated: true,
        }
    }

    pub(crate) fn is_simulated(&self) -> bool {
        self.simulated
    }

    pub(crate) fn uses_simulated_providers(&self) -> bool {
        self.simulated_providers
    }

    /// Hybrid host qualification: provider sockets remain offline, while the
    /// explicitly installed app-call port exercises independent native hosts.
    pub(crate) fn simulated_providers_with_app_calls(database: &Path, scope: &str) -> Self {
        Self {
            simulated: false,
            simulated_providers: true,
            ..Self::simulated(database, scope)
        }
    }

    pub(crate) fn execute(
        &self,
        call: &integrations::PreparedCall,
        attempt: &str,
    ) -> integrations::AdapterOutcome {
        integrations::execute(
            call,
            self.resolver.as_ref(),
            self.transport.as_ref(),
            attempt,
        )
    }

    pub(crate) fn freetool_credential_request(
        &self,
        connection: &LiveConnection,
        action: integrations::FreetoolCredentialAction,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        ensure!(
            !self.simulated_providers,
            "freetool_credential_custody_offline"
        );
        let LiveConnection::FreetoolExecutor { endpoint, .. } = connection else {
            anyhow::bail!("freetool_executor_connection_mismatch");
        };
        let credential = self
            .resolver
            .resolve(connection)
            .map_err(|_| anyhow::anyhow!("freetool_service_key_unavailable"))?;
        integrations::freetool_credential_request(endpoint, &credential, action, body).map_err(
            |error| {
                use crate::error::Failure;
                anyhow::anyhow!(match crate::error::classify(&error) {
                    Failure::InvalidForm => Failure::InvalidForm,
                    Failure::ResourceForbidden => Failure::ResourceForbidden,
                    Failure::VersionConflict => Failure::VersionConflict,
                    _ => Failure::CredentialUnavailable,
                })
            },
        )
    }

    pub(crate) fn freetool_request(
        &self,
        database: &Path,
        connection_id: &VersionRef,
        connection: &LiveConnection,
        request: crate::freetool_executor::ServiceRequest,
        max_response_bytes: u64,
    ) -> integrations::FreetoolExecutorExchange {
        let LiveConnection::FreetoolExecutor { endpoint, .. } = connection else {
            return integrations::FreetoolExecutorExchange::not_dispatched(anyhow::anyhow!(
                "freetool_executor_connection_mismatch"
            ));
        };
        let body = match serde_json::to_vec(&request) {
            Ok(body) => body,
            Err(error) => {
                return integrations::FreetoolExecutorExchange::not_dispatched(error.into());
            }
        };
        if body.len() as u64 > integrations::MAX_FREETOOL_EXECUTOR_WIRE_BYTES {
            return integrations::FreetoolExecutorExchange::not_dispatched(anyhow::anyhow!(
                "freetool_service_request_budget"
            ));
        }
        let max_response_bytes =
            max_response_bytes.min(integrations::MAX_FREETOOL_EXECUTOR_WIRE_BYTES);
        if max_response_bytes == 0 {
            return integrations::FreetoolExecutorExchange::not_dispatched(anyhow::anyhow!(
                "freetool_service_response_budget"
            ));
        }
        if self.simulated_providers {
            let response = database
                .parent()
                .context("application_database_parent_missing")
                .and_then(|parent| {
                    let world = parent.join("freetool_executor.simulated.sqlite");
                    crate::freetool_executor::simulated_call(
                        &world,
                        connection_id,
                        connection,
                        request,
                    )
                })
                .and_then(|response| serde_json::to_vec(&response).map_err(Into::into));
            let response_bytes = response.as_ref().map_or(0, |bytes| bytes.len() as u64);
            let known = response.is_ok();
            let response = response.and_then(|bytes| {
                ensure!(
                    bytes.len() as u64 <= max_response_bytes,
                    "freetool_service_response_budget"
                );
                Ok(bytes)
            });
            return integrations::FreetoolExecutorExchange {
                response,
                request_bytes: body.len() as u64,
                response_bytes,
                known,
                dispatched: true,
            };
        }
        let credential = match self.resolver.resolve(connection) {
            Ok(credential) => credential,
            Err(_) => {
                return integrations::FreetoolExecutorExchange::not_dispatched(anyhow::anyhow!(
                    "freetool_service_key_unavailable"
                ));
            }
        };
        integrations::freetool_executor_request(endpoint, &credential, &body, max_response_bytes)
    }

    #[cfg(test)]
    pub(crate) fn injected(
        resolver: Arc<dyn CredentialResolver>,
        transport: Arc<dyn Transport>,
    ) -> Self {
        Self {
            resolver,
            transport,
            simulated_providers: false,
            simulated: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_transport(
        instance: &Path,
        transport: Arc<dyn Transport>,
    ) -> Result<Self> {
        Ok(Self {
            resolver: Arc::new(MountedCredentials {
                database: database(instance)?,
            }),
            transport,
            simulated_providers: false,
            simulated: false,
        })
    }
}

struct LazyTransport(OnceLock<std::result::Result<HttpTransport, AdapterError>>);

impl Transport for LazyTransport {
    fn send(
        &self,
        request: &integrations::WireRequest,
        authorization: integrations::Authorization<'_>,
        max_response_bytes: u64,
    ) -> std::result::Result<integrations::WireResponse, integrations::TransportError> {
        // Construct the blocking client only in the blocking provider-dispatch
        // path. Loading an ordinary local app never starts an HTTP runtime.
        self.0
            .get_or_init(HttpTransport::new)
            .as_ref()
            .map_err(|error| integrations::TransportError {
                kind: *error,
                response_bytes: 0,
                http_status: None,
                request_id: None,
            })?
            .send(request, authorization, max_response_bytes)
    }
}

pub(crate) struct MountedCredentials {
    database: PathBuf,
}

impl MountedCredentials {
    // REMOVE WITH THE INGRESS ROUTE: the host route resolves a verification key
    // through this. Until it exists, only tests construct one, so the library
    // build sees it as unreachable. Narrow rather than module-wide so that new
    // dead code here is still reported.
    #[allow(dead_code)]
    pub(crate) fn new(instance: &Path) -> Result<Self> {
        Ok(Self {
            database: database(instance)?,
        })
    }
}

fn database(instance: &Path) -> Result<PathBuf> {
    Ok(instance
        .parent()
        .context("instance_directory_missing")?
        .join(".state/provider-credentials.sqlite"))
}

fn read_secret(path: &Path) -> Result<String> {
    // O_NOFOLLOW and fstat check the opened object rather than a raced pathname.
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .context("credential_mount_unavailable")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.len() <= 16_384
            && metadata.permissions().mode() & 0o077 == 0,
        "credential_mount_requires_private_regular_file"
    );
    let mut bytes = Vec::new();
    file.take(16_385).read_to_end(&mut bytes)?;
    Ok(credential_value(&bytes)?.to_owned())
}

/// A mounted credential's value: UTF-8 without trailing newlines, within the
/// bearer token rules. Validation never includes the value in an error.
fn credential_value(bytes: &[u8]) -> Result<&str> {
    ensure!(bytes.len() <= 16_384, "credential_mount_budget");
    let token = std::str::from_utf8(bytes)
        .context("credential_mount_encoding")?
        .trim_end_matches(['\r', '\n']);
    Credentials::validate(token)?;
    Ok(token)
}

/// The reviewed fingerprint registration records for a credential's bytes:
/// `sha256:` of the value without trailing newlines.
pub fn credential_fingerprint(bytes: &[u8]) -> Result<String> {
    Ok(crate::digest(credential_value(bytes)?.as_bytes()))
}

impl CredentialResolver for MountedCredentials {
    fn resolve(&self, live: &LiveConnection) -> std::result::Result<Credentials, AdapterError> {
        let result = (|| -> Result<Credentials> {
            live.validate()?;
            let metadata = fs::symlink_metadata(&self.database)?;
            ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.permissions().mode() & 0o077 == 0,
                "credential_registry_permissions"
            );
            let connection =
                Connection::open_with_flags(&self.database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let reference = live
                .credential_ref()
                .ok_or(AdapterError::CredentialUnavailable)?;
            let (profile, path, fingerprint): (String, String, String) = connection.query_row(
                "SELECT profile,path,fingerprint FROM mounts WHERE id=?1 AND revision=?2",
                params![reference.id, i64::try_from(reference.revision)?],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            ensure!(
                crate::json::decode::<LiveConnection>(profile.as_bytes())? == *live,
                "credential_connection_changed"
            );
            let token = read_secret(Path::new(&path))?;
            ensure!(
                crate::digest(token.as_bytes()) == fingerprint,
                "credential_version_changed"
            );
            Ok(Credentials::bearer(token)?)
        })();
        result.map_err(|_| AdapterError::CredentialUnavailable)
    }
}

impl MountedCredentials {
    /// Resolve the secret that verifies inbound deliveries for this connection.
    ///
    /// Separate from `resolve` rather than a mode of it: the two return different
    /// types precisely so that neither secret can be used as the other. A provider
    /// that accepts no deliveries has no such secret and says so.
    /// The connection's own credential, as local material rather than a bearer
    /// token. Which of the two a credential is depends on how its provider uses
    /// it: Slack transmits its bot token, an object store never transmits its
    /// secret access key but derives signatures from it.
    pub(crate) fn signing_secret(
        &self,
        live: &LiveConnection,
    ) -> Result<crate::integrations::LocalSecret, AdapterError> {
        self.local_secret(
            live,
            live.credential_ref()
                .ok_or(AdapterError::CredentialUnavailable)?,
        )
    }

    /// Resolve the secret that verifies inbound deliveries for this connection.
    ///
    /// Separate from `resolve` rather than a mode of it: the two return different
    /// types precisely so that neither secret can be used as the other. A provider
    /// that accepts no deliveries has no such secret and says so.
    #[allow(dead_code)] // REMOVE WITH THE INGRESS ROUTE.
    pub(crate) fn verification_key(
        &self,
        live: &LiveConnection,
    ) -> Result<crate::integrations::LocalSecret, AdapterError> {
        let reference = live
            .verification_ref()
            .ok_or(AdapterError::CredentialUnavailable)?;
        self.local_secret(live, reference)
    }

    /// One mounted secret, read as local material. The mount is re-checked against
    /// the connection and the recorded fingerprint, exactly as bearer resolution
    /// does, so a rotated or retargeted secret fails rather than being used.
    fn local_secret(
        &self,
        live: &LiveConnection,
        reference: &day2_capabilities::resources::VersionRef,
    ) -> Result<crate::integrations::LocalSecret, AdapterError> {
        let result = (|| -> Result<crate::integrations::LocalSecret> {
            live.validate()?;
            let connection =
                Connection::open_with_flags(&self.database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let (profile, path, fingerprint): (String, String, String) = connection.query_row(
                "SELECT profile,path,fingerprint FROM mounts WHERE id=?1 AND revision=?2",
                params![reference.id, i64::try_from(reference.revision)?],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            ensure!(
                crate::json::decode::<LiveConnection>(profile.as_bytes())? == *live,
                "credential_connection_changed"
            );
            let secret = read_secret(Path::new(&path))?;
            ensure!(
                crate::digest(secret.as_bytes()) == fingerprint,
                "credential_version_changed"
            );
            Ok(crate::integrations::LocalSecret::new(secret)?)
        })();
        result.map_err(|_| AdapterError::CredentialUnavailable)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub connection: LiveConnection,
    /// Which of the connection's declared secrets this mounts. Absent means the
    /// outbound credential, so existing operator requests keep working; a
    /// connection declaring more than one must say which, because a mount that
    /// guessed would silently install a signing secret as a bearer token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<day2_capabilities::resources::VersionRef>,
    pub credential_file: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_fingerprint: Option<String>,
}

/// Register an existing owner-private secret mount. This authorizes credential
/// selection, not provider use: the app still needs an activated resource grant.
/// Rotation needs a new reference revision; existing versions are immutable.
pub fn mount(instance: &Path, operator: &str, request: &Mount) -> Result<serde_json::Value> {
    ensure!(
        crate::resource_admin::is_administrator(instance, operator)?,
        "installation_admin_required"
    );
    request.connection.validate()?;
    ensure!(
        request.credential_file.is_absolute(),
        "credential_mount_requires_absolute_path"
    );
    let token = read_secret(&request.credential_file)?;
    let fingerprint = crate::digest(token.as_bytes());
    ensure!(
        request
            .expected_fingerprint
            .as_ref()
            .is_none_or(|expected| expected == &fingerprint),
        "reviewed_credential_changed"
    );
    let path = database(instance)?;
    let parent = path.parent().context("credential_registry_directory")?;
    fs::create_dir_all(parent)?;
    ensure!(
        !fs::symlink_metadata(parent)?.file_type().is_symlink(),
        "credential_registry_symlink"
    );
    if path.exists() {
        ensure!(
            !fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "credential_registry_symlink"
        );
    }
    let mut connection = crate::store::open(&path)?;
    let tx = crate::write_queue::immediate(&mut connection)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS mounts(id TEXT NOT NULL,revision INTEGER NOT NULL,profile TEXT NOT NULL,path TEXT NOT NULL,fingerprint TEXT NOT NULL,operator TEXT NOT NULL,PRIMARY KEY(id,revision)) STRICT;
        CREATE TRIGGER IF NOT EXISTS mounts_no_update BEFORE UPDATE ON mounts BEGIN SELECT RAISE(ABORT,'immutable_credential_version'); END;
        CREATE TRIGGER IF NOT EXISTS mounts_no_delete BEFORE DELETE ON mounts BEGIN SELECT RAISE(ABORT,'immutable_credential_version'); END;")?;
    // A mount may name any secret the connection declares, and only those: an
    // operator cannot mount a reference this connection never mentions.
    let reference = match &request.reference {
        Some(named) => {
            ensure!(
                request
                    .connection
                    .credential_refs()
                    .into_iter()
                    .any(|declared| declared == named),
                "credential_reference_not_declared_by_connection"
            );
            named
        }
        None => request
            .connection
            .credential_ref()
            .ok_or_else(|| anyhow::anyhow!("workload_identity_has_no_mounted_credential"))?,
    };
    let revision = i64::try_from(reference.revision)?;
    let profile = serde_json::to_string(&request.connection)?;
    let credential_path = request
        .credential_file
        .to_str()
        .context("credential_mount_path_encoding")?;
    let prior: Option<(String, String, String)> = tx
        .query_row(
            "SELECT profile,path,fingerprint FROM mounts WHERE id=?1 AND revision=?2",
            params![reference.id, revision],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some(prior) = prior {
        ensure!(
            prior == (profile.clone(), credential_path.into(), fingerprint.clone()),
            "immutable_credential_version"
        );
    } else {
        let latest: i64 = tx.query_row(
            "SELECT coalesce(max(revision),0) FROM mounts WHERE id=?1",
            [&reference.id],
            |row| row.get(0),
        )?;
        ensure!(revision > latest, "credential_revision_must_advance");
        tx.execute(
            "INSERT INTO mounts VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                reference.id,
                revision,
                profile,
                credential_path,
                fingerprint,
                operator
            ],
        )?;
    }
    tx.commit()?;
    Ok(
        serde_json::json!({"credential":reference,"registered":true,"mode":"local_private_mount","provider_qualified":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::freetool_executor::{
        ExecutionIdentity, ExecutionPlan, ServiceRequest, ServiceResponse,
    };
    use day2_capabilities::resources::VersionRef;
    use std::{
        io::Write,
        net::{TcpListener, TcpStream},
        thread,
    };

    struct FreetoolResolver;

    impl CredentialResolver for FreetoolResolver {
        fn resolve(&self, _: &LiveConnection) -> std::result::Result<Credentials, AdapterError> {
            Credentials::bearer(crate::hex(&[0x31; 32]))
                .map_err(|_| AdapterError::CredentialUnavailable)
        }
    }

    struct UnusedTransport;

    impl Transport for UnusedTransport {
        fn send(
            &self,
            _: &integrations::WireRequest,
            _: integrations::Authorization<'_>,
            _: u64,
        ) -> std::result::Result<integrations::WireResponse, integrations::TransportError> {
            unreachable!("Freetool executor transport has its own adapter")
        }
    }

    fn read_loopback_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        let mut received = Vec::new();
        let mut chunk = [0_u8; 4096];
        let (header_end, content_length) = loop {
            let count = stream.read(&mut chunk)?;
            ensure!(count > 0, "loopback request ended before headers");
            received.extend_from_slice(&chunk[..count]);
            if let Some(index) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                let header_end = index + 4;
                let headers = String::from_utf8(received[..header_end].to_vec())?;
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .context("missing content length")?;
                break (header_end, length);
            }
        };
        while received.len() - header_end < content_length {
            let count = stream.read(&mut chunk)?;
            ensure!(count > 0, "loopback request body truncated");
            received.extend_from_slice(&chunk[..count]);
        }
        Ok(received[header_end..header_end + content_length].to_vec())
    }

    #[test]
    fn freetool_host_threads_grant_response_limit_and_meters_wire_request() -> Result<()> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let server_body = vec![b'x'; 1024];
        let server = thread::spawn(move || -> Result<Vec<u8>> {
            let (mut stream, _) = listener.accept()?;
            let body = read_loopback_request(&mut stream)?;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                server_body.len()
            )?;
            stream.write_all(&server_body)?;
            Ok(body)
        });
        let database_dir = tempfile::tempdir()?;
        let database = database_dir.path().join("app.sqlite");
        let host = Host::injected(Arc::new(FreetoolResolver), Arc::new(UnusedTransport));
        let connection_id = VersionRef {
            id: "executor_wire_test".into(),
            revision: 1,
        };
        let connection = LiveConnection::FreetoolExecutor {
            credential_ref: VersionRef {
                id: "executor_wire_key".into(),
                revision: 1,
            },
            endpoint,
        };
        let request = ServiceRequest::Status {
            identity: ExecutionIdentity {
                installation: "company/staging".into(),
                application: "freetool".into(),
                actor: "alice".into(),
                artifact: "artifact-1".into(),
                operation: "freetool.run".into(),
                resource_id: "resource-1".into(),
                configuration_id: "config-1".into(),
                immutable_version: 1,
                configuration_digest: "a".repeat(64),
                run_id: "run-1".into(),
                arguments_digest: "b".repeat(64),
            },
        };
        let expected_request = serde_json::to_vec(&request)?;
        let response_limit = 128;
        let exchange = host.freetool_request(
            &database,
            &connection_id,
            &connection,
            request,
            response_limit,
        );
        assert!(exchange.response.is_err());
        assert_eq!(exchange.request_bytes, expected_request.len() as u64);
        assert_eq!(exchange.response_bytes, response_limit + 1);
        assert!(exchange.known && exchange.dispatched);
        assert_eq!(
            server
                .join()
                .map_err(|_| anyhow::anyhow!("loopback server panicked"))??,
            expected_request
        );
        Ok(())
    }

    #[test]
    fn simulated_executor_records_are_connection_bound() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("app.sqlite");
        let host = Host::simulated(&database, "test");
        let connection_id_a = VersionRef {
            id: "executor_a".into(),
            revision: 3,
        };
        let connection_a = LiveConnection::FreetoolExecutor {
            credential_ref: VersionRef {
                id: "executor_key_a".into(),
                revision: 1,
            },
            endpoint: "http://127.0.0.1:43210".into(),
        };
        let connection_id_b = VersionRef {
            id: "executor_b".into(),
            revision: 7,
        };
        let connection_b = LiveConnection::FreetoolExecutor {
            credential_ref: VersionRef {
                id: "executor_key_b".into(),
                revision: 2,
            },
            endpoint: "http://127.0.0.1:43211".into(),
        };
        let identity = ExecutionIdentity {
            installation: "company/staging".into(),
            application: "freetool".into(),
            actor: "alice".into(),
            artifact: "artifact-1".into(),
            operation: "freetool.run".into(),
            resource_id: "resource-1".into(),
            configuration_id: "config-1".into(),
            immutable_version: 1,
            configuration_digest: "a".repeat(64),
            run_id: "run-1".into(),
            arguments_digest: "b".repeat(64),
        };
        let plan = ExecutionPlan::Http {
            method: "GET".into(),
            url: "https://api.example.test/items".into(),
            headers: vec![],
            body: vec![],
        };

        host.freetool_request(
            &database,
            &connection_id_a,
            &connection_a,
            ServiceRequest::Register {
                identity: identity.clone(),
                plan,
            },
            integrations::MAX_FREETOOL_EXECUTOR_WIRE_BYTES,
        )
        .response?;
        host.freetool_request(
            &database,
            &connection_id_a,
            &connection_a,
            ServiceRequest::Execute {
                identity: identity.clone(),
            },
            integrations::MAX_FREETOOL_EXECUTOR_WIRE_BYTES,
        )
        .response?;
        let status = host.freetool_request(
            &database,
            &connection_id_b,
            &connection_b,
            ServiceRequest::Status {
                identity: identity.clone(),
            },
            integrations::MAX_FREETOOL_EXECUTOR_WIRE_BYTES,
        );
        let status: ServiceResponse = serde_json::from_slice(&status.response?)?;
        assert!(matches!(status, ServiceResponse::Status { receipt: None }));

        let result = host.freetool_request(
            &database,
            &connection_id_b,
            &connection_b,
            ServiceRequest::ResultPage {
                identity,
                offset: 0,
                limit: 100,
            },
            integrations::MAX_FREETOOL_EXECUTOR_WIRE_BYTES,
        );
        let result: ServiceResponse = serde_json::from_slice(&result.response?)?;
        assert!(matches!(result, ServiceResponse::Error { code } if code == "result_unavailable"));
        Ok(())
    }
}
