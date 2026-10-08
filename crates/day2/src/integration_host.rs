//! Trusted credential mounts and transport selection. Credential bytes are read
//! only at dispatch and never copied into instance files, app artifacts or audit.
use crate::integrations::{
    self, AdapterError, CredentialResolver, Credentials, HttpTransport, Transport,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::integrations::LiveConnection;
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
    /// Whether providers are served from their committed worlds rather than the
    /// network. Capabilities with no transport of their own — a delegated read
    /// reaches another application, not a socket — have no other way to tell.
    simulated: bool,
}

impl Host {
    pub(crate) fn local(instance: &Path) -> Result<Self> {
        Ok(Self {
            resolver: Arc::new(MountedCredentials {
                database: database(instance)?,
            }),
            transport: Arc::new(LazyTransport(OnceLock::new())),
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
            simulated: true,
        }
    }

    pub(crate) fn is_simulated(&self) -> bool {
        self.simulated
    }

    /// Hybrid host qualification: provider sockets remain offline, while the
    /// explicitly installed app-call port exercises independent native hosts.
    pub(crate) fn simulated_providers_with_app_calls(database: &Path, scope: &str) -> Self {
        Self {
            simulated: false,
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

    #[cfg(test)]
    pub(crate) fn injected(
        resolver: Arc<dyn CredentialResolver>,
        transport: Arc<dyn Transport>,
    ) -> Self {
        Self {
            resolver,
            transport,
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
            let reference = live.credential_ref();
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
        self.local_secret(live, live.credential_ref())
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
        None => request.connection.credential_ref(),
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
