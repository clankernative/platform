//! Installation-scoped control API. App names become authority handles only after operator authorization.
use crate::{
    BuildPlan, Digest, GitOid, Name,
    engine::ExecutionHost,
    journal::Journal,
    local_source::{LocalGit, SourceChange, SourceControl, SourceReceipt, private_directory},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    BindingRef, ControlScope, InstallationControl, SecretProvider, SourceProvider,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub use crate::local_source::SourceBundle;

#[derive(Clone, Debug)]
pub struct AppHandle {
    scope: Digest,
    app: Name,
    actor: String,
}
impl AppHandle {
    pub fn name(&self) -> &Name {
        &self.app
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceState {
    Pending,
    Completed { receipt: SourceReceipt },
    Rejected { code: SourceRejection },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRejection {
    RevisionConflict,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStatus {
    pub id: Digest,
    pub app: Name,
    pub request: Name,
    pub attempts: u64,
    pub state: SourceState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    scope: ControlScope,
    app: Name,
    request: Name,
    binding: BindingRef,
    actor: String,
    change: SourceChange,
}
impl Intent {
    fn id(&self) -> Result<Digest> {
        Digest::of(&(
            "day2-source-intent-v1",
            &self.scope,
            &self.app,
            &self.request,
        ))
    }
}

pub struct Service {
    scope: ControlScope,
    configuration: InstallationControl,
    journal: PathBuf,
}
impl Service {
    pub fn secret_resolver(
        &self,
        app: &AppHandle,
        tokens: std::sync::Arc<dyn crate::secrets::AccessTokenProvider>,
    ) -> Result<ScopedSecrets> {
        self.secret_resolver_with_endpoint(app, tokens, "https://secretmanager.googleapis.com/")
    }
    /// Trusted-host test hook; endpoints remain restricted by the GCP adapter to production or loopback.
    pub fn secret_resolver_with_endpoint(
        &self,
        app: &AppHandle,
        tokens: std::sync::Arc<dyn crate::secrets::AccessTokenProvider>,
        endpoint: &str,
    ) -> Result<ScopedSecrets> {
        self.check(app)?;
        let app = self
            .configuration
            .apps
            .get(&app.app)
            .context("unknown control app")?;
        let mut bindings = std::collections::BTreeMap::new();
        for (logical, binding) in &app.provider_secrets {
            let SecretProvider::GcpVersion {
                project_number,
                secret,
                version,
            } = self
                .configuration
                .secrets
                .get(binding)
                .context("unknown secret binding")?;
            bindings.insert(
                crate::source::SecretRef::try_from(logical.as_str().to_owned())?,
                crate::secrets::SecretVersion {
                    project_number: project_number.get(),
                    secret: secret.as_str().to_owned(),
                    version: version.get(),
                },
            );
        }
        let resolver = crate::secrets::GcpSecretManager::with_endpoint(
            endpoint,
            bindings.clone(),
            tokens.as_ref(),
        )?;
        let revision = crate::source::SecretResolver::binding_revision(&resolver);
        Ok(ScopedSecrets {
            endpoint: endpoint.to_owned(),
            bindings,
            tokens,
            revision,
        })
    }
    pub fn open<'a>(
        scope: ControlScope,
        configuration: InstallationControl,
        installed_apps: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self> {
        configuration.validate(installed_apps)?;
        let root = PathBuf::from(&configuration.state_directory);
        private_directory(&root)?;
        let result = Self {
            scope,
            configuration,
            journal: root.join("source-journal.sqlite"),
        };
        let mut connection = result.connection()?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS installation (singleton INTEGER PRIMARY KEY CHECK(singleton=1), scope TEXT NOT NULL); CREATE TABLE IF NOT EXISTS source_intents (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, intent TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, lease_until INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS source_events (seq INTEGER PRIMARY KEY, execution TEXT NOT NULL, kind TEXT NOT NULL, actor TEXT NOT NULL);")?;
        let transaction = day2::write_queue::immediate(&mut connection)?;
        let scope = Digest::of(&result.scope)?;
        transaction.execute(
            "INSERT OR IGNORE INTO installation(singleton,scope) VALUES(1,?1)",
            [scope.as_str()],
        )?;
        let existing: String = transaction.query_row(
            "SELECT scope FROM installation WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        ensure!(
            existing == scope.as_str(),
            "control journal belongs to another installation or environment"
        );
        transaction.commit()?;
        Ok(result)
    }
    pub fn configuration(&self) -> &InstallationControl {
        &self.configuration
    }
    pub fn scope(&self) -> &ControlScope {
        &self.scope
    }
    pub fn build_journal(&self) -> PathBuf {
        PathBuf::from(&self.configuration.state_directory).join("build-journal.sqlite")
    }
    pub fn authorize(&self, actor: &str, app: &Name) -> Result<AppHandle> {
        ensure!(
            self.configuration.operators.contains(actor),
            "control_forbidden"
        );
        ensure!(
            self.configuration.apps.contains_key(app),
            "app_has_no_control_authority"
        );
        Ok(AppHandle {
            scope: Digest::of(&self.scope)?,
            app: app.clone(),
            actor: actor.to_owned(),
        })
    }
    pub(crate) fn check(&self, app: &AppHandle) -> Result<()> {
        ensure!(
            app.scope == Digest::of(&self.scope)?,
            "control_scope_mismatch"
        );
        self.authorize(&app.actor, &app.app)?;
        Ok(())
    }
    fn binding(&self, app: &Name) -> Result<BindingRef> {
        let binding = &self
            .configuration
            .apps
            .get(app)
            .context("unknown control app")?
            .source;
        BindingRef::pin(
            binding.clone(),
            self.configuration
                .sources
                .get(binding)
                .context("unknown source provider")?,
        )
    }
    pub fn source(&self, app: &AppHandle) -> Result<Box<dyn SourceControl>> {
        self.check(app)?;
        self.source_for(&app.app)
    }
    fn source_for(&self, app: &Name) -> Result<Box<dyn SourceControl>> {
        let binding = self.binding(app)?;
        let owner = Digest::of(&("day2-managed-source-v1", &self.scope, app, &binding))?;
        match self
            .configuration
            .sources
            .get(&binding.id)
            .context("unknown source provider")?
        {
            SourceProvider::LocalGit { repository } => Ok(Box::new(LocalGit::open(
                std::path::Path::new(repository),
                &owner,
            )?)),
        }
    }
    pub fn submit(
        &self,
        app: &AppHandle,
        request: Name,
        change: SourceChange,
    ) -> Result<SourceStatus> {
        self.check(app)?;
        let intent = Intent {
            scope: self.scope.clone(),
            app: app.app.clone(),
            request,
            binding: self.binding(&app.app)?,
            actor: app.actor.clone(),
            change,
        };
        let id = intent.id()?;
        let fingerprint = Digest::of(&intent)?;
        let mut connection = self.connection()?;
        let transaction = day2::write_queue::immediate(&mut connection)?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT fingerprint FROM source_intents WHERE id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            ensure!(existing == fingerprint.as_str(), "source_request_conflict");
        } else {
            transaction.execute(
                "INSERT INTO source_intents(id,fingerprint,intent,state) VALUES(?1,?2,?3,?4)",
                params![
                    id.as_str(),
                    fingerprint.as_str(),
                    serde_json::to_string(&intent)?,
                    serde_json::to_string(&SourceState::Pending)?
                ],
            )?;
            transaction.execute(
                "INSERT INTO source_events(execution,kind,actor) VALUES(?1,'accepted',?2)",
                params![id.as_str(), app.actor],
            )?;
        }
        transaction.commit()?;
        self.status(app, &id)
    }
    pub fn status(&self, app: &AppHandle, id: &Digest) -> Result<SourceStatus> {
        self.check(app)?;
        let (intent, state, attempts, _) = read_intent(&self.connection()?, id)?;
        ensure!(
            intent.scope == self.scope && intent.app == app.app,
            "control_execution_scope_mismatch"
        );
        Ok(SourceStatus {
            id: id.clone(),
            app: intent.app,
            request: intent.request,
            attempts,
            state,
        })
    }
    pub fn pending(&self, app: &AppHandle) -> Result<Vec<Digest>> {
        self.check(app)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT id FROM source_intents WHERE json_extract(state,'$.state')='pending' AND json_extract(intent,'$.app')=?1 ORDER BY rowid LIMIT 4096")?;
        let ids = statement
            .query_map([app.app.as_str()], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut result = Vec::new();
        for raw in ids {
            let id = Digest::try_from(raw)?;
            let (intent, state, _, _) = read_intent(&connection, &id)?;
            if intent.scope == self.scope
                && intent.app == app.app
                && matches!(state, SourceState::Pending)
            {
                result.push(id);
            }
        }
        Ok(result)
    }
    pub fn advance(&self, app: &AppHandle, id: &Digest) -> Result<SourceStatus> {
        self.advance_at(app, id, now()?)
    }
    pub fn advance_at(&self, app: &AppHandle, id: &Digest, now: u64) -> Result<SourceStatus> {
        self.check(app)?;
        let mut connection = self.connection()?;
        let transaction = day2::write_queue::immediate(&mut connection)?;
        let (intent, state, attempts, lease_until) = read_intent(&transaction, id)?;
        ensure!(
            intent.scope == self.scope && intent.app == app.app,
            "control_execution_scope_mismatch"
        );
        ensure!(
            intent.binding == self.binding(&intent.app)?,
            "source binding changed since acceptance"
        );
        if !matches!(state, SourceState::Pending) || lease_until > now {
            transaction.commit()?;
            return self.status(app, id);
        }
        let attempt = i64::try_from(attempts.checked_add(1).context("source attempt overflow")?)?;
        let expires = i64::try_from(now.checked_add(120_000).context("source lease overflow")?)?;
        transaction.execute(
            "UPDATE source_intents SET attempts=?1,lease_until=?2 WHERE id=?3",
            params![attempt, expires, id.as_str()],
        )?;
        transaction.commit()?;
        let outcome = self.source_for(&intent.app)?.apply(id, &intent.change);
        let (state, kind) = match outcome {
            Ok(receipt) => (SourceState::Completed { receipt }, "completed"),
            Err(error)
                if ["source_revision_conflict", "source_base_revision_conflict"]
                    .contains(&error.to_string().as_str()) =>
            {
                (
                    SourceState::Rejected {
                        code: SourceRejection::RevisionConflict,
                    },
                    "rejected",
                )
            }
            Err(_) => {
                connection.execute(
                    "UPDATE source_intents SET lease_until=0 WHERE id=?1 AND attempts=?2",
                    params![id.as_str(), attempt],
                )?;
                anyhow::bail!("source_provider_unavailable");
            }
        };
        let transaction = day2::write_queue::immediate(&mut connection)?;
        let changed = transaction.execute(
            "UPDATE source_intents SET state=?1,lease_until=0 WHERE id=?2 AND attempts=?3",
            params![serde_json::to_string(&state)?, id.as_str(), attempt],
        )?;
        ensure!(changed == 1, "source_lease_lost");
        transaction.execute(
            "INSERT INTO source_events(execution,kind,actor) VALUES(?1,?2,?3)",
            params![id.as_str(), kind, intent.actor],
        )?;
        transaction.commit()?;
        self.status(app, id)
    }
    pub fn build_plan(&self, app: &AppHandle, request: Name, commit: GitOid) -> Result<BuildPlan> {
        self.check(app)?;
        let profile = self
            .configuration
            .apps
            .get(&app.app)
            .context("unknown control app")?
            .build
            .clone()
            .context("app_has_no_build_capability")?;
        ensure!(
            profile.source == self.binding(&app.app)?,
            "build source authority mismatch"
        );
        let plan = BuildPlan {
            version: 1,
            company: self.scope.company()?,
            app: app.app.clone(),
            request,
            commit,
            profile,
        };
        plan.validate()?;
        Ok(plan)
    }
    pub fn submit_build(
        &self,
        app: &AppHandle,
        host: &ExecutionHost,
        request: Name,
        commit: GitOid,
    ) -> Result<Digest> {
        let plan = self.build_plan(app, request, commit)?;
        // Exact commits must already exist inside this app's admitted source authority.
        // No worker may resolve an app-selected remote URL or mutable branch later.
        let snapshot = self.source(app)?.snapshot(&plan.commit)?;
        SourceBundle::from_files(snapshot.files().clone())?;
        host.accept_as(&plan, &app.actor)
    }
    pub fn build_status(&self, app: &AppHandle, id: &Digest) -> Result<crate::journal::Execution> {
        self.check(app)?;
        let execution = Journal::open(&self.build_journal())?.get(id)?;
        ensure!(
            execution.plan.company == self.scope.company()? && execution.plan.app == app.app,
            "control_execution_scope_mismatch"
        );
        Ok(execution)
    }
    pub fn build_provenance(
        &self,
        app: &AppHandle,
        id: &Digest,
    ) -> Result<crate::journal::AcceptanceProvenance> {
        self.build_status(app, id)?;
        Journal::open(&self.build_journal())?.accepted_by(id)
    }
    fn connection(&self) -> Result<Connection> {
        let connection = Connection::open(&self.journal)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        Ok(connection)
    }
}

/// Only the trusted provider host receives this value. It has no serialization or secret-byte accessor.
pub struct ScopedSecrets {
    endpoint: String,
    bindings: std::collections::BTreeMap<crate::source::SecretRef, crate::secrets::SecretVersion>,
    tokens: std::sync::Arc<dyn crate::secrets::AccessTokenProvider>,
    revision: Digest,
}
impl crate::source::SecretResolver for ScopedSecrets {
    fn binding_revision(&self) -> Digest {
        self.revision.clone()
    }
    fn resolve(
        &self,
        reference: &crate::source::SecretRef,
    ) -> std::result::Result<crate::source::SecretValue, crate::source::SourceError> {
        crate::secrets::GcpSecretManager::with_endpoint(
            &self.endpoint,
            self.bindings.clone(),
            self.tokens.as_ref(),
        )?
        .resolve(reference)
    }
}
fn read_intent(connection: &Connection, id: &Digest) -> Result<(Intent, SourceState, u64, u64)> {
    let (raw, fingerprint, state, attempts, lease): (String, String, String, i64, i64) = connection
        .query_row(
            "SELECT intent,fingerprint,state,attempts,lease_until FROM source_intents WHERE id=?1",
            [id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
    let intent: Intent = serde_json::from_str(&raw)?;
    ensure!(
        intent.id()? == *id && Digest::of(&intent)?.as_str() == fingerprint,
        "source journal integrity mismatch"
    );
    Ok((
        intent,
        serde_json::from_str(&state)?,
        u64::try_from(attempts)?,
        u64::try_from(lease)?,
    ))
}
fn now() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
