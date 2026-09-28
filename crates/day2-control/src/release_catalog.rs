//! Read the operation catalog from release authority's active pointers.
//!
//! No second mutable mapping is published: the release slot chooses an artifact,
//! and immutable artifact bytes supply its exports and embedded caller imports.

use crate::{
    Digest, Name,
    journal::Journal,
    release::{ActivationReceipt, ApprovedRelease, ReleaseApproval, ReleaseTarget},
};
use anyhow::{Context, Result, ensure};
use day2::{
    artifact::{Instance, LoadedArtifact},
    authority_state::AuthorityDocument,
    instance_catalog::{QualifiedCatalog, qualify_artifacts},
    operation_contract::Kind,
};
use day2_capabilities::resources::{Action, Provider, ResourceTarget};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize)]
pub struct ActiveSelection {
    pub digest: Digest,
    pub releases: BTreeMap<String, ActivationReceipt>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActiveCatalog {
    pub selection: ActiveSelection,
    pub qualified: Option<QualifiedCatalog>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReleaseCatalogCandidate {
    release: Digest,
    base_selection: Digest,
    target: ReleaseTarget,
    qualified: QualifiedCatalog,
    bindings: Option<QualifiedBindings>,
}

#[derive(Clone, Debug, Serialize)]
pub struct QualifiedBindings {
    pub instance: Digest,
    pub authority: BTreeMap<String, Digest>,
    pub serving: BTreeMap<String, Digest>,
}

impl Journal {
    /// A coherent active selection from one installation and environment. A
    /// desired, failed, or superseded release contributes no exported operation.
    pub fn active_catalog_selection(
        &self,
        company: &Name,
        environment: &Name,
    ) -> Result<ActiveSelection> {
        active_selection_in(&self.connection, company, environment)
    }

    pub fn enable_catalog_scope(
        &mut self,
        company: &Name,
        environment: &Name,
        artifact_store: &Path,
    ) -> Result<()> {
        day2::schema::identifier(company.as_str())?;
        day2::schema::identifier(environment.as_str())?;
        let checked = self.active_catalog(company, environment, artifact_store)?;
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        ensure!(
            active_selection_in(&tx, company, environment)?.digest == checked.selection.digest,
            "active catalog changed during enrollment"
        );
        tx.execute(
            "INSERT OR IGNORE INTO release_catalog_scopes(scope) VALUES(?1)",
            [scope_key(company, environment)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn catalog_scope_enabled(&self, company: &Name, environment: &Name) -> Result<bool> {
        catalog_scope_enabled_in(&self.connection, company, environment)
    }

    /// Discovery sees only activated releases, and refuses missing or changed
    /// artifact bytes and any caller whose embedded import no longer resolves.
    pub fn active_catalog(
        &self,
        company: &Name,
        environment: &Name,
        artifact_store: &Path,
    ) -> Result<ActiveCatalog> {
        let selection = self.active_catalog_selection(company, environment)?;
        let qualified = if selection.releases.is_empty() {
            None
        } else {
            let checked = qualify_artifacts(
                company.as_str().into(),
                environment.as_str().into(),
                &artifact_paths(&selection, artifact_store)?,
            )?;
            for (app, receipt) in &selection.releases {
                ensure!(
                    checked.catalog.apps[app].artifact == receipt.artifact.as_str(),
                    "selected artifact bytes differ from active receipt: {app}"
                );
            }
            Some(checked)
        };
        Ok(ActiveCatalog {
            selection,
            qualified,
        })
    }

    /// Replace just the approved app in the active composition. The returned
    /// base selection is checked again inside the activation transaction.
    pub fn candidate_catalog(
        &self,
        approved: &ApprovedRelease,
        artifact_store: &Path,
    ) -> Result<ReleaseCatalogCandidate> {
        let stored = crate::release::current_approval(&self.connection, approved.id())?;
        let target = &stored.approval.target;
        let selection = self.active_catalog_selection(&target.company, &target.environment)?;
        let mut paths = artifact_paths(&selection, artifact_store)?;
        paths.insert(
            target.app.as_str().into(),
            artifact_path(artifact_store, &stored.approval.artifact)?,
        );
        let qualified = qualify_artifacts(
            target.company.as_str().into(),
            target.environment.as_str().into(),
            &paths,
        )?;
        ensure!(
            qualified.catalog.apps[target.app.as_str()].artifact
                == stored.approval.artifact.as_str(),
            "candidate artifact differs from approved release"
        );
        for (app, receipt) in &selection.releases {
            if app != target.app.as_str() {
                ensure!(
                    qualified.catalog.apps[app].artifact == receipt.artifact.as_str(),
                    "selected artifact bytes differ from active receipt: {app}"
                );
            }
        }
        Ok(ReleaseCatalogCandidate {
            release: approved.id().clone(),
            base_selection: selection.digest,
            target: target.clone(),
            qualified,
            bindings: None,
        })
    }

    /// Qualify the selected contract against instance-owned grants and the
    /// exact deployment readbacks for its imported serving targets.
    pub fn candidate_catalog_with_instance(
        &self,
        approved: &ApprovedRelease,
        artifact_store: &Path,
        instance_path: &Path,
        now_ms: i64,
    ) -> Result<ReleaseCatalogCandidate> {
        let mut candidate = self.candidate_catalog(approved, artifact_store)?;
        let instance = Instance::load(instance_path)?;
        ensure!(
            instance.installation == candidate.target.company.as_str()
                && instance.environment == candidate.target.environment.as_str(),
            "instance scope differs from release candidate"
        );
        let selection = self
            .active_catalog_selection(&candidate.target.company, &candidate.target.environment)?;
        ensure!(
            selection.digest == candidate.base_selection,
            "active catalog changed during binding qualification"
        );
        let mut paths = artifact_paths(&selection, artifact_store)?;
        paths.insert(
            candidate.target.app.as_str().to_owned(),
            artifact_path(
                artifact_store,
                &candidate.qualified.catalog.apps[candidate.target.app.as_str()]
                    .artifact
                    .clone()
                    .try_into()?,
            )?,
        );
        let mut artifacts = BTreeMap::new();
        for (app, path) in paths {
            artifacts.insert(app, LoadedArtifact::load(&path)?);
        }
        let mut authority = BTreeMap::new();
        let mut serving = BTreeMap::new();
        for (caller, imports) in &candidate.qualified.consumers.imports {
            let caller_artifact = artifacts
                .get(caller)
                .context("selected caller artifact missing")?;
            let document =
                AuthorityDocument::resolve_at(&instance, caller, caller_artifact, now_ms)
                    .with_context(|| format!("caller authority: {caller}"))?;
            authority.insert(caller.clone(), Digest::of(&document)?);
            for (operation, package) in &imports.operations {
                let (callee, _) = operation
                    .split_once('.')
                    .context("import target namespace")?;
                let callee_artifact = artifacts
                    .get(callee)
                    .context("selected callee artifact missing")?;
                let exported = callee_artifact
                    .contract()
                    .operations
                    .iter()
                    .find(|exported| exported.name == *operation)
                    .context("imported serving operation missing")?;
                ensure!(
                    package.operation.kind == Kind::Query && exported.kind == "query",
                    "imported serving operation is not a query: {operation}"
                );
                let schema =
                    day2::delegation::schema_digest_for_artifact(callee_artifact, operation)?;
                let actors = check_import_grant(&document, caller, operation, &schema)?;
                let callee_document =
                    AuthorityDocument::resolve_at(&instance, callee, callee_artifact, now_ms)
                        .with_context(|| format!("callee authority: {callee}"))?;
                ensure!(
                    actors
                        .iter()
                        .any(|actor| callee_document.authorize(exported, actor).is_ok()),
                    "callee access policy rejects every granted caller: {operation}"
                );
                authority.insert(callee.to_owned(), Digest::of(&callee_document)?);
                if !serving.contains_key(callee) {
                    let (release, active) = if callee == candidate.target.app.as_str() {
                        (&candidate.release, false)
                    } else {
                        (
                            &selection
                                .releases
                                .get(callee)
                                .context("imported callee not active")?
                                .release,
                            true,
                        )
                    };
                    serving.insert(
                        callee.to_owned(),
                        serving_binding_in(
                            &self.connection,
                            release,
                            callee,
                            callee_artifact.id(),
                            active,
                        )?,
                    );
                }
            }
        }
        candidate.bindings = Some(QualifiedBindings {
            instance: Digest::of(&instance)?,
            authority,
            serving,
        });
        Ok(candidate)
    }
}

fn check_import_grant(
    document: &AuthorityDocument,
    caller: &str,
    operation: &str,
    schema: &str,
) -> Result<BTreeSet<String>> {
    let mut actors = BTreeSet::new();
    for grants in document.resources.operations.values() {
        let mut matches = grants.values().filter(|grant| {
            matches!(&grant.target, ResourceTarget::AppOperation { operation: target, .. } if target == operation)
        });
        if let Some(grant) = matches.next() {
            ensure!(
                matches.next().is_none(),
                "ambiguous imported grant: {caller} -> {operation}"
            );
            ensure!(
                matches!(&grant.target, ResourceTarget::AppOperation { app, schema_digest, .. }
                    if app == operation.split_once('.').map(|(app, _)| app).unwrap_or("") && schema_digest == schema)
                    && grant.provider == Provider::LocalDelegation
                    && grant.actions.contains(&Action::DelegateQuery),
                "stale or incompatible imported grant: {caller} -> {operation}"
            );
            actors.extend(grant.actors.iter().cloned());
        }
    }
    ensure!(
        !actors.is_empty(),
        "imported operation has no configured grant: {caller} -> {operation}"
    );
    Ok(actors)
}

fn serving_binding_in(
    connection: &Connection,
    release: &Digest,
    app: &str,
    artifact: &str,
    active: bool,
) -> Result<Digest> {
    let execution =
        crate::release_execution::validated_execution_binding(connection, release, active)?;
    ensure!(
        execution.target.app.as_str() == app && execution.artifact.as_str() == artifact,
        "selected serving binding differs from imported target: {app}"
    );
    Digest::of(&("day2-import-serving-binding-v1", execution))
}

fn active_selection_in(
    connection: &Connection,
    company: &Name,
    environment: &Name,
) -> Result<ActiveSelection> {
    let mut statement = connection.prepare(
            "SELECT target,generation,active FROM release_slots WHERE active IS NOT NULL ORDER BY target",
        )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut releases = BTreeMap::new();
    for row in rows {
        let (target, generation, body) = row?;
        let target: ReleaseTarget = serde_json::from_str(&target)?;
        if target.company != *company || target.environment != *environment {
            continue;
        }
        let receipt: ActivationReceipt = serde_json::from_str(&body)?;
        ensure!(receipt.target == target, "active release target changed");
        ensure!(
            receipt.generation <= u64::try_from(generation)?,
            "active release generation changed"
        );
        ensure!(
            receipt.id
                == Digest::of(&(
                    "day2-release-activation-v1",
                    &receipt.release,
                    &receipt.readiness
                ))?,
            "active release receipt identity changed"
        );
        let immutable: Option<String> = connection
            .query_row(
                "SELECT body FROM release_activations WHERE release=?1",
                [receipt.release.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            immutable.as_deref() == Some(body.as_str()),
            "active release differs from immutable activation"
        );
        let approved = crate::release::read_approval(connection, &receipt.release)?;
        ensure!(
            approved.approval.target == target
                && approved.approval.artifact == receipt.artifact
                && approved.generation == receipt.generation,
            "active release differs from approved artifact"
        );
        ensure!(
            releases
                .insert(target.app.as_str().to_owned(), receipt)
                .is_none(),
            "duplicate active app release"
        );
    }
    let digest = Digest::of(&(
        "day2-active-catalog-selection-v1",
        company,
        environment,
        &releases,
    ))?;
    Ok(ActiveSelection { digest, releases })
}

fn scope_key(company: &Name, environment: &Name) -> Result<String> {
    Ok(serde_json::to_string(&(company, environment))?)
}

pub(crate) fn catalog_scope_enabled_in(
    connection: &Connection,
    company: &Name,
    environment: &Name,
) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM release_catalog_scopes WHERE scope=?1)",
        [scope_key(company, environment)?],
        |row| row.get(0),
    )?)
}

pub(crate) fn check_activation_candidate(
    connection: &Connection,
    release: &Digest,
    approval: &ReleaseApproval,
    candidate: Option<&ReleaseCatalogCandidate>,
) -> Result<()> {
    let target = &approval.target;
    let enabled = catalog_scope_enabled_in(connection, &target.company, &target.environment)?;
    if !enabled && candidate.is_none() {
        return Ok(());
    }
    let candidate = candidate.context("catalog-managed release requires qualified candidate")?;
    let active = active_selection_in(connection, &target.company, &target.environment)?;
    check_candidate_selection(
        connection,
        &active,
        release,
        target,
        &approval.artifact,
        candidate,
    )
}

fn check_candidate_selection(
    connection: &Connection,
    active: &ActiveSelection,
    release: &Digest,
    target: &ReleaseTarget,
    artifact: &Digest,
    candidate: &ReleaseCatalogCandidate,
) -> Result<()> {
    ensure!(
        candidate.release == *release,
        "candidate belongs to another release"
    );
    ensure!(candidate.target == *target, "candidate target changed");
    ensure!(
        candidate.base_selection == active.digest,
        "active catalog changed since candidate qualification"
    );
    let catalog = &candidate.qualified.catalog;
    catalog.verify()?;
    ensure!(
        catalog.installation == target.company.as_str()
            && catalog.environment == target.environment.as_str(),
        "candidate catalog scope changed"
    );
    let mut selected: Vec<&str> = active.releases.keys().map(String::as_str).collect();
    if !selected.contains(&target.app.as_str()) {
        selected.push(target.app.as_str());
        selected.sort_unstable();
    }
    ensure!(
        catalog.apps.keys().map(String::as_str).collect::<Vec<_>>() == selected,
        "candidate selection changed"
    );
    ensure!(
        catalog.apps[target.app.as_str()].artifact == artifact.as_str(),
        "candidate artifact differs from approved release"
    );
    for (app, receipt) in &active.releases {
        if app != target.app.as_str() {
            ensure!(
                catalog.apps[app].artifact == receipt.artifact.as_str(),
                "candidate changed another active app"
            );
        }
    }
    ensure!(
        candidate.qualified.consumers.catalog_digest == catalog.digest,
        "candidate consumer evidence belongs to another catalog"
    );
    if !candidate.qualified.consumers.imports.is_empty() {
        let bindings = candidate
            .bindings
            .as_ref()
            .context("imported release requires qualified instance bindings and access policy")?;
        ensure!(
            !bindings.authority.is_empty(),
            "imported release has no qualified authority"
        );
        let targets: std::collections::BTreeSet<_> = candidate
            .qualified
            .consumers
            .imports
            .values()
            .flat_map(|imports| imports.operations.keys())
            .map(|operation| operation.split_once('.').map(|(app, _)| app))
            .collect::<Option<_>>()
            .context("import target namespace")?;
        ensure!(
            bindings
                .serving
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>()
                == targets,
            "qualified serving target set changed"
        );
        for app in targets {
            let (selected_release, is_active) = if app == target.app.as_str() {
                (release, false)
            } else {
                (
                    &active
                        .releases
                        .get(app)
                        .context("imported callee not active")?
                        .release,
                    true,
                )
            };
            let actual = serving_binding_in(
                connection,
                selected_release,
                app,
                &catalog.apps[app].artifact,
                is_active,
            )?;
            ensure!(
                bindings.serving.get(app) == Some(&actual),
                "selected serving binding changed since qualification: {app}"
            );
        }
    }
    Ok(())
}

fn artifact_paths(selection: &ActiveSelection, root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    selection
        .releases
        .iter()
        .map(|(app, receipt)| Ok((app.clone(), artifact_path(root, &receipt.artifact)?)))
        .collect()
}

fn artifact_path(root: &Path, id: &Digest) -> Result<PathBuf> {
    let digest = id
        .as_str()
        .strip_prefix("sha256:")
        .context("artifact digest")?;
    let path = root.join(digest);
    ensure!(path.is_dir(), "selected artifact missing: {id:?}");
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use day2::{
        instance_catalog::{CandidateCatalog, CheckedConsumers, ResolvedImports, SelectedApp},
        operation_contract::Manifest,
    };
    use serde_json::json;

    fn authority_with_import_grant(schema: &str) -> Result<AuthorityDocument> {
        Ok(serde_json::from_value(json!({
            "enabled": true,
            "readers": [],
            "writers": [],
            "policy": null,
            "resources": {
                "operations": {"ask": {"directory": {
                    "policy": {"id": "reading", "revision": 1},
                    "resource": {"id": "lookup", "revision": 1},
                    "connection": {"id": "delegation", "revision": 1},
                    "provider": "local_delegation",
                    "target": {"kind": "app_operation", "app": "directory",
                        "operation": "directory.lookup", "schema_digest": schema},
                    "actions": ["delegate_query"],
                    "actors": ["alice"],
                    "limits": {"max_request_bytes": 16384,
                        "max_response_bytes": 65536, "max_calls_per_invocation": 4},
                    "budgets": [],
                    "expires_at_ms": null
                }}},
                "budgets": {}
            }
        }))?)
    }

    #[test]
    fn imported_query_requires_one_exact_resolved_grant() -> Result<()> {
        let schema = Digest::new(b"directory.lookup schema").as_str().to_owned();
        let mut document = authority_with_import_grant(&schema)?;
        check_import_grant(&document, "caller", "directory.lookup", &schema)?;
        assert!(
            check_import_grant(&document, "caller", "directory.lookup", "sha256:stale").is_err()
        );
        document.resources.operations.clear();
        assert!(check_import_grant(&document, "caller", "directory.lookup", &schema).is_err());
        let mut document = authority_with_import_grant(&schema)?;
        let grant = document.resources.operations["ask"]["directory"].clone();
        document
            .resources
            .operations
            .get_mut("ask")
            .unwrap()
            .insert("other".into(), grant);
        assert!(check_import_grant(&document, "caller", "directory.lookup", &schema).is_err());
        Ok(())
    }

    #[test]
    fn candidate_fence_rejects_a_changed_active_selection() -> Result<()> {
        let target = ReleaseTarget {
            company: "alpha".to_owned().try_into()?,
            environment: "production".to_owned().try_into()?,
            app: "reports".to_owned().try_into()?,
        };
        let artifact = Digest::new(b"selected artifact");
        let release = Digest::new(b"approved release");
        let catalog = CandidateCatalog::derive(
            target.company.as_str().to_owned(),
            target.environment.as_str().to_owned(),
            BTreeMap::from([(
                target.app.as_str().to_owned(),
                SelectedApp {
                    artifact: artifact.as_str().to_owned(),
                    manifest: Manifest::derive("reports".to_owned(), [], &BTreeMap::new())?,
                },
            )]),
        )?;
        let mut candidate = ReleaseCatalogCandidate {
            release: release.clone(),
            base_selection: Digest::new(b"base selection"),
            target: target.clone(),
            qualified: QualifiedCatalog {
                consumers: CheckedConsumers {
                    catalog_digest: catalog.digest.clone(),
                    dependencies: BTreeMap::new(),
                    imports: BTreeMap::new(),
                },
                catalog,
            },
            bindings: None,
        };
        let active = ActiveSelection {
            digest: candidate.base_selection.clone(),
            releases: BTreeMap::new(),
        };
        let connection = Connection::open_in_memory()?;
        check_candidate_selection(
            &connection,
            &active,
            &release,
            &target,
            &artifact,
            &candidate,
        )?;
        let changed = ActiveSelection {
            digest: Digest::new(b"new selection"),
            releases: BTreeMap::new(),
        };
        assert!(
            check_candidate_selection(
                &connection,
                &changed,
                &release,
                &target,
                &artifact,
                &candidate
            )
            .unwrap_err()
            .to_string()
            .contains("changed since candidate qualification")
        );
        candidate.qualified.consumers.imports.insert(
            "reports".into(),
            ResolvedImports {
                operations: BTreeMap::new(),
                types: BTreeMap::new(),
            },
        );
        assert!(
            check_candidate_selection(
                &connection,
                &active,
                &release,
                &target,
                &artifact,
                &candidate
            )
            .unwrap_err()
            .to_string()
            .contains("requires qualified instance bindings")
        );
        Ok(())
    }
}
