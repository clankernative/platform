//! Immutable reset-binding DATA, never approval, exclusion or writer authority.
//! The accepting owner must compare the actual held archive and retain its
//! genuine approval and incumbent exclusion before applying the SQL cut.
use super::kernel::restore::{Intent, KeyPurpose};
use anyhow::{Result, ensure};
use day2_capabilities::{BindingRef, Digest, credentials::Namespace, security_epoch::EpochStore};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: u8,
    selection: EpochStore,
    namespace: Namespace,
    intent: Intent,
    full_archive: Digest,
    custody: BindingRef,
    target_epoch: u64,
    inventory: Digest,
}

/// This closed record binds a denial cut. It cannot authorize a copy, key read,
/// database opener, maintenance action or return of an admitted writer.
pub(crate) struct Cut {
    record: Record,
    digest: Digest,
}

impl Cut {
    pub(in crate::security_epoch) fn new(
        selection: &EpochStore,
        namespace: Namespace,
        intent: Intent,
        full_archive: Digest,
        custody: BindingRef,
        inventory: Digest,
    ) -> Result<Self> {
        intent.commitment(selection)?;
        namespace.validate()?;
        ensure!(
            namespace.installation == selection.scope.installation
                && namespace.environment == selection.scope.environment
                && namespace.app == selection.scope.app,
            "restore_cut_namespace_changed"
        );
        let keys: Vec<_> = intent
            .archive
            .required_keys
            .iter()
            .filter(|key| key.purpose == KeyPurpose::CustodyEncryption)
            .collect();
        ensure!(
            !keys.is_empty() && keys.iter().all(|key| key.binding == custody),
            "restore_cut_custody_changed"
        );
        let target_epoch = intent
            .archive
            .security_epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("restore_cut_epoch_exhausted"))?;
        let record = Record {
            format: 1,
            selection: selection.clone(),
            namespace,
            intent,
            full_archive,
            custody,
            target_epoch,
            inventory,
        };
        let digest = Digest::of(&("day2-restore-denial-cut-v1", &record))?;
        Ok(Self { record, digest })
    }

    pub(crate) fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn inventory(&self) -> &Digest {
        &self.record.inventory
    }

    pub(crate) fn encoded(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.record)?)
    }

    pub(crate) fn check_storage_metadata(&self, db: &rusqlite::Connection) -> Result<()> {
        let scope: String = db.query_row(
            "SELECT value FROM main.day2_meta WHERE key='scope'",
            [],
            |r| r.get(0),
        )?;
        let schema: String = db.query_row(
            "SELECT value FROM main.day2_meta WHERE key='schema'",
            [],
            |r| r.get(0),
        )?;
        let selected = &self.record.selection.scope;
        ensure!(
            scope
                == format!(
                    "{}/{}/{}",
                    selected.installation.as_str(),
                    selected.environment.as_str(),
                    selected.app.as_str()
                )
                && schema == self.record.intent.archive.schema.as_str(),
            "restore_cut_storage_binding_changed"
        );
        Ok(())
    }

    /// SQL denial binding only. This does not admit a credential issuer,
    /// maintenance original, physical owner or restored writer.
    pub(in crate::security_epoch) fn require_credential_binding(
        &self,
        namespace: &Namespace,
        source_epoch: u64,
    ) -> Result<()> {
        namespace.validate()?;
        ensure!(
            namespace == &self.record.namespace
                && source_epoch == self.record.intent.archive.security_epoch,
            "restore_credential_cut_binding_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch) fn require_applied_in(
        &self,
        db: &rusqlite::Connection,
    ) -> Result<()> {
        ensure!(!db.is_autocommit(), "restore_cut_transaction_required");
        crate::oauth::schema::require_admission(db)?;
        self.check_storage_metadata(db)?;
        let (binding, inventory): (String, String) = db.query_row(
            "SELECT binding,inventory FROM main.oauth_restore_cuts WHERE digest=?1",
            [self.digest.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        ensure!(
            binding.len() <= 32768
                && binding == self.encoded()?
                && inventory == self.inventory().as_str(),
            "restore_applied_cut_changed"
        );
        Ok(())
    }

    pub(crate) fn validate_record(encoded: &str, digest: &str) -> Result<()> {
        ensure!(encoded.len() <= 32768, "restore_cut_record_bound");
        let record: Record = crate::json::decode(encoded.as_bytes())
            .map_err(|_| anyhow::anyhow!("restore_cut_record_encoding"))?;
        ensure!(record.format == 1, "restore_cut_record_format");
        let expected = Self::new(
            &record.selection,
            record.namespace.clone(),
            record.intent.clone(),
            record.full_archive.clone(),
            record.custody.clone(),
            record.inventory.clone(),
        )?;
        ensure!(
            expected.encoded()? == encoded && expected.digest().as_str() == digest,
            "restore_cut_record_changed"
        );
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn fixture(inventory: Digest, seed: u64) -> Result<Cut> {
    fixture_for_storage(
        inventory,
        seed,
        "company/canary/calendar",
        Digest::new(b"schema"),
    )
}

#[cfg(test)]
pub(crate) fn fixture_for_storage(
    inventory: Digest,
    seed: u64,
    scope: &str,
    schema: Digest,
) -> Result<Cut> {
    fixture_for_storage_epoch(inventory, seed, scope, schema, 1)
}

#[cfg(test)]
pub(crate) fn fixture_for_storage_epoch(
    inventory: Digest,
    seed: u64,
    scope: &str,
    schema: Digest,
    source_epoch: u64,
) -> Result<Cut> {
    use super::kernel::restore::{Backup, ExactKey};
    let mut selected = super::tests::selection();
    let parts: Vec<_> = scope.split('/').collect();
    ensure!(parts.len() == 3, "fixture_scope");
    selected.scope.installation = parts[0].to_owned().try_into()?;
    selected.scope.environment = parts[1].to_owned().try_into()?;
    selected.scope.app = parts[2].to_owned().try_into()?;
    let custody = BindingRef {
        id: "vault".to_owned().try_into()?,
        revision: Digest::new(b"vault-binding"),
    };
    let namespace = Namespace {
        installation: selected.scope.installation.clone(),
        environment: selected.scope.environment.clone(),
        app: selected.scope.app.clone(),
        binding_generation: 2,
    };
    let intent = Intent {
        operation: Digest::of(&("restore-cut-operation", seed))?,
        archive: Backup {
            scope: selected.scope.clone(),
            authority: selected.authority_key()?,
            source_incarnation: Digest::new(b"old-db"),
            security_epoch: source_epoch,
            image: Digest::new(b"archive-sqlite"),
            schema,
            artifact: Digest::new(b"artifact"),
            key_set: selected.key_set.clone(),
            required_keys: vec![ExactKey {
                binding: custody.clone(),
                version: "version-1".into(),
                purpose: KeyPurpose::CustodyEncryption,
            }],
        },
        target_incarnation: Digest::of(&("new-db", seed))?,
    };
    Cut::new(
        &selected,
        namespace,
        intent,
        Digest::new(b"complete-held-archive"),
        custody,
        inventory,
    )
}
