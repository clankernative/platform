//! A distinct executor ceremony; an approval signature names its executor but
//! does not authenticate the person presenting it. Only challenge DATA crosses
//! the human wait. Every native operation borrows a fresh actual admin reader.
use super::super::super::{TrustedKey, execution_request};
use super::super::{Origin, RegistryCeremony};
use super::{
    Assertion, AuthenticationBorrow, AuthenticationReader, ControllerAdminReader,
    ControllerRegistryData, Instance, KeyRecord, KeySource, controller_record, file,
    settle_verification,
};
use crate::security_epoch::{
    AuthenticationStoreFiles, restore_approval::signed::SignedApprovalRecord,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
};

// Pure checks against a complete actual snapshot supplied by the fixed native
// caller below. This helper never creates a TrustedKey or a native origin.
fn approval_record(
    instance: &Instance,
    context: &ControllerRegistryData,
    binding: Digest,
    signed: &SignedApprovalRecord,
) -> Result<()> {
    let statement = &signed.statement;
    statement.validate()?;
    let scope = &statement.request.target.scope;
    ensure!(
        context.scope
            == format!(
                "{}/{}/{}",
                scope.installation.as_str(),
                scope.environment.as_str(),
                scope.app.as_str()
            ),
        "restore_approval_current_scope_changed"
    );
    let control = instance
        .control
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("restore_registry_missing"))?;
    let key = control
        .restore_passkeys
        .as_ref()
        .and_then(|registry| {
            registry
                .keys
                .values()
                .find(|key| Digest::new(&key.credential_id) == statement.credential)
        })
        .ok_or_else(|| anyhow::anyhow!("restore_registry_credential_not_current"))?;
    let selected = controller_record(
        instance,
        context,
        binding,
        &key.credential_id,
        &statement.request.intent().commitment()?,
        &statement.request.executor.email,
    )?;
    ensure!(
        key.email == statement.approver.email
            && key.subject == statement.approver.subject
            && selected.registry == statement.registry,
        "restore_approval_current_approver_changed"
    );
    let signing = control
        .restore_approval_signing
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("restore_approval_signing_key_missing"))?;
    signing.validate()?;
    signed.verify_signature_data(statement, signing)
}

fn current_approval(
    reader: &mut ControllerAdminReader<'_, '_, '_>,
    held: &file::Held,
    signed: &SignedApprovalRecord,
) -> Result<()> {
    let requested = (|| {
        let context = reader.registry_data()?;
        held.require_path(&context.selector)?;
        let instance = Instance::from_bytes(&held.read()?)
            .map_err(|_| anyhow::anyhow!("restore_registry_config_invalid"))?;
        approval_record(&instance, &context, held.binding()?, signed)
    })();
    let native = reader.check_registry_local();
    let file = held.check_local();
    if requested.is_err() || native.is_err() || file.is_err() {
        reader.refuse();
    }
    requested?;
    native?;
    file
}

/// Current registry, real admin selection and signature only. Success creates
/// no executor authentication, time, consumption, fence or restore permission.
fn check_approval_record(
    reader: &mut ControllerAdminReader<'_, '_, '_>,
    signed: &SignedApprovalRecord,
) -> Result<()> {
    let requested = (|| {
        let context = reader.registry_data()?;
        let opened = file::Held::open(&context.selector);
        let checked = reader.check_registry_local();
        let held = opened?;
        checked?;
        current_approval(reader, &held, signed)
    })();
    let checked = reader.check_registry_local();
    if requested.is_err() || checked.is_err() {
        reader.refuse();
    }
    requested?;
    checked
}

fn executor_record(
    instance: &Instance,
    context: &ControllerRegistryData,
    binding: Digest,
    id: &[u8],
    signed: &SignedApprovalRecord,
) -> Result<KeyRecord> {
    approval_record(instance, context, binding.clone(), signed)?;
    let key = instance
        .control
        .as_ref()
        .and_then(|c| c.restore_passkeys.as_ref())
        .and_then(|registry| registry.keys.values().find(|key| key.credential_id == id))
        .ok_or_else(|| anyhow::anyhow!("restore_registry_executor_credential_not_current"))?;
    ensure!(
        key.email == signed.statement.request.executor.email
            && key.subject == signed.statement.request.executor.subject,
        "restore_registry_executor_identity_changed"
    );
    // Preserve the reader's two checked principals. Selecting the executor's
    // key does not rewrite or impersonate the approver selection.
    let active = super::super::Admins {
        enabled: true,
        artifact: context.artifact.clone(),
        stamp: context.authority.clone(),
        members: [context.approver.clone(), context.executor.clone()].into(),
    };
    super::super::record(
        instance,
        &context.scope,
        &context.app,
        &context.artifact,
        binding,
        &active,
        id,
    )
}

fn selected(
    reader: &mut ControllerAdminReader<'_, '_, '_>,
    held: &file::Held,
    id: &[u8],
    signed: &SignedApprovalRecord,
) -> Result<KeyRecord> {
    let requested = (|| {
        let context = reader.registry_data()?;
        held.require_path(&context.selector)?;
        let instance = Instance::from_bytes(&held.read()?)
            .map_err(|_| anyhow::anyhow!("restore_registry_config_invalid"))?;
        executor_record(&instance, &context, held.binding()?, id, signed)
    })();
    let native = reader.check_registry_local();
    let file = held.check_local();
    if requested.is_err() || native.is_err() || file.is_err() {
        reader.refuse();
    }
    let data = requested?;
    native?;
    file?;
    Ok(data)
}

/// Server-owned challenge DATA only, not the authenticated accepting owner.
/// It cannot be decoded, cloned or reconstructed from a challenge-store row.
pub(in crate::security_epoch) struct ControllerExecutionCeremony {
    ceremony: RegistryCeremony,
    signed: SignedApprovalRecord,
    operation: Digest,
}

impl ControllerExecutionCeremony {
    pub(in crate::security_epoch) fn check_approval_record(
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        signed: &SignedApprovalRecord,
    ) -> Result<()> {
        check_approval_record(reader, signed)
    }

    pub(in crate::security_epoch) fn capture(
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        credential_id: &[u8],
        signed: &SignedApprovalRecord,
        operation: &Digest,
    ) -> Result<Self> {
        let requested = (|| {
            let request = execution_request(signed, operation)?;
            ensure!(
                (1..=1023).contains(&credential_id.len()),
                "restore_registry_credential_bound"
            );
            let context = reader.registry_data()?;
            let opened = file::Held::open(&context.selector);
            let checked = reader.check_registry_local();
            let held = opened?;
            checked?;
            let record = selected(reader, &held, credential_id, signed)?;
            let mut nonce = [0; 32];
            let generated = getrandom::fill(&mut nonce)
                .map_err(|_| anyhow::anyhow!("restore_registry_entropy_unavailable"));
            let checked = reader.check_registry_local();
            generated?;
            checked?;
            ensure!(
                selected(reader, &held, credential_id, signed)? == record,
                "restore_registry_selection_changed"
            );
            Ok(Self {
                ceremony: RegistryCeremony {
                    held,
                    record,
                    request,
                    nonce,
                    attempted: Cell::new(false),
                    refused: Cell::new(false),
                    local: PhantomData,
                },
                signed: signed.clone(),
                operation: operation.clone(),
            })
        })();
        if requested.is_err() {
            reader.refuse();
        }
        requested
    }

    fn observe(&self, reader: &mut ControllerAdminReader<'_, '_, '_>) -> Result<()> {
        ensure!(
            !self.ceremony.refused.get(),
            "restore_registry_ceremony_refused"
        );
        ensure!(
            execution_request(&self.signed, &self.operation)? == self.ceremony.request,
            "restore_executor_request_changed"
        );
        ensure!(
            selected(
                reader,
                &self.ceremony.held,
                &self.ceremony.record.credential_id,
                &self.signed
            )? == self.ceremony.record,
            "restore_registry_selection_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch) fn encoded_challenge(&self) -> Result<String> {
        self.ceremony.encoded_challenge()
    }

    pub(in crate::security_epoch) fn issue_durable(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        sql: (&mut rusqlite::Connection, &mut AuthenticationStoreFiles),
        window: (i64, i64),
    ) -> Result<Digest> {
        let (db, files) = sql;
        let requested = (|| {
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.observe(reader)?;
            let challenge = self.ceremony.challenge()?;
            let mut borrow = AuthenticationBorrow {
                reader: AuthenticationReader::Active(&mut *reader),
                held: &self.ceremony.held,
                files: &mut *files,
            };
            let key = TrustedKey {
                record: self.ceremony.record.clone(),
                source: KeySource::Registry(Origin {
                    owner: RefCell::new(&mut borrow),
                }),
            };
            key.check_sqlite(db)?;
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let id = super::super::super::store::issue(&tx, &key, &challenge, window.0, window.1)?;
            key.check_sqlite(&tx)?;
            let committed = tx.commit();
            let checked = key.check_sqlite(db);
            committed?;
            checked?;
            Ok(id)
        })();
        let held = crate::store::check_authentication_sqlite(files, db);
        let native = reader.check_registry_local();
        let checked = (|| {
            held?;
            native?;
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.observe(reader)
        })();
        if requested.is_err() || checked.is_err() {
            self.ceremony.refused.set(true);
            files.refuse();
            reader.refuse();
        }
        let id = requested?;
        checked?;
        Ok(id)
    }

    pub(in crate::security_epoch) fn complete_durable(
        self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        sql: (&mut rusqlite::Connection, &mut AuthenticationStoreFiles),
        id: &Digest,
        at: i64,
        assertion: &Assertion,
    ) -> Result<Option<ExecutionCompletion>> {
        let (db, files) = sql;
        let requested = (|| {
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            ensure!(
                super::super::super::store::challenge_id(&self.ceremony.challenge()?)? == *id,
                "restore_registry_challenge_id_changed"
            );
            self.ceremony.begin_attempt()?;
            self.observe(reader)?;
            let mut borrow = AuthenticationBorrow {
                reader: AuthenticationReader::Active(&mut *reader),
                held: &self.ceremony.held,
                files: &mut *files,
            };
            let key = TrustedKey {
                record: self.ceremony.record.clone(),
                source: KeySource::Registry(Origin {
                    owner: RefCell::new(&mut borrow),
                }),
            };
            super::super::super::store::complete(
                db,
                &key,
                id,
                &self.ceremony.request,
                at,
                assertion,
            )
        })();
        let held = crate::store::check_authentication_sqlite(files, db);
        let native = reader.check_registry_local();
        let checked = (|| {
            held?;
            native?;
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.observe(reader)
        })();
        let result = settle_verification(requested, checked);
        if result.is_err() || matches!(&result, Ok(None)) {
            self.ceremony.refused.set(true);
        }
        if result.is_err() {
            files.refuse();
            reader.refuse();
        }
        let Some(facts) = result? else {
            return Ok(None);
        };
        let counter = facts.counter_data();
        let (version, snapshot) = self.completion_snapshot(reader, (db, files), counter)?;
        Ok(Some(ExecutionCompletion {
            ceremony: self,
            database: std::ptr::from_ref(db),
            counter,
            version,
            snapshot,
            phase: ExecutionPhase::Verified,
        }))
    }

    fn completion_snapshot(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        sql: (&mut rusqlite::Connection, &mut AuthenticationStoreFiles),
        counter: u32,
    ) -> Result<(i64, Digest)> {
        let (db, files) = sql;
        let requested = (|| {
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.observe(reader)?;
            let challenge = self.ceremony.challenge()?;
            let mut borrow = AuthenticationBorrow {
                reader: AuthenticationReader::Active(&mut *reader),
                held: &self.ceremony.held,
                files: &mut *files,
            };
            let key = TrustedKey {
                record: self.ceremony.record.clone(),
                source: KeySource::Registry(Origin {
                    owner: RefCell::new(&mut borrow),
                }),
            };
            verified_completion_snapshot(db, &key, &challenge, counter)
        })();
        let held = crate::store::check_authentication_sqlite(files, db);
        let native = reader.check_registry_local();
        let checked = (|| {
            held?;
            native?;
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.observe(reader)
        })();
        if requested.is_err() || checked.is_err() {
            self.ceremony.refused.set(true);
            files.refuse();
            reader.refuse();
        }
        let snapshot = requested?;
        checked?;
        Ok(snapshot)
    }
}

// The exact verified-row unit is shared; only its actual native read owner
// differs. No alternate verifier or callback can manufacture a completion.
fn verified_completion_snapshot(
    db: &mut rusqlite::Connection,
    key: &TrustedKey<'_>,
    challenge: &super::super::super::Challenge,
    counter: u32,
) -> Result<(i64, Digest)> {
    key.check_sqlite(db)?;
    let tx = db.transaction()?;
    let snapshot = super::super::super::store::verified_snapshot(&tx, key, challenge, counter)?;
    key.check_sqlite(&tx)?;
    let committed = tx.commit();
    let checked = key.check_sqlite(db);
    committed?;
    checked?;
    Ok(snapshot)
}

/// An in-memory completion from this exact verified SQL/native unit, not a
/// consumed approval or native execution owner. It cannot be recovered from
/// the persisted verified row. The accepting owner must retain the actual
/// action/source/original and reborrow its same boxed connection on each check.
pub(in crate::security_epoch) struct ExecutionCompletion {
    ceremony: ControllerExecutionCeremony,
    database: *const rusqlite::Connection,
    counter: u32,
    version: i64,
    snapshot: Digest,
    phase: ExecutionPhase,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExecutionPhase {
    Verified,
    Claiming,
    Claimed,
}

#[derive(Clone, Copy)]
enum AttemptUnit {
    Record,
    Check,
}

fn attempt_sql_unit(
    db: &mut rusqlite::Connection,
    key: &TrustedKey<'_>,
    challenge: &super::super::super::Challenge,
    signed: &SignedApprovalRecord,
    operation: &Digest,
    completed: (u32, i64, &Digest),
    unit: AttemptUnit,
) -> Result<()> {
    key.check_sqlite(db)?;
    let behavior = match unit {
        AttemptUnit::Record => rusqlite::TransactionBehavior::Immediate,
        AttemptUnit::Check => rusqlite::TransactionBehavior::Deferred,
    };
    let tx = db.transaction_with_behavior(behavior)?;
    match unit {
        AttemptUnit::Record => super::super::super::store::mark_may_execute(
            &tx, key, challenge, signed, operation, completed,
        )?,
        AttemptUnit::Check => super::super::super::store::check_may_execute(
            &tx, key, challenge, signed, operation, completed,
        )?,
    }
    key.check_sqlite(&tx)?;
    let committed = tx.commit();
    let checked = key.check_sqlite(db);
    committed?;
    checked
}

impl ExecutionCompletion {
    /// The actual completed executor, boxed connection and file/native loan
    /// remain retained. Claiming is sticky on error or unwind; a row never
    /// reconstructs this completion. The consuming stop still checks its own
    /// original before and after this fixed, closed SQL unit.
    pub(in crate::security_epoch) fn record_attempt(
        &mut self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        sql: (&mut rusqlite::Connection, &mut AuthenticationStoreFiles),
    ) -> Result<()> {
        if self.phase != ExecutionPhase::Verified {
            self.ceremony.ceremony.refused.set(true);
            sql.1.refuse();
            reader.refuse();
            anyhow::bail!("restore_executor_attempt_already_started");
        }
        self.phase = ExecutionPhase::Claiming;
        let result = self.attempt_unit(reader, sql, AttemptUnit::Record);
        if result.is_ok() {
            self.phase = ExecutionPhase::Claimed;
        }
        result
    }

    fn attempt_unit(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        sql: (&mut rusqlite::Connection, &mut AuthenticationStoreFiles),
        unit: AttemptUnit,
    ) -> Result<()> {
        let (db, files) = sql;
        let requested = (|| {
            ensure!(
                std::ptr::eq(self.database, std::ptr::from_ref(db)),
                "restore_executor_completion_owner_changed"
            );
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.ceremony.observe(reader)?;
            let challenge = self.ceremony.ceremony.challenge()?;
            let mut borrow = AuthenticationBorrow {
                reader: AuthenticationReader::Active(&mut *reader),
                held: &self.ceremony.ceremony.held,
                files: &mut *files,
            };
            let key = TrustedKey {
                record: self.ceremony.ceremony.record.clone(),
                source: KeySource::Registry(Origin {
                    owner: RefCell::new(&mut borrow),
                }),
            };
            attempt_sql_unit(
                db,
                &key,
                &challenge,
                &self.ceremony.signed,
                &self.ceremony.operation,
                (self.counter, self.version, &self.snapshot),
                unit,
            )
        })();
        let held = crate::store::check_authentication_sqlite(files, db);
        let native = reader.check_registry_local();
        let checked = (|| {
            held?;
            native?;
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.ceremony.observe(reader)
        })();
        if requested.is_err() || checked.is_err() {
            self.ceremony.ceremony.refused.set(true);
            files.refuse();
            reader.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn check_fenced(
        &self,
        reader: &mut crate::security_epoch::bootstrap::FencedRegistryLoan<'_, '_, '_, '_>,
        sql: (&mut rusqlite::Connection, &mut AuthenticationStoreFiles),
        signed: &SignedApprovalRecord,
        operation: &Digest,
    ) -> Result<()> {
        let (db, files) = sql;
        let observe = |reader: &mut crate::security_epoch::bootstrap::FencedRegistryLoan<
            '_,
            '_,
            '_,
            '_,
        >|
         -> Result<()> {
            ensure!(
                !self.ceremony.ceremony.refused.get(),
                "restore_registry_ceremony_refused"
            );
            let context = reader.registry_data()?;
            let held = &self.ceremony.ceremony.held;
            held.require_path(&context.selector)?;
            let instance = Instance::from_bytes(&held.read()?)
                .map_err(|_| anyhow::anyhow!("restore_registry_config_invalid"))?;
            ensure!(
                executor_record(
                    &instance,
                    &context,
                    held.binding()?,
                    &self.ceremony.ceremony.record.credential_id,
                    signed
                )? == self.ceremony.ceremony.record,
                "restore_registry_selection_changed"
            );
            held.check_local()?;
            reader.check_local()
        };
        let requested = (|| {
            ensure!(
                self.phase == ExecutionPhase::Claimed,
                "restore_executor_attempt_not_claimed"
            );
            ensure!(
                std::ptr::eq(self.database, std::ptr::from_ref(db))
                    && signed == &self.ceremony.signed
                    && operation == &self.ceremony.operation,
                "restore_executor_completion_owner_changed"
            );
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            observe(reader)?;
            let challenge = self.ceremony.ceremony.challenge()?;
            let mut borrow = AuthenticationBorrow {
                reader: AuthenticationReader::Fenced(&mut *reader),
                held: &self.ceremony.ceremony.held,
                files: &mut *files,
            };
            let key = TrustedKey {
                record: self.ceremony.ceremony.record.clone(),
                source: KeySource::Registry(Origin {
                    owner: RefCell::new(&mut borrow),
                }),
            };
            let current = verified_completion_snapshot(db, &key, &challenge, self.counter)?;
            ensure!(
                current.0 == self.version && current.1 == self.snapshot,
                "restore_executor_completion_changed"
            );
            attempt_sql_unit(
                db,
                &key,
                &challenge,
                &self.ceremony.signed,
                &self.ceremony.operation,
                (self.counter, self.version, &self.snapshot),
                AttemptUnit::Check,
            )?;
            Ok(())
        })();
        let held = crate::store::check_authentication_sqlite(files, db);
        let native = reader.check_local();
        let checked = (|| {
            held?;
            native?;
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            observe(reader)
        })();
        if requested.is_err() || checked.is_err() {
            self.ceremony.ceremony.refused.set(true);
            files.refuse();
            reader.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn check_current(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        sql: (&mut rusqlite::Connection, &mut AuthenticationStoreFiles),
        signed: &SignedApprovalRecord,
        operation: &Digest,
    ) -> Result<()> {
        let (db, files) = sql;
        let requested = (|| {
            ensure!(
                self.phase != ExecutionPhase::Claiming,
                "restore_executor_attempt_unsettled"
            );
            ensure!(
                std::ptr::eq(self.database, std::ptr::from_ref(db))
                    && signed == &self.ceremony.signed
                    && operation == &self.ceremony.operation,
                "restore_executor_completion_owner_changed"
            );
            let current = self
                .ceremony
                .completion_snapshot(reader, (db, files), self.counter)?;
            ensure!(
                current.0 == self.version && current.1 == self.snapshot,
                "restore_executor_completion_changed"
            );
            if self.phase == ExecutionPhase::Claimed {
                self.attempt_unit(reader, (db, files), AttemptUnit::Check)?;
            }
            Ok(())
        })();
        if requested.is_err() {
            self.ceremony.ceremony.refused.set(true);
            files.refuse();
            reader.refuse();
        }
        requested
    }
}

#[cfg(test)]
mod tests;
