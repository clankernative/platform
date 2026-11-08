//! Current Controller key selection under the actual accepting read loan.
//! A ceremony remains DATA across human wait. Verification borrows a fresh
//! genuine reader; no cached membership, signature or fact can replace it.
use super::super::{Assertion, AssertionFacts, KeyRecord, KeySource, TrustedKey};
use super::{Admins, NativeBorrow, Origin, RegistryCeremony, file, record};
use crate::{
    artifact::Instance,
    security_epoch::{
        ControllerAdminReader, ControllerRegistryData, restore_approval::ApprovalIntent,
    },
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
};

mod execution;
pub(in crate::security_epoch) use execution::{ControllerExecutionCeremony, ExecutionCompletion};

struct AuthenticationBorrow<'borrow, 'fenced, 'metadata, 'storage, 'role> {
    reader: AuthenticationReader<'borrow, 'fenced, 'metadata, 'storage, 'role>,
    held: &'borrow file::Held,
    files: &'borrow mut crate::security_epoch::AuthenticationStoreFiles,
}

enum AuthenticationReader<'borrow, 'fenced, 'metadata, 'storage, 'role> {
    Active(&'borrow mut ControllerAdminReader<'metadata, 'storage, 'role>),
    Fenced(
        &'borrow mut crate::security_epoch::bootstrap::FencedRegistryLoan<
            'fenced,
            'metadata,
            'storage,
            'role,
        >,
    ),
}

impl AuthenticationReader<'_, '_, '_, '_, '_> {
    fn check_local(&mut self) -> Result<()> {
        match self {
            Self::Active(reader) => reader.check_registry_local(),
            Self::Fenced(reader) => reader.check_local(),
        }
    }
    fn refuse(&mut self) {
        match self {
            Self::Active(reader) => reader.refuse(),
            Self::Fenced(reader) => reader.refuse(),
        }
    }
}

pub(in crate::security_epoch) enum SigningUnit<'a> {
    Prepare {
        statement: &'a crate::security_epoch::restore_approval::signed::ApprovalStatement,
        counter: u32,
    },
    MaySign {
        statement: &'a crate::security_epoch::restore_approval::signed::ApprovalStatement,
    },
    CheckMay {
        statement: &'a crate::security_epoch::restore_approval::signed::ApprovalStatement,
    },
    Published {
        record: &'a crate::security_epoch::restore_approval::signed::SignedApprovalRecord,
    },
}

impl NativeBorrow for AuthenticationBorrow<'_, '_, '_, '_, '_> {
    fn check_local(&mut self) -> Result<()> {
        let before = self.reader.check_local();
        let files = self.files.check();
        let registry = self.held.check_local();
        let after = self.reader.check_local();
        if before.is_err() || files.is_err() || registry.is_err() || after.is_err() {
            self.files.refuse();
            self.reader.refuse();
        }
        before?;
        files?;
        registry?;
        after
    }

    fn check_sqlite(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.check_local()?;
        let requested = crate::store::check_authentication_sqlite(self.files, db);
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.files.refuse();
            self.reader.refuse();
        }
        requested?;
        checked
    }
}

struct ControllerBorrow<'borrow, 'metadata, 'storage, 'role> {
    reader: &'borrow mut ControllerAdminReader<'metadata, 'storage, 'role>,
    held: &'borrow file::Held,
}

/// Server-owned challenge DATA, not an approval. Full intent equality survives
/// human interaction; actual verification still borrows a fresh genuine reader.
pub(in crate::security_epoch) struct ControllerCeremony {
    ceremony: RegistryCeremony,
    intent: ApprovalIntent,
}

impl ControllerCeremony {
    fn require_challenge_id(&self, id: &Digest) -> Result<()> {
        ensure!(
            super::super::store::challenge_id(&self.ceremony.challenge()?)? == *id,
            "restore_registry_challenge_id_changed"
        );
        Ok(())
    }

    /// Fixed complete journal unit only. It lends no connection, transaction,
    /// generic callback or signing permission to its caller.
    pub(in crate::security_epoch) fn signing_unit(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        sql: (
            &mut rusqlite::Connection,
            &mut crate::security_epoch::AuthenticationStoreFiles,
        ),
        id: &Digest,
        unit: SigningUnit<'_>,
    ) -> Result<()> {
        let (db, files) = sql;
        let requested = (|| {
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.require_challenge_id(id)?;
            self.ceremony
                .observe_controller(reader, &self.intent.executor.email)?;
            let statement = match &unit {
                SigningUnit::Prepare { statement, .. }
                | SigningUnit::MaySign { statement }
                | SigningUnit::CheckMay { statement } => *statement,
                SigningUnit::Published { record } => &record.statement,
            };
            self.intent.require_request(&statement.request)?;
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
            match unit {
                SigningUnit::Prepare { statement, counter } => {
                    super::super::store::prepare_signing(&tx, &key, id, statement, counter)?
                }
                SigningUnit::MaySign { statement } => {
                    super::super::store::mark_may_sign(&tx, &key, id, statement)?
                }
                SigningUnit::CheckMay { statement } => {
                    super::super::store::check_may_sign(&tx, &key, id, statement)?
                }
                SigningUnit::Published { record } => {
                    super::super::store::record_publication(&tx, &key, id, record)?
                }
            }
            key.check_sqlite(&tx)?;
            let committed = tx.commit();
            let checked = key.check_sqlite(db);
            committed?;
            checked
        })();
        let held = crate::store::check_authentication_sqlite(files, db);
        let native = reader.check_registry_local();
        let checked = (|| {
            held?;
            native?;
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.ceremony
                .observe_controller(reader, &self.intent.executor.email)
        })();
        if requested.is_err() || checked.is_err() {
            self.ceremony.refused.set(true);
            files.refuse();
            reader.refuse();
        }
        requested?;
        checked
    }

    /// Current selection and assertion commitment DATA only. This cannot
    /// replace the actual durable completion or qualified clock held by the
    /// producer's private completed owner.
    pub(in crate::security_epoch) fn statement_data(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        request: &crate::security_epoch::restore_approval::ApprovalRequest,
        assertion: &Assertion,
    ) -> Result<(
        crate::security_epoch::restore_approval::signed::ApprovalStatement,
        day2_capabilities::restore_signing::KeySelection,
    )> {
        let requested = (|| {
            self.intent.require_request(request)?;
            self.ceremony
                .observe_controller(reader, &request.executor.email)?;
            let context = reader.registry_data()?;
            self.ceremony.held.require_path(&context.selector)?;
            let bytes = self.ceremony.held.read()?;
            let instance = Instance::from_bytes(&bytes)
                .map_err(|_| anyhow::anyhow!("restore_registry_config_invalid"))?;
            let active = controller_record(
                &instance,
                &context,
                self.ceremony.held.binding()?,
                &self.ceremony.record.credential_id,
                &self.ceremony.request,
                &request.executor.email,
            )?;
            ensure!(
                active == self.ceremony.record,
                "restore_registry_selection_changed"
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
                        .find(|key| key.credential_id == active.credential_id)
                })
                .ok_or_else(|| anyhow::anyhow!("restore_registry_credential_not_current"))?;
            let signing = control
                .restore_approval_signing
                .clone()
                .ok_or_else(|| anyhow::anyhow!("restore_approval_signing_key_missing"))?;
            signing.validate()?;
            let statement = crate::security_epoch::restore_approval::signed::ApprovalStatement {
                request: request.clone(),
                approver: crate::security_epoch::restore_approval::AdminIdentity {
                    email: key.email.clone(),
                    subject: key.subject.clone(),
                },
                registry: active.registry.clone(),
                credential: Digest::new(&active.credential_id),
                assertion: Digest::of(&(
                    "day2-restore-verified-assertion-v1",
                    self.ceremony.challenge()?.encoded()?,
                    &assertion.credential_id,
                    &assertion.client_data_json,
                    &assertion.authenticator_data,
                    &assertion.signature,
                    &assertion.user_handle,
                ))?,
                signing_key: signing.commitment()?,
            };
            statement.validate()?;
            Ok((statement, signing))
        })();
        let checked = self
            .ceremony
            .observe_controller(reader, &request.executor.email);
        if requested.is_err() || checked.is_err() {
            self.ceremony.refused.set(true);
            reader.refuse();
        }
        let data = requested?;
        checked?;
        Ok(data)
    }

    /// Fixed native producer operation. The pair is the owning action's actual
    /// SQLite connection and retained file lease, never a caller-chosen path.
    /// Commit is followed by an actual handle check before any full policy read.
    pub(in crate::security_epoch) fn issue_durable(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        sql: (
            &mut rusqlite::Connection,
            &mut crate::security_epoch::AuthenticationStoreFiles,
        ),
        expected: &ApprovalIntent,
        window: (i64, i64),
    ) -> Result<Digest> {
        let (db, files) = sql;
        let requested = (|| {
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.intent.require_exact(expected)?;
            self.ceremony
                .observe_controller(reader, &expected.executor.email)?;
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
            let id = super::super::store::issue(&tx, &key, &challenge, window.0, window.1)?;
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
            self.ceremony
                .observe_controller(reader, &expected.executor.email)
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

    /// A durable claim is spent before verification. Known assertion denials
    /// become DATA only after the actual current registry/native postcheck.
    /// Unknown or native errors retain their underlying identity and refuse.
    pub(in crate::security_epoch) fn complete_durable(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        sql: (
            &mut rusqlite::Connection,
            &mut crate::security_epoch::AuthenticationStoreFiles,
        ),
        id: &Digest,
        completion: (&ApprovalIntent, i64, &Assertion),
    ) -> Result<Option<AssertionFacts>> {
        let (db, files) = sql;
        let (expected, at, assertion) = completion;
        let requested = (|| {
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.require_challenge_id(id)?;
            self.intent.require_exact(expected)?;
            self.ceremony.begin_attempt()?;
            self.ceremony
                .observe_controller(reader, &expected.executor.email)?;
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
            super::super::store::complete(db, &key, id, &expected.commitment()?, at, assertion)
        })();
        let held = crate::store::check_authentication_sqlite(files, db);
        let native = reader.check_registry_local();
        let checked = (|| {
            held?;
            native?;
            ensure!(db.is_autocommit(), "restore_auth_transaction_open");
            self.ceremony
                .observe_controller(reader, &expected.executor.email)
        })();
        let result = settle_verification(requested, checked);
        if result.is_err() || matches!(&result, Ok(None)) {
            self.ceremony.refused.set(true);
        }
        if result.is_err() {
            files.refuse();
            reader.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn capture(
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        credential_id: &[u8],
        intent: ApprovalIntent,
    ) -> Result<Self> {
        let result = (|| {
            let request = intent.commitment()?;
            let ceremony = RegistryCeremony::capture_controller(
                reader,
                credential_id,
                request,
                &intent.executor.email,
            )?;
            Ok(Self { ceremony, intent })
        })();
        if result.is_err() {
            reader.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn encoded_challenge(&self) -> Result<String> {
        self.ceremony.encoded_challenge()
    }

    pub(in crate::security_epoch) fn verify_current(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        expected: &ApprovalIntent,
        stored_counter: u32,
        assertion: &Assertion,
    ) -> Result<Option<AssertionFacts>> {
        let result = (|| {
            self.intent.require_exact(expected)?;
            self.ceremony.verify_current_controller(
                reader,
                &self.intent.executor.email,
                stored_counter,
                assertion,
            )
        })();
        if result.is_err() {
            self.ceremony.refused.set(true);
            reader.refuse();
        }
        result
    }
}

impl NativeBorrow for ControllerBorrow<'_, '_, '_, '_> {
    fn check_local(&mut self) -> Result<()> {
        self.reader.check_registry_local()?;
        let requested = self.held.check_local();
        let checked = self.reader.check_registry_local();
        if requested.is_err() || checked.is_err() {
            self.reader.refuse();
        }
        requested?;
        checked
    }
}

// All inputs remain DATA. Only selected() obtains them from the actual reader
// and retained config; this helper creates no TrustedKey or native source.
fn controller_record(
    instance: &Instance,
    context: &ControllerRegistryData,
    file_binding: Digest,
    id: &[u8],
    request: &Digest,
    executor: &str,
) -> Result<KeyRecord> {
    ensure!(
        context.operation == *request,
        "restore_registry_operation_changed"
    );
    ensure!(
        context.executor == executor,
        "restore_registry_executor_selection_changed"
    );
    ensure!(
        Digest::of(instance)? == context.instance,
        "restore_registry_config_changed"
    );
    let key = instance
        .control
        .as_ref()
        .and_then(|c| c.restore_passkeys.as_ref())
        .and_then(|registry| registry.keys.values().find(|key| key.credential_id == id))
        .ok_or_else(|| anyhow::anyhow!("restore_registry_credential_not_current"))?;
    ensure!(
        key.email == context.approver,
        "restore_registry_approver_changed"
    );
    let active = Admins {
        enabled: true,
        artifact: context.artifact.clone(),
        stamp: context.authority.clone(),
        // These are the two principals actually checked by this retained
        // reader, not names from the desired instance policy.
        members: [context.approver.clone(), context.executor.clone()].into(),
    };
    record(
        instance,
        &context.scope,
        &context.app,
        &context.artifact,
        file_binding,
        &active,
        id,
    )
}

fn selected(
    reader: &mut ControllerAdminReader<'_, '_, '_>,
    held: &file::Held,
    id: &[u8],
    request: &Digest,
    executor: &str,
) -> Result<KeyRecord> {
    let requested = (|| {
        let context = reader.registry_data()?;
        held.require_path(&context.selector)?;
        let bytes = held.read()?;
        let instance = Instance::from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("restore_registry_config_invalid"))?;
        controller_record(&instance, &context, held.binding()?, id, request, executor)
    })();
    let checked = reader.check_registry_local();
    if requested.is_err() || checked.is_err() {
        reader.refuse();
    }
    let record = requested?;
    checked?;
    Ok(record)
}

impl RegistryCeremony {
    fn capture_controller(
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        credential_id: &[u8],
        request: Digest,
        executor: &str,
    ) -> Result<Self> {
        let result = (|| {
            let context = reader.registry_data()?;
            ensure!(
                context.operation == request && context.executor == executor,
                "restore_registry_operation_or_executor_changed"
            );
            ensure!(
                (1..=1023).contains(&credential_id.len()),
                "restore_registry_credential_bound"
            );
            let opened = file::Held::open(&context.selector);
            let checked = reader.check_registry_local();
            let held = opened?;
            checked?;
            let record = selected(reader, &held, credential_id, &request, executor)?;
            let mut nonce = [0; 32];
            let generated = getrandom::fill(&mut nonce)
                .map_err(|_| anyhow::anyhow!("restore_registry_entropy_unavailable"));
            let checked = reader.check_registry_local();
            generated?;
            checked?;
            ensure!(
                selected(reader, &held, credential_id, &request, executor)? == record,
                "restore_registry_selection_changed"
            );
            Ok(Self {
                held,
                record,
                request,
                nonce,
                attempted: Cell::new(false),
                refused: Cell::new(false),
                local: PhantomData,
            })
        })();
        if result.is_err() {
            reader.refuse();
        }
        result
    }

    fn observe_controller(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        executor: &str,
    ) -> Result<()> {
        ensure!(!self.refused.get(), "restore_registry_ceremony_refused");
        ensure!(
            selected(
                reader,
                &self.held,
                &self.record.credential_id,
                &self.request,
                executor,
            )? == self.record,
            "restore_registry_selection_changed"
        );
        Ok(())
    }

    fn verify_current_controller(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        executor: &str,
        stored_counter: u32,
        assertion: &Assertion,
    ) -> Result<Option<AssertionFacts>> {
        let result = (|| {
            self.begin_attempt()?;
            self.observe_controller(reader, executor)?;
            let challenge = self.challenge()?;
            let requested = {
                let mut borrow = ControllerBorrow {
                    reader,
                    held: &self.held,
                };
                let key = TrustedKey {
                    record: self.record.clone(),
                    source: KeySource::Registry(Origin {
                        owner: RefCell::new(&mut borrow),
                    }),
                };
                super::super::verify(&key, &challenge, &self.request, stored_counter, assertion)
            };
            let checked = self.observe_controller(reader, executor);
            settle_verification(requested, checked)
        })();
        if result.is_err() {
            self.refused.set(true);
            reader.refuse();
        } else if matches!(&result, Ok(None)) {
            // A known denial spends this attempt without poisoning a reader
            // whose actual postchecks succeeded. No retry on the ceremony.
            self.refused.set(true);
        }
        result
    }
}

/// Only this fixed native caller converts an actual typed assertion rejection
/// into DATA, after the actual current-source postcheck has already run and
/// succeeded. Unknown errors retain their identity, and a failed postcheck
/// never becomes a known denial. The caller refuses the reader on every Err.
fn settle_verification(
    requested: Result<AssertionFacts>,
    checked: Result<()>,
) -> Result<Option<AssertionFacts>> {
    match requested {
        Ok(facts) => {
            checked?;
            Ok(Some(facts))
        }
        Err(error) if error.is::<super::super::AssertionDenied>() => {
            checked?;
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;
