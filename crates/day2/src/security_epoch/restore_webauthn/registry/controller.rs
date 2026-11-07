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
