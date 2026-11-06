//! Current Controller key selection under the actual accepting read loan.
//! A ceremony remains DATA across human wait. Verification borrows a fresh
//! genuine reader; no cached membership, signature or fact can replace it.
use super::super::{Assertion, AssertionFacts, KeyRecord, KeySource, TrustedKey};
use super::{Admins, NativeBorrow, Origin, RegistryCeremony, file, record};
use crate::{
    artifact::Instance,
    security_epoch::{ControllerAdminReader, ControllerRegistryData},
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
) -> Result<KeyRecord> {
    ensure!(
        context.operation == *request,
        "restore_registry_operation_changed"
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
) -> Result<KeyRecord> {
    let requested = (|| {
        let context = reader.registry_data()?;
        held.require_path(&context.selector)?;
        let bytes = held.read()?;
        let instance = Instance::from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("restore_registry_config_invalid"))?;
        controller_record(&instance, &context, held.binding()?, id, request)
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
    pub(in crate::security_epoch::restore_webauthn) fn capture_controller(
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        credential_id: &[u8],
        request: Digest,
    ) -> Result<Self> {
        let result = (|| {
            let context = reader.registry_data()?;
            ensure!(
                context.operation == request,
                "restore_registry_operation_changed"
            );
            ensure!(
                (1..=1023).contains(&credential_id.len()),
                "restore_registry_credential_bound"
            );
            let opened = file::Held::open(&context.selector);
            let checked = reader.check_registry_local();
            let held = opened?;
            checked?;
            let record = selected(reader, &held, credential_id, &request)?;
            let mut nonce = [0; 32];
            let generated = getrandom::fill(&mut nonce)
                .map_err(|_| anyhow::anyhow!("restore_registry_entropy_unavailable"));
            let checked = reader.check_registry_local();
            generated?;
            checked?;
            ensure!(
                selected(reader, &held, credential_id, &request)? == record,
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

    fn observe_controller(&self, reader: &mut ControllerAdminReader<'_, '_, '_>) -> Result<()> {
        ensure!(!self.refused.get(), "restore_registry_ceremony_refused");
        ensure!(
            selected(
                reader,
                &self.held,
                &self.record.credential_id,
                &self.request
            )? == self.record,
            "restore_registry_selection_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch::restore_webauthn) fn verify_current_controller(
        &self,
        reader: &mut ControllerAdminReader<'_, '_, '_>,
        stored_counter: u32,
        assertion: &Assertion,
    ) -> Result<AssertionFacts> {
        let result = (|| {
            self.begin_attempt()?;
            self.observe_controller(reader)?;
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
            let checked = self.observe_controller(reader);
            let facts = requested?;
            checked?;
            Ok(facts)
        })();
        if result.is_err() {
            self.refused.set(true);
            reader.refuse();
        }
        result
    }
}

#[cfg(test)]
mod tests;
