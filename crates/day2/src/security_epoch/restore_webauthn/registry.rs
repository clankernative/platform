//! Reviewed-instance key selection under a real, prefence native SQL owner.
//! The retained ceremony is DATA across human wait, not a cached permission.
//! No signer, restore approval, post-fence policy owner or ledger opener exists.
use super::{Assertion, AssertionFacts, Challenge, KeyRecord, KeySource, TrustedKey};
use crate::{
    artifact::Instance,
    store::{Runtime, RuntimeSql},
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
    rc::Rc,
};
mod controller;
mod file;

// Not a public extension point. The fixed production implementors retain an
// actual native RuntimeSql or Controller admin reader; DATA cannot supply one.
trait NativeBorrow {
    fn check_local(&mut self) -> Result<()>;
}
pub(super) struct Origin<'owner> {
    owner: RefCell<&'owner mut dyn NativeBorrow>,
}
impl Origin<'_> {
    pub(super) fn check_local(&self) -> Result<()> {
        self.owner
            .try_borrow_mut()
            .map_err(|_| anyhow::anyhow!("restore_registry_borrow_busy"))?
            .check_local()
    }
}
struct Borrow<'a, 'owner, 'stage, 'role, 'original> {
    runtime: &'a Runtime,
    sql: &'a mut RuntimeSql<'owner, 'stage, 'role, 'original>,
    held: &'a file::Held,
}
impl NativeBorrow for Borrow<'_, '_, '_, '_, '_> {
    fn check_local(&mut self) -> Result<()> {
        self.sql.require_native_registry_read(self.runtime)?;
        self.held.check_local()?;
        self.sql.require_native_registry_read(self.runtime)
    }
}

/// Only capture() can create this server-owned continuation. No Clone, codec,
/// row reconstruction or current grant survives human interaction or restart.
pub(super) struct RegistryCeremony {
    held: file::Held,
    record: KeyRecord,
    request: Digest,
    nonce: [u8; 32],
    attempted: Cell<bool>,
    refused: Cell<bool>,
    local: PhantomData<Rc<()>>,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($type:ty, $bound:path) => {{
            trait AmbiguousIfImpl<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?Sized + $bound> AmbiguousIfImpl<u8> for T {}
            let _ = <$type as AmbiguousIfImpl<_>>::check;
        }};
    }
    macro_rules! closed {
        ($type:ty) => {
            assert_not_impl!($type, Clone);
            assert_not_impl!($type, Copy);
            assert_not_impl!($type, Default);
            assert_not_impl!($type, std::fmt::Debug);
            assert_not_impl!($type, serde::Serialize);
            assert_not_impl!($type, serde::Deserialize<'static>);
            assert_not_impl!($type, Send);
            assert_not_impl!($type, Sync);
        };
    }
    closed!(super::TrustedKey<'static>);
    closed!(Origin<'static>);
    closed!(RegistryCeremony);
};

struct Admins {
    enabled: bool,
    artifact: String,
    stamp: crate::authority_state::AuthorityStamp,
    members: std::collections::BTreeSet<String>,
}

fn record(
    instance: &Instance,
    scope: &str,
    app: &str,
    artifact: &str,
    file_binding: Digest,
    active: &Admins,
    id: &[u8],
) -> Result<KeyRecord> {
    ensure!(
        instance.scope(app)? == scope,
        "restore_registry_scope_changed"
    );
    let registry = instance
        .control
        .as_ref()
        .and_then(|c| c.restore_passkeys.as_ref())
        .ok_or_else(|| anyhow::anyhow!("restore_registry_missing"))?;
    registry.validate()?;
    let key = registry
        .keys
        .values()
        .find(|key| key.credential_id == id)
        .ok_or_else(|| anyhow::anyhow!("restore_registry_credential_not_current"))?;
    ensure!(
        key.origin == instance.security_edge()?.1.origin,
        "restore_registry_shell_origin_changed"
    );
    ensure!(
        active.enabled
            && active.artifact == artifact
            && active.stamp.revision > 0
            && active.members.contains(&key.email),
        "restore_registry_current_admin_required"
    );
    Ok(KeyRecord {
        admin: Digest::of(&(
            "day2-restore-registry-admin-v1",
            scope,
            &key.email,
            &key.subject,
            &active.stamp,
        ))?,
        registry: Digest::of(&(
            "day2-restore-registry-selection-v1",
            file_binding,
            Digest::of(instance)?,
            registry.content_digest()?,
            &active.stamp,
        ))?,
        revision: active.stamp.revision,
        credential_id: key.credential_id.clone(),
        user_handle: key.user_handle.clone(),
        public_key: key.cose_key.uncompressed_p256().to_vec(),
        rp_id: key.rp_id.clone(),
        origin: key.origin.clone(),
        backup_eligible: key.backup_eligible,
    })
}

fn selected(
    runtime: &Runtime,
    sql: &mut RuntimeSql<'_, '_, '_, '_>,
    held: &file::Held,
    id: &[u8],
) -> Result<KeyRecord> {
    sql.require_native_registry_read(runtime)?;
    held.require_path(runtime.restore_registry_path()?)?;
    let bytes = held.read()?;
    let instance = Instance::from_bytes(&bytes)
        .map_err(|_| anyhow::anyhow!("restore_registry_config_invalid"))?;
    let active = sql.read(|db| {
        runtime.check_binding(db)?;
        let active = crate::authority_state::current(db)?;
        active.document.validate(runtime.artifact())?;
        let members = active.policy()?.admins.clone();
        Ok(Admins {
            enabled: active.document.enabled,
            artifact: active.artifact_id,
            stamp: active.stamp,
            members,
        })
    })?;
    held.check_local()?;
    sql.require_native_registry_read(runtime)?;
    record(
        &instance,
        runtime.scope(),
        runtime.app(),
        runtime.artifact().id(),
        held.binding()?,
        &active,
        id,
    )
}

impl RegistryCeremony {
    pub(super) fn capture(
        runtime: &Runtime,
        sql: &mut RuntimeSql<'_, '_, '_, '_>,
        credential_id: &[u8],
        request: Digest,
    ) -> Result<Self> {
        let result = (|| {
            sql.require_native_registry_read(runtime)?;
            ensure!(
                (1..=1023).contains(&credential_id.len()),
                "restore_registry_credential_bound"
            );
            let held = file::Held::open(runtime.restore_registry_path()?)?;
            let record = selected(runtime, sql, &held, credential_id)?;
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce)
                .map_err(|_| anyhow::anyhow!("restore_registry_entropy_unavailable"))?;
            ensure!(
                selected(runtime, sql, &held, credential_id)? == record,
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
            sql.refuse_registry();
        }
        result
    }

    fn challenge(&self) -> Result<Challenge> {
        ensure!(!self.refused.get(), "restore_registry_ceremony_refused");
        Ok(Challenge {
            request: self.request.clone(),
            nonce: self.nonce,
            enrollment: self.record.binding_data()?,
        })
    }

    /// Challenge DATA only. The existing request-bound durable one-use store
    /// must be joined before any approval; this creates no signing permission.
    pub(super) fn encoded_challenge(&self) -> Result<String> {
        ensure!(
            !self.attempted.get(),
            "restore_registry_ceremony_already_attempted"
        );
        self.challenge()?.encoded()
    }

    fn observe(&self, runtime: &Runtime, sql: &mut RuntimeSql<'_, '_, '_, '_>) -> Result<()> {
        ensure!(!self.refused.get(), "restore_registry_ceremony_refused");
        ensure!(
            selected(runtime, sql, &self.held, &self.record.credential_id)? == self.record,
            "restore_registry_selection_changed"
        );
        Ok(())
    }

    fn begin_attempt(&self) -> Result<()> {
        ensure!(
            !self.refused.get() && !self.attempted.replace(true),
            "restore_registry_ceremony_already_attempted"
        );
        Ok(())
    }

    /// A fresh real native owner is required after human wait. It does not
    /// renew an old Current or turn this ceremony/return DATA into an approval.
    /// No transaction is held across configuration reads or signature work.
    pub(super) fn verify_current(
        &self,
        runtime: &Runtime,
        sql: &mut RuntimeSql<'_, '_, '_, '_>,
        stored_counter: u32,
        assertion: &Assertion,
    ) -> Result<AssertionFacts> {
        let result = (|| {
            self.begin_attempt()?;
            self.observe(runtime, sql)?;
            let challenge = self.challenge()?;
            let requested = {
                let mut borrow = Borrow {
                    runtime,
                    sql,
                    held: &self.held,
                };
                let key = TrustedKey {
                    record: self.record.clone(),
                    source: KeySource::Registry(Origin {
                        owner: RefCell::new(&mut borrow),
                    }),
                };
                super::verify(&key, &challenge, &self.request, stored_counter, assertion)
            };
            // Evaluate the actual postcheck even if verification refused, then
            // preserve the primary requested error when both failed.
            let checked = self.observe(runtime, sql);
            let value = requested?;
            checked?;
            Ok(value)
        })();
        if result.is_err() {
            self.refused.set(true);
            sql.refuse_registry();
        }
        result
    }
}

#[cfg(test)]
mod tests;
