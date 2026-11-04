//! Host-selected, short-lived readiness and exact-version custody leases.
//! The snapshot is supplied by the installation's admitted readiness adapters;
//! browser fields never select a provider, key, issuer or security epoch.
use super::{
    crypto::{KeyLease, VerifierLease},
    issuance::{Authority, ReadyKeys},
    store::HumanRevealPermit,
};
use crate::oauth::approval_registry::{ApprovalKeyProvider, ApprovalKeyPurpose, ApprovalKeyRef};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    BindingRef, Digest,
    credentials::{CredentialFamilyBinding, ManagementPolicy, ManagementPredicate, Namespace},
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, RwLock},
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct Selection {
    pub binding: CredentialFamilyBinding,
    pub security_origin: String,
    pub management: ManagementPolicy,
    pub verifier: ApprovalKeyRef,
    pub encryption: ApprovalKeyRef,
    pub security_epoch: u64,
    pub observed_at: i64,
    pub ready_until: i64,
    pub grant_until: i64,
    pub max_active_lineages: u32,
    /// Current admitted human accounts, keyed by email with canonical subjects.
    pub issuers: BTreeMap<String, String>,
}

pub(crate) struct SelectedAuthority {
    entries: Arc<RwLock<Selections>>,
    keys: Arc<dyn ApprovalKeyProvider>,
    verification: Arc<dyn VerificationSource>,
    history: Mutex<VerificationHistory>,
}

struct Selections {
    current: Vec<Selection>,
    revision: u64,
    // Process-local refusal memory only, never an external epoch witness.
    // Removing a family must not make an already observed epoch forgettable.
    epoch_floor: BTreeMap<Digest, u64>,
}

/// A trusted installation adapter must supply a fresh, authenticated LOCAL
/// observation, including its actual origin. This port is also called inside
/// guarded SQL: it must not acquire another owner or perform provider/network
/// I/O. No native source or factory is installed by this module.
pub(crate) trait VerificationSource: Send + Sync {
    fn current(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        minimum_time: i64,
    ) -> Result<VerificationObservation>;
}

/// DATA returned by that trusted source, never a native proof, readiness grant,
/// or a browser-selectable authority. Revisions include retirement/key changes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerificationObservation {
    pub namespace: Namespace,
    pub family: day2_capabilities::Name,
    pub epoch_store: BindingRef,
    pub binding: Digest,
    pub management: Digest,
    pub verifier: ApprovalKeyRef,
    pub security_epoch: u64,
    pub revision: u64,
    pub enabled: bool,
    pub observed_at: i64,
    pub ready_until: i64,
    pub read_at: i64,
}

#[derive(Default)]
struct VerificationHistory {
    // Process-local refusal memory only; no restart/restore witness is claimed.
    domains: BTreeMap<Digest, (u64, i64)>,
    targets: BTreeMap<Digest, VerificationObservation>,
}

fn epoch_domain(binding: &CredentialFamilyBinding) -> Result<Digest> {
    Digest::of(&(
        "day2-credential-selection-epoch-domain-v1",
        &binding.namespace,
        &binding.epoch_store,
    ))
}

impl SelectedAuthority {
    pub(crate) fn new(
        entries: Vec<Selection>,
        keys: Arc<dyn ApprovalKeyProvider>,
        verification: Arc<dyn VerificationSource>,
    ) -> Result<Self> {
        let result = Self {
            entries: Arc::new(RwLock::new(Selections {
                current: Vec::new(),
                revision: 0,
                epoch_floor: BTreeMap::new(),
            })),
            keys,
            verification,
            history: Mutex::new(VerificationHistory::default()),
        };
        result.replace(entries)?;
        Ok(result)
    }

    /// Disposable existing selection fixtures explicitly share a simulated
    /// local source. New adapter conformance uses an independent source/model.
    #[cfg(test)]
    pub(crate) fn fixture(
        entries: Vec<Selection>,
        keys: Arc<dyn ApprovalKeyProvider>,
    ) -> Result<Self> {
        struct Source(Arc<RwLock<Selections>>);
        impl VerificationSource for Source {
            fn current(
                &self,
                binding: &CredentialFamilyBinding,
                management: &ManagementPolicy,
                minimum_time: i64,
            ) -> Result<VerificationObservation> {
                let entries = self.0.read().unwrap();
                let selected = SelectedAuthority::verification_selection(
                    &entries.current,
                    binding,
                    management,
                    minimum_time,
                )?;
                Ok(VerificationObservation {
                    namespace: selected.binding.namespace.clone(),
                    family: selected.binding.family.clone(),
                    epoch_store: selected.binding.epoch_store.clone(),
                    binding: Digest::of(&selected.binding)?,
                    management: Digest::of(&selected.management)?,
                    verifier: selected.verifier.clone(),
                    security_epoch: selected.security_epoch,
                    revision: entries.revision,
                    enabled: true,
                    observed_at: selected.observed_at,
                    ready_until: selected.ready_until,
                    read_at: minimum_time,
                })
            }
        }
        struct Unavailable;
        impl VerificationSource for Unavailable {
            fn current(
                &self,
                _: &CredentialFamilyBinding,
                _: &ManagementPolicy,
                _: i64,
            ) -> Result<VerificationObservation> {
                anyhow::bail!("fixture source not installed")
            }
        }
        let mut result = Self::new(entries, keys, Arc::new(Unavailable))?;
        result.verification = Arc::new(Source(result.entries.clone()));
        Ok(result)
    }

    pub(crate) fn replace(&self, entries: Vec<Selection>) -> Result<()> {
        ensure!(entries.len() <= 128, "credential admission budget");
        let mut seen = std::collections::BTreeSet::new();
        let mut epochs = BTreeMap::new();
        for entry in &entries {
            entry.binding.namespace.validate()?;
            let origin = url::Url::parse(&entry.security_origin)?;
            ensure!(
                origin.scheme() == "https"
                    && origin.origin().ascii_serialization() == entry.security_origin,
                "credential readiness security origin mismatch"
            );
            ensure!(
                seen.insert((
                    entry.binding.namespace.clone(),
                    entry.binding.family.clone()
                )),
                "duplicate credential admission"
            );
            ensure!(
                entry.verifier.binding == entry.binding.verifier
                    && entry.encryption.binding == entry.binding.custody
                    && entry.verifier.binding != entry.encryption.binding,
                "credential key purpose binding mismatch"
            );
            ensure!(
                entry.security_epoch > 0
                    && entry.observed_at >= 0
                    && entry.ready_until > entry.observed_at
                    && entry.ready_until - entry.observed_at <= 300
                    && entry.grant_until >= entry.ready_until
                    && (1..=10_000).contains(&entry.max_active_lineages)
                    && entry.issuers.len() <= 10_000
                    && matches!(entry.management.issue, ManagementPredicate::Creator)
                    && matches!(
                        entry.binding.delivery,
                        day2_capabilities::credentials::DeliveryProfile::AuthenticatedCreatorReveal
                    ),
                "unsupported or unbounded credential readiness"
            );
            for (actor, subject) in &entry.issuers {
                crate::authority::valid_actor(actor)?;
                ensure!(
                    !subject.is_empty() && subject.len() <= 256,
                    "invalid credential subject"
                );
            }
            if let Some(epoch) = epochs.insert(epoch_domain(&entry.binding)?, entry.security_epoch)
            {
                ensure!(
                    epoch == entry.security_epoch,
                    "credential epoch cohort mismatch"
                );
            }
        }
        let mut selected = self
            .entries
            .write()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        // Validate the whole replacement under the same lock as readers and
        // competing updates. A rejected batch neither advances a floor nor
        // publishes a partially changed selection. No floor is ever evicted.
        ensure!(
            selected.epoch_floor.len()
                + epochs
                    .keys()
                    .filter(|domain| !selected.epoch_floor.contains_key(*domain))
                    .count()
                <= 128,
            "credential epoch history budget"
        );
        for (domain, epoch) in &epochs {
            ensure!(
                selected
                    .epoch_floor
                    .get(domain)
                    .is_none_or(|previous| epoch >= previous),
                "credential security epoch rewound"
            );
        }
        let revision = selected
            .revision
            .checked_add(1)
            .context("credential selection revision exhausted")?;
        selected.epoch_floor.extend(epochs);
        selected.current = entries;
        selected.revision = revision;
        Ok(())
    }

    fn selected<'a>(
        entries: &'a [Selection],
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        now: i64,
    ) -> Result<&'a Selection> {
        let entry = Self::verification_selection(entries, binding, management, now)?;
        ensure!(
            entry.issuers.get(actor).map(String::as_str) == Some(subject),
            "credential subject unavailable or changed"
        );
        Ok(entry)
    }

    fn verification_selection<'a>(
        entries: &'a [Selection],
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        now: i64,
    ) -> Result<&'a Selection> {
        let entry = entries
            .iter()
            .find(|entry| {
                entry.binding.namespace == binding.namespace
                    && entry.binding.family == binding.family
            })
            .context("credential family readiness unavailable")?;
        ensure!(
            &entry.binding == binding
                && &entry.management == management
                && entry.observed_at <= now
                && now < entry.ready_until,
            "credential authority unavailable or changed"
        );
        Ok(entry)
    }

    fn key(
        &self,
        reference: &ApprovalKeyRef,
        purpose: ApprovalKeyPurpose,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let mut material = self.keys.load(reference, purpose)?;
        let bytes = Zeroizing::new(std::mem::take(&mut material.bytes));
        ensure!(
            material.binding == reference.binding
                && material.version == reference.version
                && material.purpose == purpose,
            "credential key lease identity mismatch"
        );
        Ok(bytes)
    }

    fn lease(&self, selected: &Selection) -> Result<KeyLease> {
        let verifier = self.key(&selected.verifier, ApprovalKeyPurpose::CustodyVerifier)?;
        let encryption = self.key(&selected.encryption, ApprovalKeyPurpose::CustodyEncryption)?;
        KeyLease::new(
            &*verifier,
            &encryption,
            selected.verifier.version.clone(),
            selected.encryption.version.clone(),
        )
    }

    fn verification_snapshot(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        now: i64,
    ) -> Result<(Selection, u64)> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        Ok((
            Self::verification_selection(&entries.current, binding, management, now)?.clone(),
            entries.revision,
        ))
    }

    fn observe_verification(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        minimum_time: i64,
    ) -> Result<VerificationObservation> {
        let observed = self
            .verification
            .current(binding, management, minimum_time)?;
        // Wrong-world observations must neither load a key nor poison the
        // rightful world's refusal memory. Validate actual origin first.
        ensure!(
            observed.namespace == binding.namespace
                && observed.family == binding.family
                && observed.epoch_store == binding.epoch_store
                && observed.binding == Digest::of(binding)?
                && observed.management == Digest::of(management)?
                && observed.verifier.binding == binding.verifier,
            "credential verifier source scope mismatch"
        );
        ensure!(
            !observed.verifier.version.is_empty() && observed.verifier.version.len() <= 160,
            "credential verifier version budget"
        );
        ensure!(
            observed.security_epoch > 0
                && observed.revision > 0
                && observed.observed_at >= 0
                && observed.observed_at <= observed.read_at
                && observed
                    .ready_until
                    .checked_sub(observed.observed_at)
                    .is_some_and(|span| (1..=300).contains(&span)),
            "credential verifier source clock unavailable or expired"
        );
        let domain = epoch_domain(binding)?;
        let target = Digest::of(&(&binding.namespace, &binding.family, &binding.epoch_store))?;
        let mut history = self
            .history
            .lock()
            .map_err(|_| anyhow::anyhow!("credential verification history poisoned"))?;
        ensure!(
            (history.domains.contains_key(&domain) || history.domains.len() < 128)
                && (history.targets.contains_key(&target) || history.targets.len() < 128),
            "credential verification history budget"
        );
        if let Some((epoch, read_at)) = history.domains.get(&domain) {
            ensure!(
                observed.security_epoch >= *epoch && observed.read_at >= *read_at,
                "credential verifier source rewound"
            );
        }
        if let Some(previous) = history.targets.get(&target) {
            ensure!(
                observed.revision >= previous.revision,
                "credential verifier source revision rewound"
            );
            if observed.revision == previous.revision {
                let mut stable = observed.clone();
                stable.read_at = previous.read_at;
                ensure!(
                    stable == *previous,
                    "credential verifier source changed without revision"
                );
            }
        }
        // Record genuine newer evidence even when the local selection is stale
        // or the source says disabled, so a subsequent rollback cannot regrant.
        history
            .domains
            .insert(domain, (observed.security_epoch, observed.read_at));
        history.targets.insert(target, observed.clone());
        // Even expired authenticated evidence must not make a newer epoch
        // forgettable. Freshness authorizes nothing until after floor recording.
        ensure!(
            observed.read_at >= minimum_time && observed.read_at < observed.ready_until,
            "credential verifier source clock unavailable or expired"
        );
        Ok(observed)
    }

    fn check_verification(
        &self,
        selected: &Selection,
        revision: u64,
        observed: &VerificationObservation,
    ) -> Result<()> {
        let (_, current_revision) =
            self.verification_snapshot(&selected.binding, &selected.management, observed.read_at)?;
        ensure!(
            current_revision == revision
                && observed.enabled
                && observed.security_epoch == selected.security_epoch
                && observed.verifier == selected.verifier,
            "credential verifier authority retired or changed"
        );
        Ok(())
    }
}

impl Authority for SelectedAuthority {
    fn verification_epoch(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        verifier_version: &str,
        now: i64,
    ) -> Result<Option<u64>> {
        let (selected, revision) = self.verification_snapshot(binding, management, now)?;
        let observed = self.observe_verification(binding, management, now)?;
        self.check_verification(&selected, revision, &observed)?;
        Ok((selected.verifier.version == verifier_version).then_some(selected.security_epoch))
    }

    fn verification_keys(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        now: i64,
    ) -> Result<VerifierLease> {
        let (selected, revision) = self.verification_snapshot(binding, management, now)?;
        let before = self.observe_verification(binding, management, now)?;
        self.check_verification(&selected, revision, &before)?;
        let started = super::effects::Instant::now();
        // Neither selection nor history locks span provider work. Reentrant
        // admission replacement is allowed and must invalidate this acquisition.
        let requested = self.key(&selected.verifier, ApprovalKeyPurpose::CustodyVerifier);
        let checked: Result<()> = (|| {
            let elapsed = i64::try_from(
                started
                    .checked_elapsed()
                    .context("credential key clock rewound")?
                    .as_secs(),
            )?;
            let minimum = before
                .read_at
                .checked_add(elapsed)
                .context("credential key clock overflow")?;
            let mut after = self.observe_verification(binding, management, minimum)?;
            self.check_verification(&selected, revision, &after)?;
            after.read_at = before.read_at;
            ensure!(
                after == before,
                "credential verifier source changed during key acquisition"
            );
            Ok(())
        })();
        // Both Results are evaluated. A provider error remains primary if the
        // mandatory postcheck also refuses; no lease escapes on either error.
        let bytes = requested?;
        checked?;
        VerifierLease::new(&*bytes, selected.verifier.version.clone())
    }

    fn personal_actor(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        subject: &str,
        now: i64,
    ) -> Result<String> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        let selected = Self::verification_selection(&entries.current, binding, management, now)?;
        let actors = selected
            .issuers
            .iter()
            .filter(|(_, current)| current.as_str() == subject)
            .map(|(actor, _)| actor);
        let mut actors = actors;
        let actor = actors
            .next()
            .context("credential subject mapping missing")?;
        ensure!(
            actors.next().is_none(),
            "ambiguous credential subject mapping"
        );
        Ok(actor.clone())
    }

    fn check_shell(&self, binding: &CredentialFamilyBinding, origin: &str) -> Result<()> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        ensure!(
            entries
                .current
                .iter()
                .any(|entry| &entry.binding == binding && entry.security_origin == origin),
            "credential shell not selected for family"
        );
        Ok(())
    }
    fn prepare(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        now: i64,
    ) -> Result<ReadyKeys> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        let selected = Self::selected(&entries.current, binding, management, actor, subject, now)?;
        Ok(ReadyKeys {
            keys: self.lease(selected)?,
            binding: Digest::of(binding)?,
            security_epoch: selected.security_epoch,
            valid_until: selected.grant_until,
            max_active_lineages: selected.max_active_lineages,
        })
    }

    fn validate(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        ready: &ReadyKeys,
        now: i64,
    ) -> Result<()> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        let selected = Self::selected(&entries.current, binding, management, actor, subject, now)?;
        ensure!(
            ready.binding == Digest::of(binding)?
                && ready.security_epoch == selected.security_epoch
                && ready.keys.verifier_version == selected.verifier.version
                && ready.keys.encryption_version == selected.encryption.version
                && ready.valid_until <= selected.grant_until
                && now < ready.valid_until
                && ready.max_active_lineages <= selected.max_active_lineages,
            "credential readiness changed"
        );
        Ok(())
    }

    fn reveal_epoch(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        now: i64,
    ) -> Result<u64> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        Ok(
            Self::selected(&entries.current, binding, management, actor, subject, now)?
                .security_epoch,
        )
    }

    fn human_keys(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        permit: &HumanRevealPermit,
        now: i64,
    ) -> Result<KeyLease> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        let selected = Self::selected(&entries.current, binding, management, actor, subject, now)?;
        ensure!(
            permit.encryption_version() == selected.encryption.version
                && permit.security_epoch() == selected.security_epoch,
            "credential delivery key or epoch retired"
        );
        self.lease(selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::approval_registry::ApprovalKeyMaterial;
    use day2_capabilities::{
        Name,
        credentials::{DeliveryProfile, RotationProfile},
        oauth::{ResourceAudienceRef, SecurityOriginRef},
    };
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    fn name(value: &str) -> Name {
        Name::try_from(value.to_owned()).unwrap()
    }

    fn selection() -> Selection {
        let pin = |value: &str| BindingRef::pin(name(value), &value).unwrap();
        let binding = CredentialFamilyBinding {
            namespace: Namespace {
                installation: name("fixture"),
                environment: name("test"),
                app: name("credentials"),
                binding_generation: 2,
            },
            family: name("client"),
            approved_authority: pin("authority"),
            management: pin("management"),
            rotation: RotationProfile::AtomicReplace,
            delivery: DeliveryProfile::AuthenticatedCreatorReveal,
            verifier: pin("verifier"),
            custody: pin("custody"),
            security_shell: SecurityOriginRef(pin("shell")),
            audience: ResourceAudienceRef(pin("audience")),
            epoch_store: pin("epoch"),
            max_lifetime_seconds: 2000,
            reveal_window_seconds: 300,
            quota: pin("quota"),
        };
        Selection {
            verifier: ApprovalKeyRef {
                binding: binding.verifier.clone(),
                version: "verify-v1".into(),
            },
            encryption: ApprovalKeyRef {
                binding: binding.custody.clone(),
                version: "encrypt-v1".into(),
            },
            binding,
            security_origin: "https://security.example.com".into(),
            management: ManagementPolicy {
                identity_authority: pin("people"),
                issue: ManagementPredicate::Creator,
                read_metadata: ManagementPredicate::Creator,
                rotate: ManagementPredicate::Creator,
                revoke: ManagementPredicate::Creator,
            },
            security_epoch: 7,
            observed_at: 1000,
            ready_until: 1200,
            grant_until: 3000,
            max_active_lineages: 10,
            issuers: BTreeMap::new(),
        }
    }

    struct Clock(Mutex<(u64, i64, Duration)>);
    impl super::super::effects::Hooks for Clock {
        fn domain(&self) -> u64 {
            self.0.lock().unwrap().0
        }
        fn wall_time(&self) -> Result<i64> {
            Ok(self.0.lock().unwrap().1)
        }
        fn monotonic(&self) -> Duration {
            self.0.lock().unwrap().2
        }
        fn fill_id(&self, _: &mut [u8]) -> Result<()> {
            anyhow::bail!("adapter has no identifier effect")
        }
        fn fill_secret(&self, _: &mut [u8]) -> Result<()> {
            anyhow::bail!("adapter has no secret entropy effect")
        }
    }

    struct Source {
        observation: Mutex<VerificationObservation>,
        clock: Arc<Clock>,
        reads: AtomicUsize,
        unavailable: Mutex<bool>,
    }
    impl VerificationSource for Source {
        fn current(
            &self,
            _: &CredentialFamilyBinding,
            _: &ManagementPolicy,
            _: i64,
        ) -> Result<VerificationObservation> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            ensure!(
                !*self.unavailable.lock().unwrap(),
                "fixture current source unavailable"
            );
            let mut result = self.observation.lock().unwrap().clone();
            result.read_at = self.clock.0.lock().unwrap().1;
            Ok(result)
        }
    }

    #[derive(Debug)]
    struct ProviderFailed;
    impl std::fmt::Display for ProviderFailed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fixture provider refused")
        }
    }
    impl std::error::Error for ProviderFailed {}

    type ProviderCut = Box<dyn FnOnce() + Send>;
    struct Keys {
        actual: Mutex<ApprovalKeyRef>,
        mode: Mutex<u8>,
        calls: Mutex<Vec<(ApprovalKeyRef, ApprovalKeyPurpose)>>,
        cut: Mutex<Option<ProviderCut>>,
    }
    impl ApprovalKeyProvider for Keys {
        fn load(
            &self,
            reference: &ApprovalKeyRef,
            purpose: ApprovalKeyPurpose,
        ) -> Result<ApprovalKeyMaterial> {
            self.calls
                .lock()
                .unwrap()
                .push((reference.clone(), purpose));
            let cut = self.cut.lock().unwrap().take();
            if let Some(cut) = cut {
                cut();
            }
            let mode = *self.mode.lock().unwrap();
            if mode == 1 {
                return Err(ProviderFailed.into());
            }
            let mut actual = self.actual.lock().unwrap().clone();
            if mode == 2 {
                actual.version = "wrong-version".into();
            }
            if mode == 3 {
                actual.binding = selection().binding.custody;
            }
            Ok(ApprovalKeyMaterial {
                binding: actual.binding,
                version: actual.version,
                purpose: if mode == 4 {
                    ApprovalKeyPurpose::CustodyEncryption
                } else {
                    ApprovalKeyPurpose::CustodyVerifier
                },
                bytes: [3; 32],
            })
        }
    }

    struct Fixture {
        selected: Selection,
        authority: Arc<SelectedAuthority>,
        source: Arc<Source>,
        keys: Arc<Keys>,
        clock: Arc<Clock>,
    }
    impl Fixture {
        fn new() -> Result<Self> {
            let selected = selection();
            let clock = Arc::new(Clock(Mutex::new((1, 1100, Duration::from_secs(10)))));
            let source = Arc::new(Source {
                observation: Mutex::new(VerificationObservation {
                    namespace: selected.binding.namespace.clone(),
                    family: selected.binding.family.clone(),
                    epoch_store: selected.binding.epoch_store.clone(),
                    binding: Digest::of(&selected.binding)?,
                    management: Digest::of(&selected.management)?,
                    verifier: selected.verifier.clone(),
                    security_epoch: 7,
                    revision: 1,
                    enabled: true,
                    observed_at: 1000,
                    ready_until: 1200,
                    read_at: 1100,
                }),
                clock: clock.clone(),
                reads: AtomicUsize::new(0),
                unavailable: Mutex::new(false),
            });
            let keys = Arc::new(Keys {
                actual: Mutex::new(selected.verifier.clone()),
                mode: Mutex::new(0),
                calls: Mutex::new(Vec::new()),
                cut: Mutex::new(None),
            });
            let authority = Arc::new(SelectedAuthority::new(
                vec![selected.clone()],
                keys.clone(),
                source.clone(),
            )?);
            Ok(Self {
                selected,
                authority,
                source,
                keys,
                clock,
            })
        }

        fn acquire(&self) -> Result<VerifierLease> {
            super::super::effects::scope(self.clock.clone(), || {
                self.authority.verification_keys(
                    &self.selected.binding,
                    &self.selected.management,
                    1100,
                )
            })
        }

        fn epoch(&self) -> Result<Option<u64>> {
            self.authority.verification_epoch(
                &self.selected.binding,
                &self.selected.management,
                "verify-v1",
                1100,
            )
        }
    }

    #[test]
    fn exact_verifier_and_local_epoch_never_borrow_encryption_or_load_in_sql() -> Result<()> {
        let f = Fixture::new()?;
        assert_eq!(f.acquire()?.verifier_version, "verify-v1");
        let mut db = rusqlite::Connection::open_in_memory()?;
        let tx = db.transaction()?;
        assert_eq!(f.epoch()?, Some(7));
        tx.commit()?;
        let calls = f.keys.calls.lock().unwrap();
        assert_eq!(
            calls.as_slice(),
            &[(
                f.selected.verifier.clone(),
                ApprovalKeyPurpose::CustodyVerifier
            )]
        );
        assert_eq!(f.source.reads.load(Ordering::SeqCst), 3);
        Ok(())
    }

    #[test]
    fn actual_scope_mismatches_refuse_before_key_io_without_poisoning_rightful_source() -> Result<()>
    {
        for mismatch in 0..11 {
            let f = Fixture::new()?;
            let original = f.source.observation.lock().unwrap().clone();
            {
                let mut v = f.source.observation.lock().unwrap();
                match mismatch {
                    0 => v.namespace.installation = name("other"),
                    1 => v.namespace.environment = name("other"),
                    2 => v.namespace.app = name("other"),
                    3 => v.namespace.binding_generation += 1,
                    4 => v.family = name("other"),
                    5 => v.epoch_store = f.selected.binding.custody.clone(),
                    6 => v.binding = Digest::of(&"wrong-binding")?,
                    7 => v.management = Digest::of(&"wrong-management")?,
                    8 => v.verifier.binding = f.selected.binding.custody.clone(),
                    9 => v.verifier.version = "retired-version".into(),
                    10 => v.enabled = false,
                    _ => unreachable!(),
                }
            }
            assert!(f.acquire().is_err(), "mismatch {mismatch}");
            assert!(f.keys.calls.lock().unwrap().is_empty());
            *f.source.observation.lock().unwrap() = original;
            // Wrong origin never entered history; genuine retirement/key
            // evidence needs a newer source revision to restore service.
            if mismatch >= 9 {
                f.source.observation.lock().unwrap().revision += 1;
            }
            assert!(f.acquire().is_ok(), "restore {mismatch}");
        }
        Ok(())
    }

    #[test]
    fn actual_provider_binding_version_and_purpose_are_independently_checked() -> Result<()> {
        for mode in 1..=4 {
            let f = Fixture::new()?;
            *f.keys.mode.lock().unwrap() = mode;
            assert!(f.acquire().is_err(), "provider mode {mode}");
            assert_eq!(f.source.reads.load(Ordering::SeqCst), 2);
        }
        Ok(())
    }

    #[test]
    fn key_io_cut_rechecks_source_selection_time_and_source_availability() -> Result<()> {
        for cut in 0..10 {
            let f = Fixture::new()?;
            let source = f.source.clone();
            let clock = f.clock.clone();
            let authority = f.authority.clone();
            let original = f.selected.clone();
            *f.keys.cut.lock().unwrap() = Some(Box::new(move || match cut {
                0 => {
                    let mut v = source.observation.lock().unwrap();
                    v.enabled = false;
                    v.revision += 1;
                }
                1 => {
                    let mut v = source.observation.lock().unwrap();
                    v.security_epoch += 1;
                    v.revision += 1;
                }
                2 => {
                    let mut v = source.observation.lock().unwrap();
                    v.verifier.version = "verify-v2".into();
                    v.revision += 1;
                }
                3 => {
                    authority.replace(vec![original.clone()]).unwrap();
                }
                4 => {
                    authority.replace(Vec::new()).unwrap();
                    authority.replace(vec![original]).unwrap();
                }
                5 => {
                    clock.0.lock().unwrap().1 = 1200;
                }
                6 => {
                    clock.0.lock().unwrap().1 = 1099;
                }
                7 => {
                    clock.0.lock().unwrap().2 = Duration::ZERO;
                }
                8 => {
                    clock.0.lock().unwrap().0 = 2;
                }
                9 => {
                    *source.unavailable.lock().unwrap() = true;
                }
                _ => unreachable!(),
            }));
            assert!(f.acquire().is_err(), "key cut {cut}");
            assert_eq!(f.keys.calls.lock().unwrap().len(), 1);
            // No lock is held across provider callback: reentrant replace
            // above completes rather than deadlocking or silently succeeding.
        }
        Ok(())
    }

    #[test]
    fn elapsed_provider_work_cannot_reuse_a_frozen_wall_sample_or_extend_readiness() -> Result<()> {
        for wall in [1100, 1101, 1200] {
            let f = Fixture::new()?;
            let clock = f.clock.clone();
            *f.keys.cut.lock().unwrap() = Some(Box::new(move || {
                let mut c = clock.0.lock().unwrap();
                c.1 = wall;
                c.2 += Duration::from_secs(1);
            }));
            assert_eq!(f.acquire().is_ok(), wall == 1101);
        }
        Ok(())
    }

    #[test]
    fn provider_error_remains_primary_but_postcheck_always_observes_retirement() -> Result<()> {
        let f = Fixture::new()?;
        *f.keys.mode.lock().unwrap() = 1;
        let source = f.source.clone();
        *f.keys.cut.lock().unwrap() = Some(Box::new(move || {
            let mut v = source.observation.lock().unwrap();
            v.revision += 1;
            v.enabled = false;
        }));
        let error = f.acquire().err().context("provider must refuse")?;
        assert!(error.downcast_ref::<ProviderFailed>().is_some());
        assert_eq!(f.source.reads.load(Ordering::SeqCst), 2);
        *f.keys.mode.lock().unwrap() = 0;
        let mut v = f.source.observation.lock().unwrap();
        v.revision = 1;
        v.enabled = true;
        drop(v);
        assert!(f.acquire().is_err());
        assert_eq!(f.keys.calls.lock().unwrap().len(), 1);
        Ok(())
    }

    #[test]
    fn stale_local_selection_still_records_new_source_epoch_before_refusing_rollback() -> Result<()>
    {
        let f = Fixture::new()?;
        {
            let mut v = f.source.observation.lock().unwrap();
            v.security_epoch = 8;
            v.revision = 2;
        }
        assert!(f.epoch().is_err());
        {
            let mut v = f.source.observation.lock().unwrap();
            v.security_epoch = 7;
            v.revision = 3;
        }
        assert!(f.epoch().is_err());
        {
            let mut v = f.source.observation.lock().unwrap();
            v.security_epoch = 8;
            v.revision = 4;
        }
        let mut selected = f.selected.clone();
        selected.security_epoch = 8;
        f.authority.replace(vec![selected])?;
        assert_eq!(f.epoch()?, Some(8));
        f.authority.replace(Vec::new())?;
        {
            let mut v = f.source.observation.lock().unwrap();
            v.security_epoch = 7;
            v.revision = 5;
        }
        assert!(f.authority.replace(vec![f.selected.clone()]).is_err());
        Ok(())
    }

    #[test]
    fn source_same_revision_mutation_and_local_revision_exhaustion_refuse_atomically() -> Result<()>
    {
        let f = Fixture::new()?;
        assert!(f.acquire().is_ok());
        f.source.observation.lock().unwrap().ready_until = 1199;
        assert!(f.acquire().is_err());
        let mut entries = f.authority.entries.write().unwrap();
        entries.revision = u64::MAX;
        drop(entries);
        assert!(f.authority.replace(Vec::new()).is_err());
        assert_eq!(f.authority.entries.read().unwrap().current.len(), 1);
        Ok(())
    }
    // The reference consumes only closed events and scalar world state; it
    // never calls selection/source validation or reads implementation floors.
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    #[serde(tag = "event", deny_unknown_fields)]
    enum Event {
        Source {
            epoch: u64,
            revision: u64,
            enabled: bool,
            key: u8,
            wrong_world: bool,
        },
        Select {
            epoch: u64,
            key: u8,
        },
        Time {
            wall: i64,
        },
        Acquire,
    }

    #[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Outcome {
        accepted: bool,
        key_loads: usize,
        source_reads: usize,
    }

    struct Model {
        source: (u64, u64, bool, u8, bool),
        selected: (u64, u8),
        local_floor: u64,
        local_revision: u64,
        wall: i64,
        epoch_floor: u64,
        time_floor: i64,
        previous: Option<(u64, u64, bool, u8)>,
    }
    impl Model {
        fn new() -> Self {
            Self {
                source: (7, 1, true, 1, false),
                selected: (7, 1),
                local_floor: 7,
                local_revision: 1,
                wall: 1100,
                epoch_floor: 0,
                time_floor: 0,
                previous: None,
            }
        }

        fn event(&mut self, event: &Event) -> Option<Outcome> {
            match *event {
                Event::Source {
                    epoch,
                    revision,
                    enabled,
                    key,
                    wrong_world,
                } => self.source = (epoch, revision, enabled, key, wrong_world),
                Event::Select { epoch, key } => {
                    if epoch >= self.local_floor {
                        self.local_floor = epoch;
                        self.local_revision += 1;
                        self.selected = (epoch, key);
                    }
                }
                Event::Time { wall } => self.wall = wall,
                Event::Acquire => {
                    let (epoch, revision, enabled, key, wrong_world) = self.source;
                    let frozen = (epoch, revision, enabled, key);
                    let current = !wrong_world
                        && epoch >= self.epoch_floor
                        && self.wall >= self.time_floor
                        && self
                            .previous
                            .is_none_or(|p| revision > p.1 || (revision == p.1 && frozen == p));
                    if current {
                        self.epoch_floor = epoch;
                        self.time_floor = self.wall;
                        self.previous = Some(frozen);
                    }
                    let accepted = current
                        && enabled
                        && (epoch, key) == self.selected
                        && (1100..1200).contains(&self.wall);
                    return Some(Outcome {
                        accepted,
                        key_loads: usize::from(accepted),
                        source_reads: if accepted { 2 } else { 1 },
                    });
                }
            }
            None
        }
    }

    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Replay {
        version: u8,
        implementation: Digest,
        events: Vec<Event>,
        false_oracle: [bool; 2],
        runs: [RecordedRun; 2],
    }

    #[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RecordedRun {
        outcomes: Vec<Outcome>,
        states: Vec<State>,
        agrees: bool,
    }

    #[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct State {
        selections: Vec<Digest>,
        revision: u64,
        local_floors: BTreeMap<Digest, u64>,
        domains: BTreeMap<Digest, (u64, i64)>,
        targets: BTreeMap<Digest, Digest>,
    }

    // Hash every immutable/scoped DATA field instead of exporting references.
    // Only this lossless commitment encoding is shared with the reference.
    fn selected_digest(v: &Selection) -> Result<Digest> {
        Digest::of(&(
            &v.binding,
            &v.security_origin,
            &v.management,
            (&v.verifier.binding, &v.verifier.version),
            (&v.encryption.binding, &v.encryption.version),
            v.security_epoch,
            v.observed_at,
            v.ready_until,
            v.grant_until,
            v.max_active_lineages,
            &v.issuers,
        ))
    }

    fn observed_digest(v: &VerificationObservation) -> Result<Digest> {
        Digest::of(&(
            &v.namespace,
            &v.family,
            &v.epoch_store,
            &v.binding,
            &v.management,
            (&v.verifier.binding, &v.verifier.version),
            v.security_epoch,
            v.revision,
            v.enabled,
            v.observed_at,
            v.ready_until,
            v.read_at,
        ))
    }

    fn state(authority: &SelectedAuthority) -> Result<State> {
        let entries = authority.entries.read().unwrap();
        let history = authority.history.lock().unwrap();
        Ok(State {
            selections: entries
                .current
                .iter()
                .map(selected_digest)
                .collect::<Result<_>>()?,
            revision: entries.revision,
            local_floors: entries.epoch_floor.clone(),
            domains: history.domains.clone(),
            targets: history
                .targets
                .iter()
                .map(|(key, value)| Ok((key.clone(), observed_digest(value)?)))
                .collect::<Result<_>>()?,
        })
    }

    impl Model {
        fn state(&self) -> Result<State> {
            // Fixed immutable fixture input, not a snapshot of the actual world.
            let mut selected = selection();
            selected.security_epoch = self.selected.0;
            selected.verifier.version = format!("verify-v{}", self.selected.1);
            let b = &selected.binding;
            let domain = Digest::of(&(
                "day2-credential-selection-epoch-domain-v1",
                &b.namespace,
                &b.epoch_store,
            ))?;
            let target = Digest::of(&(&b.namespace, &b.family, &b.epoch_store))?;
            let mut targets = BTreeMap::new();
            let mut domains = BTreeMap::new();
            if let Some((epoch, revision, enabled, key)) = self.previous {
                let view = VerificationObservation {
                    namespace: b.namespace.clone(),
                    family: b.family.clone(),
                    epoch_store: b.epoch_store.clone(),
                    binding: Digest::of(b)?,
                    management: Digest::of(&selected.management)?,
                    verifier: ApprovalKeyRef {
                        binding: b.verifier.clone(),
                        version: format!("verify-v{key}"),
                    },
                    security_epoch: epoch,
                    revision,
                    enabled,
                    observed_at: 1000,
                    ready_until: 1200,
                    read_at: self.time_floor,
                };
                targets.insert(target, observed_digest(&view)?);
                domains.insert(domain.clone(), (self.epoch_floor, self.time_floor));
            }
            Ok(State {
                selections: vec![selected_digest(&selected)?],
                revision: self.local_revision,
                local_floors: BTreeMap::from([(domain, self.local_floor)]),
                domains,
                targets,
            })
        }
    }

    fn implementation() -> Result<Digest> {
        Digest::of(&(
            "credential-verifier-adapter-model-v1",
            include_str!("authority.rs"),
            include_str!("effects.rs"),
            include_str!("crypto.rs"),
        ))
    }

    fn history(events: &[Event], false_oracle: bool) -> Result<RecordedRun> {
        ensure!(
            !events.is_empty() && events.len() <= 64,
            "adapter history budget"
        );
        let f = Fixture::new()?;
        let mut model = Model::new();
        let mut outcomes = Vec::new();
        let mut states = Vec::new();
        let mut agrees = true;
        for event in events {
            let predicted = model.event(event);
            match *event {
                Event::Source {
                    epoch,
                    revision,
                    enabled,
                    key,
                    wrong_world,
                } => {
                    ensure!(
                        (1..=32).contains(&epoch)
                            && (1..=128).contains(&revision)
                            && (1..=2).contains(&key),
                        "adapter source fixture bounds"
                    );
                    let mut v = f.source.observation.lock().unwrap();
                    v.security_epoch = epoch;
                    v.revision = revision;
                    v.enabled = enabled;
                    v.verifier.version = format!("verify-v{key}");
                    v.namespace.environment = name(if wrong_world { "other" } else { "test" });
                }
                Event::Select { epoch, key } => {
                    ensure!(
                        (1..=32).contains(&epoch) && (1..=2).contains(&key),
                        "adapter selection fixture bounds"
                    );
                    let mut selected = f.selected.clone();
                    selected.security_epoch = epoch;
                    selected.verifier.version = format!("verify-v{key}");
                    if f.authority.replace(vec![selected.clone()]).is_ok() {
                        *f.keys.actual.lock().unwrap() = selected.verifier;
                    }
                }
                Event::Time { wall } => {
                    ensure!(
                        (1000..=1200).contains(&wall),
                        "adapter clock fixture bounds"
                    );
                    f.clock.0.lock().unwrap().1 = wall;
                }
                Event::Acquire => {
                    let keys = f.keys.calls.lock().unwrap().len();
                    let reads = f.source.reads.load(Ordering::SeqCst);
                    let outcome = Outcome {
                        accepted: f.acquire().is_ok(),
                        key_loads: f.keys.calls.lock().unwrap().len() - keys,
                        source_reads: f.source.reads.load(Ordering::SeqCst) - reads,
                    };
                    let mut expected = predicted.context("model acquire outcome")?;
                    if false_oracle {
                        expected.accepted = !expected.accepted;
                    }
                    agrees &= outcome == expected;
                    outcomes.push(outcome);
                }
            }
            let observed = state(&f.authority)?;
            agrees &= observed == model.state()?;
            states.push(observed);
        }
        ensure!(!outcomes.is_empty(), "adapter history requires acquisition");
        Ok(RecordedRun {
            outcomes,
            states,
            agrees,
        })
    }

    fn save_replay(
        events: &[Event],
        false_oracle: [bool; 2],
        runs: [RecordedRun; 2],
    ) -> Result<std::path::PathBuf> {
        use std::io::Write;
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../artifacts/credential-verifier-adapter");
        std::fs::create_dir_all(&directory)?;
        let mut file = tempfile::Builder::new()
            .prefix("failure-")
            .suffix(".json")
            .tempfile_in(directory)?;
        let replay = Replay {
            version: 1,
            implementation: implementation()?,
            events: events.to_vec(),
            false_oracle,
            runs,
        };
        file.write_all(&serde_json::to_vec_pretty(&replay)?)?;
        file.as_file().sync_all()?;
        Ok(file.keep()?.1)
    }

    fn replay_file(path: &std::path::Path) -> Result<bool> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 128 * 1024, "adapter replay byte budget");
        let replay: Replay = crate::json::decode(&bytes)?;
        ensure!(
            replay.version == 1 && replay.implementation == implementation()?,
            "adapter replay source mismatch"
        );
        let first = history(&replay.events, replay.false_oracle[0])?;
        let second = history(&replay.events, replay.false_oracle[1])?;
        ensure!(
            (!replay.runs[0].agrees || !replay.runs[1].agrees || replay.runs[0] != replay.runs[1])
                && [first.clone(), second.clone()] == replay.runs,
            "adapter counterexample must reproduce disagreement"
        );
        Ok(first.agrees && second.agrees && first == second)
    }

    #[test]
    fn seeded_exact_adapter_histories_match_independent_epoch_key_and_retirement_model()
    -> Result<()> {
        for seed in 0u64..32 {
            let mut rng = seed + 1;
            let mut events = vec![Event::Acquire];
            // Directed current->retired->rollback->new-current prefixes plus
            // seeded revisions, key/epoch replacements, wrong worlds and clocks.
            for step in 0..20 {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                let epoch = 7 + (rng >> 32) % 3;
                let key = 1 + ((rng >> 40) % 2) as u8;
                let revision = 1 + ((rng >> 44) % 12);
                events.push(match step % 4 {
                    0 => Event::Source {
                        epoch,
                        revision,
                        enabled: rng & 1 == 0,
                        key,
                        wrong_world: rng & 4 != 0,
                    },
                    1 => Event::Select { epoch, key },
                    2 => Event::Time {
                        wall: [1099, 1100, 1101, 1199, 1200][(rng as usize) % 5],
                    },
                    _ => Event::Source {
                        epoch,
                        revision: revision + 1,
                        enabled: true,
                        key,
                        wrong_world: false,
                    },
                });
                events.push(Event::Acquire);
            }
            let first = history(&events, false)?;
            let second = history(&events, false)?;
            if !first.agrees || !second.agrees || first != second {
                let path = save_replay(&events, [false, false], [first, second])?;
                anyhow::bail!(
                    "adapter model disagreement; redacted replay {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn deliberately_wrong_oracle_is_persisted_and_replayed_without_secret_material() -> Result<()> {
        let events = vec![
            Event::Acquire,
            Event::Source {
                epoch: 8,
                revision: 2,
                enabled: false,
                key: 2,
                wrong_world: false,
            },
            Event::Acquire,
        ];
        let first = history(&events, true)?;
        let second = history(&events, true)?;
        assert!(!first.agrees && !second.agrees);
        let path = save_replay(&events, [true, true], [first, second])?;
        assert!(!replay_file(&path)?);
        let bytes = std::fs::read(&path)?;
        let text = std::str::from_utf8(&bytes)?;
        for forbidden in [
            "bytes",
            "token",
            "secret",
            "fixture provider refused",
            "binding",
            "key_material",
        ] {
            assert!(!text.contains(forbidden));
        }
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        let mut invalid: serde_json::Value = serde_json::from_slice(&bytes)?;
        invalid["version"] = 2.into();
        std::fs::write(&path, serde_json::to_vec(&invalid)?)?;
        assert!(replay_file(&path).is_err());
        std::fs::write(&path, bytes)?;
        Ok(())
    }

    #[test]
    fn replay_saved_exact_adapter_history() -> Result<()> {
        let Some(path) = std::env::var_os("DAY2_CREDENTIAL_VERIFIER_ADAPTER_REPLAY") else {
            return Ok(());
        };
        assert!(!replay_file(std::path::Path::new(&path))?);
        Ok(())
    }

    #[test]
    fn expired_new_epoch_is_remembered_and_history_capacity_never_evicts_a_floor() -> Result<()> {
        let f = Fixture::new()?;
        {
            let mut v = f.source.observation.lock().unwrap();
            v.security_epoch = 8;
            v.revision = 2;
        }
        f.clock.0.lock().unwrap().1 = 1200;
        assert!(f.epoch().is_err());
        f.clock.0.lock().unwrap().1 = 1100;
        {
            let mut v = f.source.observation.lock().unwrap();
            v.security_epoch = 7;
            v.revision = 1;
        }
        assert!(f.epoch().is_err());

        let f = Fixture::new()?;
        for index in 0..129 {
            let mut binding = f.selected.binding.clone();
            binding.family = name(&format!("family-{index}"));
            let mut v = f.source.observation.lock().unwrap();
            v.family = binding.family.clone();
            v.binding = Digest::of(&binding)?;
            drop(v);
            assert_eq!(
                f.authority
                    .observe_verification(&binding, &f.selected.management, 1100)
                    .is_ok(),
                index < 128
            );
        }
        assert_eq!(f.authority.history.lock().unwrap().targets.len(), 128);
        assert_eq!(f.authority.history.lock().unwrap().domains.len(), 1);
        assert!(f.keys.calls.lock().unwrap().is_empty());
        Ok(())
    }
    #[test]
    fn second_run_only_disagreement_retains_both_actual_runs_and_replays() -> Result<()> {
        let events = vec![Event::Acquire];
        let first = history(&events, false)?;
        let second = history(&events, true)?;
        assert!(first.agrees && !second.agrees);
        let expected = [first, second];
        let path = save_replay(&events, [false, true], expected.clone())?;
        let saved: Replay = crate::json::decode(&std::fs::read(&path)?)?;
        assert_eq!(saved.runs, expected);
        assert!(!replay_file(&path)?);
        let bytes = std::fs::read(&path)?;
        // Losing either run is an invalid counterexample, rather than silently
        // replacing the failing run with the agreeing first observation.
        for slot in 0..2 {
            let mut invalid: serde_json::Value = serde_json::from_slice(&bytes)?;
            invalid["runs"][slot]["agrees"] = (!expected[slot].agrees).into();
            std::fs::write(&path, serde_json::to_vec(&invalid)?)?;
            assert!(replay_file(&path).is_err());
        }
        std::fs::write(&path, bytes)?;
        Ok(())
    }

    #[test]
    fn unavailable_or_malformed_source_cannot_reach_key_provider() -> Result<()> {
        for fault in 0..7 {
            let f = Fixture::new()?;
            let mut v = f.source.observation.lock().unwrap();
            match fault {
                0 => *f.source.unavailable.lock().unwrap() = true,
                1 => v.security_epoch = 0,
                2 => v.revision = 0,
                3 => v.ready_until = v.observed_at,
                4 => v.ready_until = v.observed_at + 301,
                5 => v.verifier.version = "x".repeat(161),
                6 => v.observed_at = -1,
                _ => unreachable!(),
            }
            drop(v);
            assert!(f.acquire().is_err());
            assert!(f.keys.calls.lock().unwrap().is_empty());
        }
        assert!(history(&[], false).is_err());
        assert!(history(&vec![Event::Acquire; 65], false).is_err());
        Ok(())
    }
}
