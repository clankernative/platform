//! Fresh principal reads borrowed from the actual SQL owner. This view neither
//! acquires Current nor stores a grant, clock, connection or positive lookup.

use super::native_management::{Consumer, PendingWriter, RuntimeConsumer};
use crate::store::Runtime;
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;

/// The private variants can only borrow an existing genuine typed owner.
/// Continuations receive that same owner, after any subject SQL unit closes.
pub(crate) struct SubjectReader<'owner, 'stage, 'role, 'original> {
    source: Source<'owner, 'stage, 'role, 'original>,
    refused: bool,
}

enum Source<'owner, 'stage, 'role, 'original> {
    Pending(&'owner Runtime, &'owner mut PendingWriter<'stage, 'role>),
    Human(
        &'owner Runtime,
        &'owner mut Consumer<'stage, 'role, 'original>,
    ),
    Runtime(&'owner Runtime, &'owner mut RuntimeConsumer<'stage, 'role>),
    // SQLite/readiness adapter conformance only. It cannot yield an owner.
    #[cfg(test)]
    Fixture(&'owner Path),
}

impl<'owner, 'stage, 'role, 'original> SubjectReader<'owner, 'stage, 'role, 'original> {
    pub(crate) fn pending(
        runtime: &'owner Runtime,
        current: &'owner mut PendingWriter<'stage, 'role>,
    ) -> Self {
        Self {
            source: Source::Pending(runtime, current),
            refused: false,
        }
    }

    pub(crate) fn human(
        runtime: &'owner Runtime,
        current: &'owner mut Consumer<'stage, 'role, 'original>,
    ) -> Self {
        Self {
            source: Source::Human(runtime, current),
            refused: false,
        }
    }

    pub(crate) fn runtime(
        runtime: &'owner Runtime,
        current: &'owner mut RuntimeConsumer<'stage, 'role>,
    ) -> Self {
        Self {
            source: Source::Runtime(runtime, current),
            refused: false,
        }
    }

    /// Every lookup opens, reads, closes and postchecks under the SAME owner.
    /// Returning an owned subject does not return a connection or permission.
    pub(super) fn subject(&mut self, database: &Path, email: &str) -> Result<Option<String>> {
        ensure!(!self.refused, "OAuth subject reader already refused");
        let selected = match &self.source {
            Source::Pending(runtime, _)
            | Source::Human(runtime, _)
            | Source::Runtime(runtime, _) => runtime.db(),
            #[cfg(test)]
            Source::Fixture(path) => path,
        };
        if selected != database {
            self.refuse();
            anyhow::bail!("OAuth subject database selection changed");
        }
        let result = match &mut self.source {
            Source::Pending(runtime, current) => {
                current.sql_read(runtime, |db| query_subject(db, email))
            }
            Source::Human(runtime, current) => {
                current.sql_read(runtime, |db| query_subject(db, email))
            }
            Source::Runtime(runtime, current) => {
                current.sql_read(runtime, |db| query_subject(db, email))
            }
            #[cfg(test)]
            Source::Fixture(path) => {
                // The ordinary opener refuses the native path BEFORE I/O.
                // This test-only branch cannot provide any actual owner.
                (|| {
                    let db = crate::store::open(path)?;
                    let result = query_subject(&db, email);
                    db.close().map_err(|(_, error)| error)?;
                    result
                })()
            }
        };
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn with_pending<T>(
        &mut self,
        operation: impl FnOnce(&mut PendingWriter<'stage, 'role>) -> Result<T>,
    ) -> Result<T> {
        ensure!(!self.refused, "OAuth subject reader already refused");
        if let Source::Pending(_, current) = &mut self.source {
            return operation(current);
        }
        self.refuse();
        anyhow::bail!("OAuth subject reader is not the Pending owner")
    }

    pub(crate) fn with_human<T>(
        &mut self,
        operation: impl FnOnce(&mut Consumer<'stage, 'role, 'original>) -> Result<T>,
    ) -> Result<T> {
        ensure!(!self.refused, "OAuth subject reader already refused");
        if let Source::Human(_, current) = &mut self.source {
            return operation(current);
        }
        self.refuse();
        anyhow::bail!("OAuth subject reader is not the human owner")
    }

    pub(crate) fn with_runtime<T>(
        &mut self,
        operation: impl FnOnce(&mut RuntimeConsumer<'stage, 'role>) -> Result<T>,
    ) -> Result<T> {
        ensure!(!self.refused, "OAuth subject reader already refused");
        if let Source::Runtime(_, current) = &mut self.source {
            return operation(current);
        }
        self.refuse();
        anyhow::bail!("OAuth subject reader is not the runtime owner")
    }

    fn refuse(&mut self) {
        self.refused = true;
        match &mut self.source {
            Source::Pending(_, current) => current.refuse(),
            Source::Human(_, current) => current.refuse(),
            Source::Runtime(_, current) => current.refuse(),
            #[cfg(test)]
            Source::Fixture(_) => {}
        }
    }

    #[cfg(test)]
    pub(in crate::oauth) fn fixture(database: &'owner Path) -> Self {
        Self {
            source: Source::Fixture(database),
            refused: false,
        }
    }
}

fn query_subject(db: &Connection, email: &str) -> Result<Option<String>> {
    Ok(db
        .query_row(
            "SELECT subject FROM day2_principals WHERE email=?1",
            [email],
            |row| row.get(0),
        )
        .optional()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{effects, native_management, simulation::World};
    use day2_capabilities::security_epoch::AuthorityScope;
    use std::{sync::Arc, time::Duration};

    /// Scripted role and clock controls, never a production native witness.
    struct Clock(Arc<World>);

    impl effects::Hooks for Clock {
        fn domain(&self) -> u64 {
            effects::Hooks::domain(self.0.as_ref())
        }

        fn wall_time(&self) -> Result<i64> {
            effects::Hooks::wall_time(self.0.as_ref())
        }

        fn monotonic(&self) -> Duration {
            effects::Hooks::monotonic(self.0.as_ref())
        }

        fn fill(&self, bytes: &mut [u8]) -> Result<()> {
            effects::Hooks::fill(self.0.as_ref(), bytes)
        }

        fn send(&self, request: reqwest::blocking::Request) -> Result<effects::Response> {
            effects::Hooks::send(self.0.as_ref(), request)
        }

        fn provider_observation(
            &self,
            data: crate::oauth::shell_oidc::ProviderObservationData,
        ) -> Result<()> {
            effects::Hooks::provider_observation(self.0.as_ref(), data)
        }

        fn simulate_runtime_owner(&self) -> bool {
            true
        }
    }

    fn fixture() -> Result<(tempfile::TempDir, Runtime, AuthorityScope)> {
        let directory = tempfile::tempdir()?;
        let (runtime, _, _) = crate::oauth::admission::tests::management_fixture(directory.path())?;
        let db = crate::store::open(runtime.db())?;
        db.pragma_update(None, "journal_mode", "DELETE")?;
        crate::iap::bind_subject(
            &db,
            &crate::iap::Verified {
                email: "alice@example.com".into(),
                subject: "accounts.google.com:alice".into(),
            },
            100,
        )?;
        db.close().map_err(|(_, error)| error)?;
        let instance = crate::artifact::Instance::load(runtime.instance_path())?;
        let scope = AuthorityScope {
            installation: instance.installation.try_into()?,
            environment: instance.environment.try_into()?,
            app: runtime.app().to_owned().try_into()?,
        };
        Ok((directory, runtime, scope))
    }

    #[test]
    fn subject_units_resample_rows_and_return_only_the_same_owner_after_close() -> Result<()> {
        let (_directory, runtime, scope) = fixture()?;
        let world = World::new(56_701);
        effects::scope(Arc::new(Clock(world)), || -> Result<()> {
            native_management::fixtures::select_app_scope(&scope)?;
            native_management::with_runtime_consumer(
                &runtime,
                native_management::RuntimePhase::Read,
                |current| {
                    let original: *const RuntimeConsumer<'_, '_> = current;
                    let mut subjects = SubjectReader::runtime(&runtime, current);
                    assert_eq!(
                        subjects.subject(runtime.db(), "alice@example.com")?,
                        Some("accounts.google.com:alice".into())
                    );
                    // DELETE journaling requires the previous read snapshot
                    // to have closed before this independent writer commits.
                    let db = crate::store::open(runtime.db())?;
                    db.execute(
                        "UPDATE day2_principals SET subject='accounts.google.com:replacement' WHERE email='alice@example.com'",
                        [],
                    )?;
                    db.close().map_err(|(_, error)| error)?;
                    assert_eq!(
                        subjects.subject(runtime.db(), "alice@example.com")?,
                        Some("accounts.google.com:replacement".into())
                    );
                    subjects.with_runtime(|same| {
                        assert!(std::ptr::eq(same, original));
                        same.check()
                    })
                },
            )
        })
    }

    #[test]
    fn subject_lookup_does_not_restart_the_clock_or_restore_a_refused_role() -> Result<()> {
        let (_directory, runtime, scope) = fixture()?;
        let world = World::new(56_702);
        effects::scope(Arc::new(Clock(world.clone())), || -> Result<()> {
            native_management::fixtures::select_app_scope(&scope)?;
            let result = native_management::with_runtime_consumer(
                &runtime,
                native_management::RuntimePhase::Read,
                |current| {
                    let mut subjects = SubjectReader::runtime(&runtime, current);
                    world.advance(4);
                    assert!(
                        subjects
                            .subject(runtime.db(), "alice@example.com")?
                            .is_some()
                    );
                    world.advance(1);
                    assert!(subjects.subject(runtime.db(), "alice@example.com").is_err());
                    assert!(subjects.with_runtime(|_| Ok(())).is_err());
                    Ok(()) // Swallowing the error cannot settle the owner.
                },
            );
            assert!(result.is_err());
            let entered = std::cell::Cell::new(false);
            assert!(
                native_management::with_runtime_consumer(
                    &runtime,
                    native_management::RuntimePhase::Read,
                    |_| {
                        entered.set(true);
                        Ok(())
                    },
                )
                .is_err()
            );
            assert!(!entered.get());
            Ok(())
        })
    }

    #[test]
    fn changed_subject_file_and_wrong_owner_variant_permanently_refuse_the_same_role() -> Result<()>
    {
        for wrong_owner in [false, true] {
            let (_directory, runtime, scope) = fixture()?;
            let world = World::new(56_703 + u64::from(wrong_owner));
            effects::scope(Arc::new(Clock(world)), || -> Result<()> {
                native_management::fixtures::select_app_scope(&scope)?;
                assert!(
                    native_management::with_runtime_consumer(
                        &runtime,
                        native_management::RuntimePhase::Read,
                        |current| {
                            let mut subjects = SubjectReader::runtime(&runtime, current);
                            if wrong_owner {
                                assert!(
                                    subjects
                                        .with_human::<()>(|_| {
                                            panic!("a runtime reader cannot yield a human original")
                                        })
                                        .is_err()
                                );
                            } else {
                                assert!(
                                    subjects
                                        .subject(
                                            Path::new("/unselected/subject.sqlite"),
                                            "alice@example.com",
                                        )
                                        .is_err()
                                );
                            }
                            assert!(subjects.subject(runtime.db(), "alice@example.com").is_err());
                            assert!(subjects.with_runtime(|_| Ok(())).is_err());
                            Ok(())
                        },
                    )
                    .is_err()
                );
                assert!(
                    native_management::with_runtime_consumer::<()>(
                        &runtime,
                        native_management::RuntimePhase::Read,
                        |_| panic!("a later reader cannot restore the refused role"),
                    )
                    .is_err()
                );
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn fixture_reader_cannot_open_native_storage_or_supply_any_owner() {
        let path = Path::new("/state/day2-native/day2-initial.sqlite");
        let mut subjects = SubjectReader::fixture(path);
        assert!(
            subjects
                .subject(path, "alice@example.com")
                .is_err_and(|error| {
                    error
                        .to_string()
                        .contains("native_runtime_sql_owner_required")
                })
        );
        assert!(
            subjects
                .with_pending::<()>(|_| panic!("fixture Pending owner"))
                .is_err()
        );
        assert!(
            subjects
                .with_human::<()>(|_| panic!("fixture human owner"))
                .is_err()
        );
        assert!(
            subjects
                .with_runtime::<()>(|_| panic!("fixture runtime owner"))
                .is_err()
        );
    }
}
