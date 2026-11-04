use std::cell::Cell;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Point {
    Captured,
    Directory,
    FirstWrite,
    Copied,
    BeforeCommit,
    AfterCommit,
    Closed,
    Synced,
}
#[derive(Clone, Copy)]
enum Action {
    Refuse,
    Panic,
}
thread_local! {static CUT:Cell<Option<(Point,Action)>>=const{Cell::new(None)};}
pub(super) fn cut(point: Point) -> Result<()> {
    if let Some((selected, action)) = CUT.with(Cell::get)
        && selected == point
    {
        match action {
            Action::Refuse => anyhow::bail!("staging_fixture_cut"),
            Action::Panic => panic!("staging_fixture_unwind"),
        }
    }
    SOURCE_SWAP.with(|swap| -> Result<()> {
        if let Some(path) = &*swap.borrow() {
            if point == Point::Captured {
                std::fs::rename(path, path.with_extension("held"))?;
                std::fs::write(path, b"not-a-sqlite-image")?;
            }
            if point == Point::BeforeCommit {
                std::fs::remove_file(path)?;
                std::fs::rename(path.with_extension("held"), path)?;
            }
        }
        Ok(())
    })?;
    CRASH.with(|c| -> Result<()> {
        if let Some((selected, marker)) = &*c.borrow()
            && *selected == point
        {
            let pending = marker.with_extension("pending");
            std::fs::write(&pending, b"staging-cut-ready")?;
            std::fs::rename(&pending, marker)?;
            // Parent retains the child's stdin and kills the same Child
            // object after reading the closed marker. This is process loss,
            // not a power-loss or hostile-kernel claim.
            let mut byte = [0u8; 1];
            std::io::stdin().read_exact(&mut byte)?;
            anyhow::bail!("staging_crash_continuation_forbidden");
        }
        Ok(())
    })
}
thread_local! {static CRASH:std::cell::RefCell<Option<(Point,PathBuf)>>=const{std::cell::RefCell::new(None)};}
struct CutScope;
impl Drop for CutScope {
    fn drop(&mut self) {
        CUT.with(|c| c.set(None));
    }
}
fn fault(point: Point, action: Action) -> CutScope {
    CUT.with(|c| {
        assert!(c.get().is_none());
        c.set(Some((point, action)));
    });
    CutScope
}

use super::*;
use crate::managed_credentials::{effects, simulation, store::tests as fixture};
use rusqlite::OpenFlags;
use std::os::unix::fs::{PermissionsExt, symlink};
use syn::visit::{self, Visit};

pub(super) struct Fixture {
    state: State,
    refused: bool,
    calls: usize,
    fail_after_directory: bool,
    reject_application: bool,
    pub(super) expire_current: Option<Rc<Cell<(u64, u64)>>>,
}
impl sealed::Sealed for Fixture {}
impl Checks for Fixture {
    fn state(&mut self) -> &mut State {
        &mut self.state
    }
    fn current(&mut self) -> Result<()> {
        self.calls += 1;
        if let Some(clock) = self.expire_current.take() { clock.set((99, 100)); }
        ensure!(!self.refused, "fixture_refused");
        ensure!(
            !(self.fail_after_directory && self.state.directory_may_exist),
            "fixture_postcheck_refused"
        );
        Ok(())
    }
    fn local_sql(&mut self) -> Result<()> {
        self.current()
    }
    fn application(&mut self, tx: &Transaction<'_>) -> Result<()> {
        ensure!(!self.reject_application, "fixture_unsupported_application");
        let value: String = tx.query_row("SELECT value FROM fixture_business", [], |r| r.get(0))?;
        ensure!(value == "keep-data", "fixture_business_changed");
        Ok(())
    }
    fn refuse(&mut self) {
        self.refused = true;
    }
}

pub(super) struct World {
    source: tempfile::TempDir,
    target: tempfile::TempDir,
    pub(super) owner: Fixture,
    source_digest: Digest,
}
pub(super) fn world() -> Result<World> {
    let (source, mut db) = fixture::database()?;
    fixture::committed_issue(&mut db)?;
    db.execute_batch("CREATE TABLE fixture_business(value TEXT) STRICT; INSERT INTO fixture_business VALUES('keep-data'); CREATE TABLE fixture_payload(value BLOB) STRICT; INSERT INTO fixture_payload VALUES(zeroblob(131072));")?;
    drop(db);
    let path = source.path().join("app.sqlite").canonicalize()?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let source_digest = Digest::new(&std::fs::read(&path)?);
    let target = tempfile::tempdir()?;
    let root_path = target.path().canonicalize()?;
    let owner = fixture_owner(path, root_path, source_digest.clone())?;
    Ok(World {
        source,
        target,
        owner,
        source_digest,
    })
}
pub(super) fn fixture_owner(source: PathBuf, root_path: PathBuf, database: Digest) -> Result<Fixture> {
    let root = File::open(&root_path)?;
    let scope = Rc::new(());
    let state = State {
        input: Input {
            source,
            operation: Digest::new(b"one-staging-op"),
            namespace: fixture::namespace(),
            source_epoch: 7,
            database,
            target_incarnation: Digest::new(b"fresh-target"),
        },
        root_path,
        root,
        scope: scope.clone(),
        expected_scope: scope,
        attempted: false,
        refused: false,
        directory_may_exist: false,
        directory: None,
        creator: None,
        creator_identity: None,
        frozen_image: None,
        birth_original: None,
        source: None,
        sql: None,
        consumed: 0,
        written: 0,
        complete: false,
        writer_attempted: false,
    };
    Ok(Fixture {
        state,
        refused: false,
        calls: 0,
        fail_after_directory: false,
        reject_application: false,
        expire_current: None,
    })
}

#[test]
fn same_io_body_copies_resets_syncs_and_retains_the_actual_creator() -> Result<()> {
    effects::scope(simulation::World::new(2001), || {
        let mut w = world()?;
        let result = execute(&mut w.owner)?;
        assert_eq!(result.reset.newly_revoked, 1);
        assert_ne!(result.image, w.source_digest);
        assert!(w.owner.state.complete && !w.owner.refused);
        assert!(w.owner.state.creator.is_some() && w.owner.state.directory.is_some());
        assert!(w.owner.state.sql.is_none());
        assert_eq!(w.owner.state.written, result.bytes);
        assert_eq!(
            result.bytes,
            w.owner.state.creator.as_ref().unwrap().metadata()?.len()
        );
        assert_eq!(
            Digest::new(&std::fs::read(w.source.path().join("app.sqlite"))?),
            w.source_digest
        );
        let db = Connection::open_with_flags(
            w.owner.state.target_path()?,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        assert_eq!(
            db.query_row("SELECT value FROM fixture_business", [], |r| r
                .get::<_, String>(0))?,
            "keep-data"
        );
        assert_eq!(
            db.query_row("SELECT state FROM day2_credential_lineages", [], |r| r
                .get::<_, String>(
                0
            ))?,
            "revoked"
        );
        assert_eq!(
            db.query_row(
                "SELECT security_epoch FROM day2_credential_versions",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            7
        );
        assert!(execute(&mut w.owner).is_err());
        assert!(w.owner.refused);
        assert!(w.target.path().exists());
        Ok(())
    })
}

#[test]
fn unsupported_scope_digest_application_and_source_symlink_create_no_target() -> Result<()> {
    effects::scope(simulation::World::new(2002), || {
        for fault in 0..4 {
            let mut w = world()?;
            match fault {
                0 => w.owner.state.input.namespace.binding_generation += 1,
                1 => w.owner.state.input.database = Digest::new(b"wrong-image"),
                2 => w.owner.reject_application = true,
                _ => {
                    let alias = w.source.path().join("alias.sqlite");
                    symlink(&w.owner.state.input.source, &alias)?;
                    w.owner.state.input.source = alias;
                }
            }
            assert!(execute(&mut w.owner).is_err());
            assert!(w.owner.refused && !w.owner.state.complete);
            assert!(!w.owner.state.target_dir()?.exists());
        }
        Ok(())
    })
}

#[test]
fn existing_target_and_postcheck_failure_keep_the_primary_io_cause() -> Result<()> {
    effects::scope(simulation::World::new(2003), || {
        let mut w = world()?;
        let destination = w.owner.state.target_dir()?;
        std::fs::create_dir(&destination)?;
        std::fs::write(destination.join("keep"), b"existing-data")?;
        w.owner.fail_after_directory = true;
        let error = execute(&mut w.owner).unwrap_err();
        assert_eq!(
            error.downcast_ref::<rustix::io::Errno>(),
            Some(&rustix::io::Errno::EXIST)
        );
        assert!(w.owner.refused && !w.owner.state.complete);
        assert!(w.owner.state.creator.is_none() && w.owner.state.directory.is_none());
        assert_eq!(std::fs::read(destination.join("keep"))?, b"existing-data");
        Ok(())
    })
}

#[test]
fn scope_pointer_and_target_root_symlink_cannot_retarget_an_owner() -> Result<()> {
    effects::scope(simulation::World::new(2004), || {
        for alias in [false, true] {
            let mut w = world()?;
            if alias {
                let link = w.source.path().join("target-alias");
                symlink(&w.owner.state.root_path, &link)?;
                w.owner.state.root_path = link;
            } else {
                w.owner.state.scope = Rc::new(());
            }
            assert!(execute(&mut w.owner).is_err());
            assert!(w.owner.refused && !w.owner.state.directory_may_exist);
        }
        Ok(())
    })
}

#[test]
fn no_production_default_or_data_impl_can_supply_staging_checks() {
    struct Implementations {
        production: usize,
        defaults: usize,
    }
    impl<'ast> Visit<'ast> for Implementations {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if item.attrs.iter().any(|a| {
                a.path().is_ident("cfg")
                    && matches!(&a.meta,syn::Meta::List(v) if v.tokens.to_string()=="test")
            }) {
                return;
            }
            visit::visit_item_mod(self, item)
        }
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            if item
                .trait_
                .as_ref()
                .is_some_and(|(_, p, _)| p.segments.last().is_some_and(|n| n.ident == "Checks"))
            {
                self.production += 1;
            }
            visit::visit_item_impl(self, item)
        }
        fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
            if item.ident == "Checks" {
                self.defaults += item
                    .items
                    .iter()
                    .filter(|v| matches!(v,syn::TraitItem::Fn(f) if f.default.is_some()))
                    .count();
            }
            visit::visit_item_trait(self, item)
        }
    }
    fn closed(source: &str) -> bool {
        let mut seen = Implementations {
            production: 0,
            defaults: 0,
        };
        seen.visit_file(&syn::parse_file(source).unwrap());
        seen.production == 0 && seen.defaults == 0
    }
    let source = include_str!("../restore_staging.rs");
    assert!(closed(source));
    assert!(!closed(
        &(source.to_owned() + "\nimpl Checks for UntrustedData {}")
    ));
    let begin = source.find("fn current(").unwrap();
    let end = source[begin..].find(';').unwrap() + begin;
    assert!(!source[begin..end].contains('{'));
    let mut mutant = source.to_owned();
    mutant.replace_range(end..=end, " { Ok(()) }");
    assert!(!closed(&mutant));
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<A> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <State as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
}

// This oracle does not call execute, stage_reset or schema admission. Its only
// state transition is the independently specified atomic commit of revocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImageState {
    Absent,
    Partial,
    Original,
    Revoked,
}
#[derive(Debug, PartialEq, Eq)]
struct Observation {
    image: ImageState,
    complete: bool,
    refused: bool,
    creator: bool,
    sql_held: bool,
    memory_revoked: Option<bool>,
}
fn expected(point: Point) -> Observation {
    use Point::*;
    Observation {
        image: match point {
            Captured | Directory | BeforeCommit | AfterCommit | Closed => ImageState::Absent,
            FirstWrite => ImageState::Partial,
            Copied | Synced => ImageState::Revoked,
        },
        complete: false,
        refused: true,
        creator: matches!(point, FirstWrite | Copied | Synced),
        sql_held: matches!(point, BeforeCommit | AfterCommit),
        memory_revoked: match point {
            BeforeCommit => Some(false),
            AfterCommit => Some(true),
            _ => None,
        },
    }
}
fn observe(owner: &mut Fixture, source_length: u64) -> Result<Observation> {
    let path = owner.state.target_path()?;
    let image = if !path.try_exists()? {
        ImageState::Absent
    } else if path.metadata()?.len() < source_length {
        ImageState::Partial
    } else {
        let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let states:(i64,i64)=db.query_row("SELECT (SELECT count(*) FROM day2_credential_lineages WHERE state='active'),(SELECT count(*) FROM day2_credential_lineages WHERE state='revoked')",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        assert_eq!(
            db.query_row("SELECT value FROM fixture_business", [], |r| r
                .get::<_, String>(0))?,
            "keep-data"
        );
        assert_eq!(
            db.query_row("SELECT length(value) FROM fixture_payload", [], |r| r
                .get::<_, i64>(0))?,
            131072
        );
        assert_eq!(
            db.query_row(
                "SELECT security_epoch FROM day2_credential_versions",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            7
        );
        match states {
            (1, 0) => ImageState::Original,
            (0, 1) => ImageState::Revoked,
            _ => anyhow::bail!("unexpected_staging_state"),
        }
    };
    Ok(Observation {
        image,
        complete: owner.state.complete,
        refused: owner.refused,
        creator: owner.state.creator.is_some(),
        sql_held: owner.state.sql.is_some(),
        memory_revoked: owner
            .state
            .sql
            .as_ref()
            .map(|db| {
                db.query_row(
                    "SELECT state='revoked' FROM day2_credential_lineages",
                    [],
                    |r| r.get::<_, bool>(0),
                )
            })
            .transpose()?,
    })
}
#[test]
fn independent_failure_frontiers_replay_twice_without_regrant_or_source_mutation() -> Result<()> {
    for seed in [2011, 2027, 2063] {
        for point in [
            Point::Captured,
            Point::Directory,
            Point::FirstWrite,
            Point::Copied,
            Point::BeforeCommit,
            Point::AfterCommit,
            Point::Closed,
            Point::Synced,
        ] {
            let mut replay = Vec::new();
            for _ in 0..2 {
                replay.push(effects::scope(
                    simulation::World::new(seed),
                    || -> Result<Observation> {
                        let mut w = world()?;
                        let length = w.owner.state.input.source.metadata()?.len();
                        let guard = fault(point, Action::Refuse);
                        assert!(execute(&mut w.owner).is_err());
                        drop(guard);
                        let observed = observe(&mut w.owner, length)?;
                        assert_eq!(observed, expected(point));
                        assert!(execute(&mut w.owner).is_err());
                        assert_eq!(observe(&mut w.owner, length)?, observed);
                        assert_eq!(
                            Digest::new(&std::fs::read(&w.owner.state.input.source)?),
                            w.source_digest
                        );
                        Ok(observed)
                    },
                )?);
            }
            assert_eq!(replay[0], replay[1]);
        }
    }
    Ok(())
}
#[test]
fn unwinding_reset_retains_connection_and_rolls_back_without_completion() -> Result<()> {
    effects::scope(simulation::World::new(2069), || {
        let mut w = world()?;
        let length = w.owner.state.input.source.metadata()?.len();
        let guard = fault(Point::BeforeCommit, Action::Panic);
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| execute(&mut w.owner)));
        drop(guard);
        assert!(result.is_err());
        assert_eq!(
            observe(&mut w.owner, length)?,
            expected(Point::BeforeCommit)
        );
        assert!(w.owner.state.creator.is_none() && w.owner.state.sql.is_some());
        Ok(())
    })
}

const CHILD: &str = "security_epoch::restore_staging::tests::staging_process_loss_child";
const CHILD_CONFIG: &str = "DAY2_RESTORE_STAGING_FIXTURE";
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildConfig {
    source: PathBuf,
    root: PathBuf,
    database: Digest,
    point: Point,
    marker: PathBuf,
}
#[test]
#[ignore = "disposable process-loss child; launched only by its parent test"]
fn staging_process_loss_child() -> Result<()> {
    let path = std::env::var_os(CHILD_CONFIG).context("staging_child_config_missing")?;
    let bytes = std::fs::read(path)?;
    ensure!(bytes.len() <= 4096, "staging_child_config_bound");
    let config: ChildConfig = crate::json::decode(&bytes)?;
    effects::scope(simulation::World::new(2081), || {
        let mut owner = fixture_owner(config.source, config.root, config.database)?;
        CRASH.with(|c| *c.borrow_mut() = Some((config.point, config.marker)));
        execute(&mut owner)?;
        anyhow::bail!("staging_child_missed_cut")
    })
}
struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn real_process_loss_never_publishes_memory_commit_or_adopts_partial_or_reset_targets() -> Result<()>
{
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    for point in [
        Point::BeforeCommit,
        Point::AfterCommit,
        Point::FirstWrite,
        Point::Copied,
        Point::Synced,
    ] {
        effects::scope(simulation::World::new(2081), || -> Result<()> {
            let w = world()?;
            let control = tempfile::tempdir()?;
            let marker = control.path().join("ready");
            let config_path = control.path().join("config.json");
            let config = ChildConfig {
                source: w.owner.state.input.source.clone(),
                root: w.owner.state.root_path.clone(),
                database: w.source_digest.clone(),
                point,
                marker: marker.clone(),
            };
            std::fs::write(&config_path, serde_json::to_vec(&config)?)?;
            let mut child = ChildGuard(
                Command::new(std::env::current_exe()?)
                    .args(["--exact", CHILD, "--ignored", "--test-threads=1"])
                    .env(CHILD_CONFIG, &config_path)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()?,
            );
            let deadline = Instant::now() + Duration::from_secs(30);
            while !marker.try_exists()? {
                ensure!(
                    child.0.try_wait()?.is_none(),
                    "staging_child_exited_before_cut"
                );
                ensure!(Instant::now() < deadline, "staging_child_cut_timeout");
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(std::fs::read(&marker)?, b"staging-cut-ready");
            child.0.kill()?;
            let status = child.0.wait()?;
            assert!(!status.success());
            let mut restarted = fixture_owner(
                w.owner.state.input.source.clone(),
                w.owner.state.root_path.clone(),
                w.source_digest.clone(),
            )?;
            let path = restarted.state.target_path()?;
            let present = path.try_exists()?;
            assert_eq!(
                present,
                matches!(point, Point::FirstWrite | Point::Copied | Point::Synced)
            );
            if matches!(point, Point::Copied | Point::Synced) {
                let db =
                    Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                let state: String =
                    db.query_row("SELECT state FROM day2_credential_lineages", [], |r| {
                        r.get(0)
                    })?;
                assert_eq!(state, "revoked");
                assert!(crate::store::require_no_managed_credential_restore_state(&db).is_err());
            }
            if point == Point::FirstWrite {
                assert!(
                    path.metadata()?.len() < std::fs::metadata(&w.owner.state.input.source)?.len()
                );
            }
            let preserved = if present {
                Some(Digest::new(&std::fs::read(&path)?))
            } else {
                None
            };
            // The two pre-creation cuts have no physical target to adopt. The
            // one-shot external ledger, not a reconstructed fixture owner,
            // would forbid renewing those attempts in a genuine implementation.
            if !present {
                return Ok(());
            }
            assert!(execute(&mut restarted).is_err());
            assert!(restarted.refused && !restarted.state.complete);
            assert_eq!(Some(Digest::new(&std::fs::read(&path)?)), preserved);
            assert_eq!(
                Digest::new(&std::fs::read(&w.owner.state.input.source)?),
                w.source_digest
            );
            Ok(())
        })?;
    }
    Ok(())
}

thread_local! {
    static SOURCE_SWAP:std::cell::RefCell<Option<PathBuf>>=const{std::cell::RefCell::new(None)};
    static TARGET_SWAP:Cell<bool>=const{Cell::new(false)};
}
struct SwapScope;
impl Drop for SwapScope {
    fn drop(&mut self) {
        SOURCE_SWAP.with(|s| *s.borrow_mut() = None);
        TARGET_SWAP.with(|s| s.set(false));
    }
}
pub(super) fn before_write(state: &mut State) -> Result<()> {
    if TARGET_SWAP.with(Cell::get) {
        let path = state.target_path()?;
        std::fs::rename(&path, path.with_extension("held"))?;
        std::fs::write(&path, b"untouched-decoy")?;
    }
    Ok(())
}
pub(super) fn after_write(state: &mut State) -> Result<()> {
    if TARGET_SWAP.with(Cell::get) {
        let path = state.target_path()?;
        ensure!(
            std::fs::read(&path)? == b"untouched-decoy",
            "staging_wrote_decoy_path"
        );
        std::fs::remove_file(&path)?;
        std::fs::rename(path.with_extension("held"), &path)?;
    }
    Ok(())
}
#[test]
fn swapped_source_and_target_paths_cannot_redirect_sql_admission_reset_or_file_writes() -> Result<()>
{
    effects::scope(simulation::World::new(2093), || {
        let mut w = world()?;
        let _scope = SwapScope;
        SOURCE_SWAP.with(|s| *s.borrow_mut() = Some(w.owner.state.input.source.clone()));
        TARGET_SWAP.with(|s| s.set(true));
        let result = execute(&mut w.owner)?;
        assert_eq!(result.reset.newly_revoked, 1);
        assert_eq!(
            Digest::new(&std::fs::read(&w.owner.state.input.source)?),
            w.source_digest
        );
        assert_eq!(
            Digest::new(&std::fs::read(w.owner.state.target_path()?)?),
            result.image
        );
        let target = Connection::open_with_flags(
            w.owner.state.target_path()?,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        assert_eq!(
            target.query_row("SELECT state FROM day2_credential_lineages", [], |r| r
                .get::<_, String>(
                0
            ))?,
            "revoked"
        );
        Ok(())
    })
}
#[test]
fn actual_sql_constructor_cannot_reopen_either_path_or_deserialize_different_bytes() {
    struct Opens {
        fresh: usize,
        foreign: usize,
        deserialized: usize,
        exact: bool,
    }
    impl<'ast> Visit<'ast> for Opens {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func
                && path.path.segments.iter().any(|s| s.ident == "Connection")
            {
                if path
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "open_in_memory")
                {
                    self.fresh += 1;
                } else {
                    self.foreign += 1;
                }
            }
            visit::visit_expr_call(self, call)
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "deserialize_read_exact" {
                self.deserialized += 1;
                self.exact = matches!(call.args.iter().nth(1),Some(syn::Expr::Reference(r)) if matches!(&*r.expr,syn::Expr::Index(i) if matches!(&*i.expr,syn::Expr::Path(p) if p.path.is_ident("image"))));
            }
            visit::visit_expr_method_call(self, call)
        }
    }
    fn valid(source: &str) -> bool {
        let mut seen = Opens {
            fresh: 0,
            foreign: 0,
            deserialized: 0,
            exact: false,
        };
        seen.visit_file(&syn::parse_file(source).unwrap());
        seen.fresh == 1 && seen.foreign == 0 && seen.deserialized == 1 && seen.exact
    }
    let source = include_str!("../restore_staging.rs");
    assert!(valid(source));
    assert_eq!(source.matches("Connection::open_in_memory()?").count(), 1);
    assert!(!valid(&source.replacen(
        "Connection::open_in_memory()?",
        "Connection::open(source_path)?",
        1
    )));
    assert_eq!(source.matches("&image[..]").count(), 1);
    assert!(!valid(&source.replacen("&image[..]", "&foreign[..]", 1)));
}

#[test]
fn wal_shm_journal_and_dangling_sidecars_refuse_before_any_target() -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        for dangling in [false, true] {
            effects::scope(simulation::World::new(2099), || -> Result<()> {
                let mut w = world()?;
                let mut name = w.owner.state.input.source.as_os_str().to_os_string();
                name.push(suffix);
                if dangling {
                    symlink(w.source.path().join("absent"), PathBuf::from(name))?;
                } else {
                    std::fs::write(PathBuf::from(name), b"unqualified-sidecar")?;
                }
                assert!(execute(&mut w.owner).is_err());
                assert!(
                    w.owner.refused
                        && !w.owner.state.complete
                        && !w.owner.state.directory_may_exist
                );
                assert!(!w.owner.state.target_dir()?.try_exists()?);
                Ok(())
            })?;
        }
    }
    Ok(())
}

thread_local! {static CREATE_SWAP:Cell<bool>=const{Cell::new(false)};}
struct CreationSwap;
impl Drop for CreationSwap {
    fn drop(&mut self) {
        CREATE_SWAP.with(|c| c.set(false));
    }
}
fn creation_parent(state: &State) -> Result<PathBuf> {
    if state.directory.is_some() {
        state.target_dir()
    } else {
        Ok(state.root_path.clone())
    }
}
pub(super) fn before_create(state: &mut State) -> Result<()> {
    if CREATE_SWAP.with(Cell::get) {
        let path = creation_parent(state)?;
        std::fs::rename(&path, path.with_extension("held-create"))?;
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub(super) fn after_create(state: &mut State) -> Result<()> {
    if CREATE_SWAP.with(Cell::get) {
        // During the first creation directory has just been recorded. The
        // swapped parent is still the root, until the creator is attempted.
        let root_shadow = state.root_path.with_extension("held-create");
        let path = if root_shadow.try_exists()? {
            state.root_path.clone()
        } else {
            state.target_dir()?
        };
        ensure!(
            std::fs::read_dir(&path)?.next().is_none(),
            "staging_creation_escaped_held_parent"
        );
        std::fs::remove_dir(&path)?;
        std::fs::rename(path.with_extension("held-create"), &path)?;
    }
    Ok(())
}
#[test]
fn creation_stays_under_held_parent_descriptors_during_parent_path_swaps() -> Result<()> {
    effects::scope(simulation::World::new(2101), || {
        let mut w = world()?;
        let _scope = CreationSwap;
        CREATE_SWAP.with(|c| c.set(true));
        let result = execute(&mut w.owner)?;
        assert!(w.owner.state.complete && !w.owner.refused);
        assert_eq!(
            Digest::new(&std::fs::read(w.owner.state.target_path()?)?),
            result.image
        );
        Ok(())
    })
}
