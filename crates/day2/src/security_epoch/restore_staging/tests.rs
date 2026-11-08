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
use std::fs::OpenOptions;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use syn::visit::{self, Visit};

pub(super) struct Fixture {
    state: State,
    application: application::tests::Fixture,
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
        if let Some(clock) = self.expire_current.take() {
            clock.set((99, 100));
        }
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
    fn application(&mut self, tx: &Transaction<'_>) -> Result<application::Selection<'_>> {
        ensure!(!self.reject_application, "fixture_unsupported_application");
        let present: bool =
            tx.query_row("SELECT EXISTS(SELECT 1 FROM fixture_business)", [], |r| {
                r.get(0)
            })?;
        ensure!(present, "fixture_business_missing");
        Ok(self.application.selection())
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
impl World {
    pub(super) fn source_path(&self) -> Result<PathBuf> {
        Ok(self.source.path().join("app.sqlite").canonicalize()?)
    }
}

pub(super) fn world() -> Result<World> {
    let source = tempfile::tempdir()?;
    let mut application = application::tests::Fixture::new()?;
    application.db.execute_batch("CREATE TABLE fixture_payload(value BLOB) STRICT; INSERT INTO fixture_payload VALUES(zeroblob(131072));")?;
    std::fs::write(
        source.path().join("app.sqlite"),
        &*application.db.serialize(MAIN_DB)?,
    )?;
    let path = source.path().join("app.sqlite").canonicalize()?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let source_digest = Digest::new(&std::fs::read(&path)?);
    let target = tempfile::tempdir()?;
    let root_path = target.path().canonicalize()?;
    let owner =
        fixture_owner_with_application(path, root_path, source_digest.clone(), application)?;
    Ok(World {
        source,
        target,
        owner,
        source_digest,
    })
}
pub(super) fn fixture_owner(
    source: PathBuf,
    root_path: PathBuf,
    database: Digest,
) -> Result<Fixture> {
    fixture_owner_with_application(
        source,
        root_path,
        database,
        application::tests::Fixture::new()?,
    )
}

fn fixture_owner_with_application(
    source: PathBuf,
    root_path: PathBuf,
    database: Digest,
    application: application::tests::Fixture,
) -> Result<Fixture> {
    // The fixture supplies the private-root precondition explicitly, independent
    // of the process umask. Production admission must still refuse public roots.
    std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700))?;
    let root = File::open(&root_path)?;
    ensure!(
        source.is_absolute() && source.canonicalize()? == source,
        "fixture_source_alias"
    );
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits(),
        )?)
        .open(&source)?;
    let scope = Rc::new(());
    let state = State {
        input: Input {
            source,
            operation: Digest::new(b"one-staging-op"),
            namespace: fixture::namespace(),
            source_epoch: 1,
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
        application,
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
        assert_eq!(result.reset.credentials.newly_revoked, 1);
        assert_eq!(result.reset.closed_oauth_originals, 1);
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
        w.owner.application.require_image(&db, true)?;
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
            1
        );
        assert!(execute(&mut w.owner).is_err());
        assert!(w.owner.refused);
        assert!(w.target.path().exists());
        Ok(())
    })
}

#[test]
fn unsupported_scope_digest_application_and_non_file_source_create_no_target() -> Result<()> {
    effects::scope(simulation::World::new(2002), || {
        for fault in 0..4 {
            let mut w = world()?;
            match fault {
                0 => w.owner.state.input.namespace.binding_generation += 1,
                1 => w.owner.state.input.database = Digest::new(b"wrong-image"),
                2 => w.owner.reject_application = true,
                _ => {
                    w.owner.state.input.source = File::open(w.source.path())?;
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
    use quote::ToTokens as _;
    fn factory_tokens(mut block: syn::Block) -> String {
        fn expr(value: &mut syn::Expr) {
            match value {
                syn::Expr::Call(call) => {
                    expr(&mut call.func);
                    for arg in &mut call.args {
                        expr(arg);
                    }
                    call.args.pop_punct();
                }
                syn::Expr::MethodCall(call) => {
                    expr(&mut call.receiver);
                    for arg in &mut call.args {
                        expr(arg);
                    }
                    call.args.pop_punct();
                }
                syn::Expr::Try(node) => expr(&mut node.expr),
                syn::Expr::Paren(node) => expr(&mut node.expr),
                syn::Expr::Closure(node) => expr(&mut node.body),
                syn::Expr::Block(node) => body(&mut node.block),
                syn::Expr::If(node) => {
                    expr(&mut node.cond);
                    body(&mut node.then_branch);
                    if let Some((_, other)) = &mut node.else_branch {
                        expr(other);
                    }
                }
                _ => {}
            }
        }
        fn body(value: &mut syn::Block) {
            for statement in &mut value.stmts {
                match statement {
                    syn::Stmt::Local(local) => {
                        if let Some(init) = &mut local.init {
                            expr(&mut init.expr);
                        }
                    }
                    syn::Stmt::Expr(value, _) => expr(value),
                    _ => {}
                }
            }
        }
        body(&mut block);
        block.to_token_stream().to_string()
    }
    fn archive_factory_flow(body: &syn::Block) -> bool {
        let mut actual = body.clone();
        // The State literal is independently checked field-by-field below.
        // Keep every binding, ordered check, postcheck and consuming call here.
        let Some(syn::Stmt::Local(requested)) = actual.stmts.get_mut(3) else {
            return false;
        };
        let Some(init) = &mut requested.init else {
            return false;
        };
        let syn::Expr::Call(call) = &mut *init.expr else {
            return false;
        };
        let syn::Expr::Paren(paren) = &mut *call.func else {
            return false;
        };
        let syn::Expr::Closure(closure) = &mut *paren.expr else {
            return false;
        };
        let syn::Expr::Block(closure) = &mut *closure.body else {
            return false;
        };
        let mut count = 0;
        for statement in &mut closure.block.stmts {
            if let syn::Stmt::Local(local) = statement
                && matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="state")
                && let Some(init) = &mut local.init
                && matches!(&*init.expr,syn::Expr::Struct(value) if value.path.segments.last().is_some_and(|name|name.ident=="State"))
            {
                count += 1;
                *init.expr = syn::parse_quote!(CHECKED_STATE_LITERAL);
            }
        }
        if count != 1 {
            return false;
        }
        let expected: syn::Block = syn::parse_quote!({
            if self.attempted {
                if let Some(executor) = self.executor.as_mut() {
                    executor.refuse();
                }
                anyhow::bail!("restore_archive_attempt_spent");
            }
            self.attempted = true;
            let mut executor = self
                .executor
                .take()
                .context("restore_archive_executor_closed")?;
            let requested: Result<super::State> = (|| {
                executor.require_historical_keys(&self.intent)?;
                self.snapshot.tree.check()?;
                let source = self
                    .snapshot
                    .source
                    .take()
                    .context("restore_archive_source_spent")?;
                let root = self
                    .preparation
                    .root
                    .take()
                    .context("restore_archive_root_spent")?;
                let scope = std::rc::Rc::new(());
                let state = CHECKED_STATE_LITERAL;
                state.require_unstarted()?;
                Ok(state)
            })();
            let checked = executor.require_historical_keys(&self.intent);
            if requested.is_err() || checked.is_err() {
                executor.refuse();
            }
            let state = requested?;
            checked?;
            let selection = super::application::Selection::prepared(
                &self.preparation.namespace,
                self.intent.archive.security_epoch,
                &self.snapshot.artifact,
                &self.preparation.fence,
                &self.preparation.authority_schema,
                &self.preparation.oauth_schema,
                &self.preparation.cut,
            )?;
            super::writer::NativeRestore::consume(
                executor,
                &self.intent,
                state,
                selection,
                CapturedRestoreArtifact {
                    snapshot: &self.snapshot,
                    local: std::marker::PhantomData,
                },
            )
        });
        factory_tokens(actual) == factory_tokens(expected)
    }
    struct Implementations {
        writer: bool,
        archive: bool,
        in_archive: bool,
        archive_factory: bool,
        archive_factories: usize,
        in_state: bool,
        external: Vec<String>,
        production: usize,
        defaults: usize,
        writer_owners: usize,
        closed_writer: bool,
        parents: usize,
        parent_impls: usize,
        in_parent: bool,
        parent_factory: bool,
        parent_constructions: usize,
        state_constructions: usize,
        closed: bool,
    }
    impl<'ast> Visit<'ast> for Implementations {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if item.attrs.iter().any(|a| {
                a.path().is_ident("cfg")
                    && matches!(&a.meta,syn::Meta::List(v) if v.tokens.to_string()=="test")
            }) {
                return;
            }
            if item.content.is_none() {
                self.closed &= item.attrs.iter().all(|a| a.path().is_ident("doc"));
                self.external.push(item.ident.to_string());
            }
            visit::visit_item_mod(self, item)
        }
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            let parent = matches!(&*item.self_ty, syn::Type::Path(t)
                if t.qself.is_none() && t.path.segments.len() == 1
                    && t.path.segments[0].ident == "NativeParent");
            if item
                .trait_
                .as_ref()
                .is_some_and(|(_, p, _)| p.segments.last().is_some_and(|n| n.ident == "Checks"))
            {
                self.production += 1;
            }
            if parent {
                self.parent_impls += 1;
                let names = [
                    "state",
                    "current",
                    "local_sql",
                    "application",
                    "refuse",
                    "execute_staging",
                    "stage_and_settle",
                ];
                let names: &[&str] = if item.items.len() == 1
                    && matches!(&item.items[0], syn::ImplItem::Fn(method) if method.sig.ident == "admit")
                {
                    &["admit"]
                } else {
                    &names
                };
                let allowed = item.trait_.is_none()
                    && item.items.len() == names.len()
                    && names.iter().all(|name| item.items.iter().filter(|member| matches!(member,
                        syn::ImplItem::Fn(method) if method.sig.ident == *name && matches!(method.vis, syn::Visibility::Inherited))).count() == 1);
                self.closed &= self.writer && allowed;
            }
            if let Some((_, path, _)) = &item.trait_
                && path
                    .segments
                    .last()
                    .is_some_and(|name| name.ident == "WriterOwner")
            {
                self.writer_owners += 1;
                self.closed_writer &= self.writer
                    && matches!(&*item.self_ty, syn::Type::Path(ty)
                        if ty.qself.is_none() && ty.path.segments.len() == 1
                            && ty.path.segments[0].ident == "PortableWriter");
            }
            let previous = (self.in_parent, self.in_archive, self.in_state);
            self.in_parent = parent;
            self.in_archive = self.archive
                && item.trait_.is_none()
                && matches!(&*item.self_ty, syn::Type::Path(t) if t.qself.is_none()
                    && t.path.segments.len()==1 && t.path.segments[0].ident=="ArchivePrepared");
            self.in_state = matches!(&*item.self_ty, syn::Type::Path(t)
                if t.path.segments.last().is_some_and(|name|name.ident=="State"));
            visit::visit_item_impl(self, item);
            (self.in_parent, self.in_archive, self.in_state) = previous;
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            let previous = (self.parent_factory, self.archive_factory);
            self.parent_factory = self.writer && self.in_parent && item.sig.ident == "admit";
            let mut actual = item.sig.clone();
            actual.inputs.pop_punct();
            let mut expected: syn::Signature = syn::parse_quote!(
                fn start_native(&mut self) -> Result<super::writer::NativeRestore<'metadata, 'storage, 'role, '_>>
            );
            expected.inputs.pop_punct();
            self.archive_factory = self.in_archive
                && item.vis.to_token_stream().to_string() == "pub (super)"
                && actual.to_token_stream().to_string() == expected.to_token_stream().to_string();
            self.archive_factories += usize::from(self.archive_factory);
            if self.archive_factory {
                self.closed &= archive_factory_flow(&item.block);
            }
            visit::visit_impl_item_fn(self, item);
            (self.parent_factory, self.archive_factory) = previous;
        }
        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            if item.ident == "NativeParent" {
                self.parents += 1;
                let fields: Vec<_> = item.fields.iter().collect();
                let expected = [
                    (
                        "loan",
                        "crate::security_epoch::bootstrap::RestoreWriteLoan<'borrow,'metadata,'storage,'role>",
                    ),
                    (
                        "root",
                        "crate::security_epoch::storage_authority::RestoreCreatorRoot",
                    ),
                    ("state", "State"),
                    ("selection", "super::application::Selection<'selection>"),
                    (
                        "artifact",
                        "&'selection super::archive::CapturedRestoreArtifact<'selection>",
                    ),
                    (
                        "installed",
                        "Option<super::archive::InstalledRestoreArtifact>",
                    ),
                ];
                self.closed &= self.writer
                    && matches!(item.vis, syn::Visibility::Inherited)
                    && item.attrs.iter().all(|a| a.path().is_ident("doc"))
                    && fields.len() == expected.len()
                    && fields.iter().zip(expected).all(|(field, (name, ty))| {
                        matches!(field.vis, syn::Visibility::Inherited)
                            && field.ident.as_ref().is_some_and(|i| i == name)
                            && field.ty.to_token_stream().to_string()
                                == syn::parse_str::<syn::Type>(ty)
                                    .unwrap()
                                    .to_token_stream()
                                    .to_string()
                    });
            }
            visit::visit_item_struct(self, item)
        }
        fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
            let name = expression
                .path
                .segments
                .last()
                .map(|part| part.ident.to_string());
            if name.as_deref() == Some("State")
                || (self.in_state && name.as_deref() == Some("Self"))
            {
                // Only the real child factory may consume the retained
                // executor, captured source and protected root into State.
                self.state_constructions += 1;
                let expected: syn::ExprStruct = syn::parse_quote!(super::State {
                    input: super::Input {
                        source,
                        operation: self.intent.operation.clone(),
                        namespace: self.preparation.namespace.clone(),
                        source_epoch: self.intent.archive.security_epoch,
                        database: self.intent.archive.image.clone(),
                        target_incarnation: self.intent.target_incarnation.clone(),
                    },
                    root_path: self.preparation.root_path.clone(),
                    root,
                    scope: std::rc::Rc::clone(&scope),
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
                });
                self.closed &=
                    self.archive_factory
                        && expression.rest.is_none()
                        && expression.fields.len() == expected.fields.len()
                        && expression.fields.iter().zip(&expected.fields).all(
                            |(actual, expected)| {
                                actual.member.to_token_stream().to_string()
                                    == expected.member.to_token_stream().to_string()
                                    && actual.expr.to_token_stream().to_string()
                                        == expected.expr.to_token_stream().to_string()
                            },
                        );
            }
            if name.as_deref() == Some("NativeParent")
                || (self.in_parent && name.as_deref() == Some("Self"))
            {
                self.parent_constructions += 1;
                self.closed &= self.parent_factory;
            }
            visit::visit_expr_struct(self, expression)
        }
        fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
            if item.ident == "Checks" || item.ident == "WriterOwner" {
                self.defaults += item
                    .items
                    .iter()
                    .filter(|v| matches!(v,syn::TraitItem::Fn(f) if f.default.is_some()))
                    .count();
            }
            visit::visit_item_trait(self, item)
        }
    }
    fn closed(sources: [&str; 7]) -> bool {
        let mut seen = Implementations {
            writer: false,
            archive: false,
            in_archive: false,
            archive_factory: false,
            archive_factories: 0,
            in_state: false,
            external: Vec::new(),
            production: 0,
            defaults: 0,
            writer_owners: 0,
            closed_writer: true,
            parents: 0,
            parent_impls: 0,
            in_parent: false,
            parent_factory: false,
            parent_constructions: 0,
            state_constructions: 0,
            closed: true,
        };
        for (index, source) in sources.into_iter().enumerate() {
            seen.writer = index == 1;
            seen.archive = index == 4;
            seen.external.clear();
            seen.visit_file(&syn::parse_file(source).unwrap());
            seen.external.sort();
            let expected: &[&str] = match index {
                0 => &["application", "archive", "writer"],
                1 => &["dispatch", "receiver"],
                4 => &["installation"],
                _ => &[],
            };
            seen.closed &= seen
                .external
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied());
        }
        seen.production == 0
            && seen.parents == 1
            && seen.parent_impls == 2
            && seen.parent_constructions == 1
            && seen.state_constructions == 1
            && seen.archive_factories == 1
            && seen.defaults == 0
            && seen.closed
            && seen.writer_owners == 2
            && seen.closed_writer
    }
    let source = include_str!("../restore_staging.rs");
    let writer = include_str!("writer.rs");
    let application = include_str!("application.rs");
    let dispatch = include_str!("writer/dispatch.rs");
    let archive = include_str!("archive.rs");
    let receiver = include_str!("writer/receiver.rs");
    let installation = include_str!("archive/installation.rs");
    assert!(closed([
        source,
        writer,
        application,
        dispatch,
        archive,
        receiver,
        installation
    ]));
    for index in 0..7 {
        for implementation in [
            "\nimpl Checks for UntrustedData {}",
            "\nmod nested { impl super::Checks for UntrustedData {} }",
            "\nimpl WriterOwner for UntrustedData {}",
            "\nmod nested { impl super::WriterOwner for UntrustedData {} }",
        ] {
            let mut sources = [
                source.to_owned(),
                writer.to_owned(),
                application.to_owned(),
                dispatch.to_owned(),
                archive.to_owned(),
                receiver.to_owned(),
                installation.to_owned(),
            ];
            sources[index].push_str(implementation);
            assert!(!closed(std::array::from_fn(|i| sources[i].as_str())));
        }
    }
    let begin = source.find("fn current(").unwrap();
    let end = source[begin..].find(';').unwrap() + begin;
    assert!(!source[begin..end].contains('{'));
    let mut mutant = source.to_owned();
    mutant.replace_range(end..=end, " { Ok(()) }");
    assert!(!closed([
        &mutant,
        writer,
        application,
        dispatch,
        archive,
        receiver,
        installation
    ]));
    for (from, to) in [
        (
            "impl NativeParent<'_, '_, '_, '_, '_>",
            "impl UntrustedData",
        ),
        (
            "struct NativeParent<",
            "#[derive(Default)] struct NativeParent<",
        ),
    ] {
        assert_eq!(writer.matches(from).count(), 1);
        assert!(!closed([
            source,
            &writer.replacen(from, to, 1),
            application,
            dispatch,
            archive,
            receiver,
            installation
        ]));
    }
    // The new admission method also has a loan parameter. Mutate the actual
    // retained field, not a same-spelled parameter or a formatting substring.
    let mut foreign_loan = syn::parse_file(writer).unwrap();
    let parents: Vec<_> = foreign_loan
        .items
        .iter_mut()
        .filter_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "NativeParent" => Some(item),
            _ => None,
        })
        .collect();
    let [parent] = parents.as_slice() else {
        panic!("one actual NativeParent");
    };
    assert_eq!(
        parent
            .fields
            .iter()
            .filter(|field| field.ident.as_ref().is_some_and(|name| name == "loan"))
            .count(),
        1
    );
    let parent = parents.into_iter().next().unwrap();
    let loan = parent
        .fields
        .iter_mut()
        .find(|field| field.ident.as_ref().is_some_and(|name| name == "loan"))
        .unwrap();
    loan.ty = syn::parse_quote!(UntrustedData);
    assert!(!closed([
        source,
        &foreign_loan.to_token_stream().to_string(),
        application,
        dispatch,
        archive,
        receiver,
        installation
    ]));
    for field_name in ["artifact", "installed"] {
        for cut in 0..2 {
            let mut changed = syn::parse_file(writer).unwrap();
            let mut selected = 0;
            for item in &mut changed.items {
                if let syn::Item::Struct(item) = item
                    && item.ident == "NativeParent"
                {
                    for field in &mut item.fields {
                        if field.ident.as_ref().is_some_and(|name| name == field_name) {
                            selected += 1;
                            if cut == 0 {
                                field.ty = syn::parse_quote!(std::fs::File);
                            } else {
                                field.vis = syn::parse_quote!(pub);
                            }
                        }
                    }
                }
            }
            assert_eq!(selected, 1);
            assert!(!closed([
                source,
                &changed.to_token_stream().to_string(),
                application,
                dispatch,
                archive,
                receiver,
                installation
            ]));
        }
    }
    for constructor in [
        "impl NativeParent<'_, '_, '_, '_, '_> { fn from_receipt() -> Self { unreachable!() } }",
        "fn adopt_data() { let parent = NativeParent { loan: receipt, state, selection }; }",
        "fn raw_state() { let state = State { ..record }; }",
        "impl Drop for NativeParent<'_, '_, '_, '_, '_> { fn drop(&mut self) {} }",
    ] {
        assert!(!closed([
            source,
            &(writer.to_owned() + constructor),
            application,
            dispatch,
            archive,
            receiver,
            installation
        ]));
    }
    for addition in [
        "fn raw_archive_state() { let state = super::State { ..record }; }",
        "impl super::State { fn raw() -> Self { Self { ..record } } }",
        "mod unreviewed_child;",
    ] {
        assert!(!closed([
            source,
            writer,
            application,
            dispatch,
            &(archive.to_owned() + addition),
            receiver,
            installation
        ]));
    }
    for (from, to) in [
        ("pub(super) fn start_native", "pub fn start_native"),
        ("pub(super) fn start_native", "pub(super) fn adopt_receipt"),
        ("expected_scope: scope", "expected_scope: untrusted_scope"),
        (
            "database: self.intent.archive.image.clone()",
            "database: untrusted_digest.clone()",
        ),
    ] {
        assert_eq!(archive.matches(from).count(), 1);
        assert!(!closed([
            source,
            writer,
            application,
            dispatch,
            &archive.replacen(from, to, 1),
            receiver,
            installation
        ]));
    }
    fn mutate_archive_factory(source: &str, from: &str, to: &str) -> String {
        let mut parsed = syn::parse_file(source).unwrap();
        let mut count = 0;
        for item in &mut parsed.items {
            if let syn::Item::Impl(item) = item
                && matches!(&*item.self_ty,syn::Type::Path(ty) if ty.qself.is_none()
                    && ty.path.segments.len()==1 && ty.path.segments[0].ident=="ArchivePrepared")
            {
                for member in &mut item.items {
                    if let syn::ImplItem::Fn(method) = member
                        && method.sig.ident == "start_native"
                    {
                        count += 1;
                        let mut text = method.block.to_token_stream().to_string();
                        let tokens = |fragment: &str| {
                            let block: syn::Block =
                                syn::parse_str(&format!("{{{fragment}}}")).unwrap();
                            let mut result = proc_macro2::TokenStream::new();
                            for statement in block.stmts {
                                statement.to_tokens(&mut result);
                            }
                            result.to_string()
                        };
                        let (from, to) = (tokens(from), tokens(to));
                        assert_eq!(
                            text.matches(&from).count(),
                            1,
                            "one actual prepared binding"
                        );
                        text = text.replacen(&from, &to, 1);
                        method.block = syn::parse_str(&text).unwrap();
                    }
                }
            }
        }
        assert_eq!(count, 1, "one actual prepared factory");
        parsed.to_token_stream().to_string()
    }
    for (from, to) in [
        ("self.snapshot.source.take()", "untrusted_source.take()"),
        ("self.preparation.root.take()", "untrusted_root.take()"),
        ("self.executor.take()", "untrusted_executor.take()"),
        ("self.attempted = true;", "self.attempted = false;"),
        (
            "let checked = executor.require_historical_keys(&self.intent);",
            "let checked = Ok(());",
        ),
        ("checked?;", "let _ = checked;"),
        (
            "super::writer::NativeRestore::consume",
            "super::writer::NativeRestore::adopt_record",
        ),
    ] {
        let changed = mutate_archive_factory(archive, from, to);
        assert!(!closed([
            source,
            writer,
            application,
            dispatch,
            &changed,
            receiver,
            installation
        ]));
    }
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

    // Omitting the actual owning module edge or introducing an unchecked
    // child in the installer must fail just like any other production source.
    for (archive_source, installer_source) in [
        (
            archive.replacen("mod installation;", "mod unreviewed;", 1),
            installation.to_owned(),
        ),
        (
            archive.to_owned(),
            installation.to_owned() + "\nmod unreviewed_child;",
        ),
    ] {
        assert!(!closed([
            source,
            writer,
            application,
            dispatch,
            &archive_source,
            receiver,
            &installer_source
        ]));
    }
}

#[test]
fn memory_admission_rejects_invalid_owners_before_replacing_their_hook() -> Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    for fault in 0..3 {
        let directory = tempfile::tempdir()?;
        let mut db = if fault == 0 {
            Connection::open(directory.path().join("foreign.sqlite"))?
        } else {
            Connection::open_in_memory()?
        };
        if fault != 2 {
            db.pragma_update(None, "temp_store", "MEMORY")?;
        }
        if fault == 1 {
            db.execute_batch("BEGIN")?;
        }
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&hits);
        db.progress_handler(
            1,
            Some(move || {
                observed.fetch_add(1, Ordering::Relaxed);
                false
            }),
        )?;
        assert!(MemoryAdmission::configure(&mut db).is_err());
        let before = hits.load(Ordering::Relaxed);
        db.query_row("WITH RECURSIVE w(n) AS(VALUES(0) UNION ALL SELECT n+1 FROM w WHERE n<2000) SELECT max(n) FROM w",[],|r|r.get::<_,i64>(0))?;
        assert!(hits.load(Ordering::Relaxed) > before);
        if fault == 1 {
            db.execute_batch("ROLLBACK")?;
        }
    }
    Ok(())
}

#[test]
fn retained_memory_admission_checks_the_actual_hook_and_never_selects_raw_installation() {
    use quote::ToTokens as _;
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = call.func.as_ref() {
                self.0
                    .push(path.path.segments.last().unwrap().ident.to_string());
            }
            visit::visit_expr_call(self, call);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0.push(call.method.to_string());
            visit::visit_expr_method_call(self, call);
        }
    }
    let file = syn::parse_file(include_str!("../../oauth/schema.rs")).unwrap();
    let functions: Vec<_> = file
        .items
        .into_iter()
        .filter_map(|item| match item {
            syn::Item::Fn(f) if f.sig.ident == "admit_retained_memory_transaction" => Some(f),
            _ => None,
        })
        .collect();
    assert_eq!(functions.len(), 1);
    let first: syn::Stmt = syn::parse_str("hook.enter(tx)?;").unwrap();
    let last: syn::Expr = syn::parse_str("admit_with_runtime_hook(tx, |_| operation(tx))").unwrap();
    let valid = |f: &syn::ItemFn| {
        let mut calls = Calls(Vec::new());
        calls.visit_block(&f.block);
        f.block
            .stmts
            .first()
            .is_some_and(|s| s.to_token_stream().to_string() == first.to_token_stream().to_string())
            && matches!(f.block.stmts.last(),Some(syn::Stmt::Expr(e,None)) if e.to_token_stream().to_string()==last.to_token_stream().to_string())
            && calls
                .0
                .iter()
                .filter(|name| name.as_str() == "enter")
                .count()
                == 1
            && calls
                .0
                .iter()
                .filter(|name| name.as_str() == "admit_with_runtime_hook")
                .count()
                == 1
            && !calls.0.iter().any(|name| {
                matches!(
                    name.as_str(),
                    "admit" | "admit_inner" | "progress_handler" | "configure_connection"
                )
            })
    };
    assert!(valid(&functions[0]));
    let mut no_owner = functions[0].clone();
    no_owner.block.stmts.remove(0);
    assert!(!valid(&no_owner));
    for tail in [
        "admit(tx, |_| operation(tx))",
        "admit_with_runtime_hook(other, |_| operation(tx))",
    ] {
        let mut changed = functions[0].clone();
        *changed.block.stmts.last_mut().unwrap() =
            syn::Stmt::Expr(syn::parse_str(tail).unwrap(), None);
        assert!(!valid(&changed));
    }
    let mut clear = functions[0].clone();
    clear
        .block
        .stmts
        .insert(1, syn::parse_quote!(tx.progress_handler(0,None);));
    assert!(!valid(&clear));
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
            1
        );
        match states {
            (1, 0) => {
                owner.application.require_image(&db, false)?;
                ImageState::Original
            }
            (0, 1) => {
                owner.application.require_image(&db, true)?;
                ImageState::Revoked
            }
            _ => anyhow::bail!("unexpected_staging_state"),
        }
    };
    let memory_revoked = if let Some(db) = owner.state.sql.as_ref() {
        let revoked = db.query_row(
            "SELECT state='revoked' FROM day2_credential_lineages",
            [],
            |r| r.get::<_, bool>(0),
        )?;
        owner.application.require_image(db, revoked)?;
        Some(revoked)
    } else {
        None
    };
    Ok(Observation {
        image,
        complete: owner.state.complete,
        refused: owner.refused,
        creator: owner.state.creator.is_some(),
        sql_held: owner.state.sql.is_some(),
        memory_revoked,
    })
}

#[test]
fn changed_complete_source_selection_refuses_before_creator_and_rolls_back_the_whole_image()
-> Result<()> {
    for fault in 0..3 {
        effects::scope(simulation::World::new(2110 + fault), || -> Result<()> {
            let mut w = world()?;
            let db = Connection::open(w.source.path().join("app.sqlite"))?;
            match fault {
                0 => {
                    db.execute(
                        "UPDATE day2_meta SET value=?1 WHERE key='schema'",
                        [Digest::new(b"foreign-schema").as_str()],
                    )?;
                }
                1 => {
                    db.execute(
                        "UPDATE day2_authority SET artifact_id=?1",
                        [Digest::new(b"foreign-artifact").as_str()],
                    )?;
                }
                _ => {
                    db.execute("UPDATE oauth_connection_slots SET account='foreign-account' WHERE slot='old-slot'", [])?;
                }
            }
            drop(db);
            let bytes = std::fs::read(w.source.path().join("app.sqlite"))?;
            let changed = Digest::new(&bytes);
            // Bind the changed image itself. Digest refusal cannot substitute
            // for comparing its actual schema, authority and OAuth inventory.
            w.owner.state.input.database = changed.clone();
            assert!(execute(&mut w.owner).is_err());
            assert!(w.owner.refused && !w.owner.state.complete);
            assert!(!w.owner.state.directory_may_exist && w.owner.state.creator.is_none());
            assert!(!w.owner.state.target_dir()?.try_exists()?);
            {
                let sql = w
                    .owner
                    .state
                    .sql
                    .as_ref()
                    .context("failed_reset_scratch_missing")?;
                assert!(sql.is_autocommit());
                assert_eq!(
                    sql.query_row("SELECT state FROM day2_credential_lineages", [], |r| r
                        .get::<_, String>(
                        0
                    ))?,
                    "active"
                );
                assert_eq!(
                    sql.query_row(
                        "SELECT status FROM oauth_connection_slots WHERE slot='old-slot'",
                        [],
                        |r| r.get::<_, String>(0)
                    )?,
                    "active"
                );
                assert!(crate::authority_state::current(sql)?.document.enabled);
                assert_eq!(
                    sql.query_row("SELECT count(*) FROM day2_web_sessions", [], |r| r
                        .get::<_, i64>(0))?,
                    1
                );
            }
            assert_eq!(
                Digest::new(&std::fs::read(w.source.path().join("app.sqlite"))?),
                changed
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn malformed_live_and_tombstoned_model_rows_refuse_before_reset_or_creator() -> Result<()> {
    for deleted_at in [0, 101] {
        effects::scope(simulation::World::new(2120), || -> Result<()> {
            let mut w = world()?;
            let db = Connection::open(w.source.path().join("app.sqlite"))?;
            db.execute(
                "UPDATE fixture_business SET value=?1,deleted_at=?2",
                rusqlite::params!["x".repeat(16385), deleted_at],
            )?;
            assert_eq!(
                db.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))?,
                "ok"
            );
            drop(db);
            let expected = Digest::new(&std::fs::read(w.source.path().join("app.sqlite"))?);
            w.owner.state.input.database = expected.clone();
            let error = execute(&mut w.owner).unwrap_err();
            assert_eq!(error.root_cause().to_string(), "invalid field: value");
            assert!(
                w.owner.refused
                    && !w.owner.state.complete
                    && !w.owner.state.directory_may_exist
                    && w.owner.state.creator.is_none()
            );
            let scratch = w
                .owner
                .state
                .sql
                .as_ref()
                .context("model_refusal_scratch_missing")?;
            assert!(
                scratch.is_autocommit()
                    && crate::authority_state::current(scratch)?.document.enabled
            );
            assert_eq!(
                scratch.query_row("SELECT state FROM day2_credential_lineages", [], |r| r
                    .get::<_, String>(
                    0
                ))?,
                "active"
            );
            assert_eq!(
                scratch.query_row(
                    "SELECT status FROM oauth_connection_slots WHERE slot='old-slot'",
                    [],
                    |r| r.get::<_, String>(0)
                )?,
                "active"
            );
            assert_eq!(
                scratch.query_row("SELECT count(*) FROM day2_web_sessions", [], |r| r
                    .get::<_, i64>(0))?,
                1
            );
            assert_eq!(
                Digest::new(&std::fs::read(w.source.path().join("app.sqlite"))?),
                expected
            );
            assert!(execute(&mut w.owner).is_err());
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn actual_staging_owns_one_complete_reset_commit_serialize_and_unconditional_postcheck() {
    use quote::ToTokens as _;
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            self.0.push(call.to_token_stream().to_string());
            visit::visit_expr_call(self, call);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0.push(call.to_token_stream().to_string());
            visit::visit_expr_method_call(self, call);
        }
    }
    fn valid(source: &str) -> bool {
        let file = syn::parse_file(source).unwrap();
        let functions: Vec<_> = file
            .items
            .iter()
            .filter_map(|i| match i {
                syn::Item::Fn(f) if f.sig.ident == "prepare_image" => Some(f),
                _ => None,
            })
            .collect();
        if functions.len() != 1 {
            return false;
        }
        let tail: syn::Block = syn::parse_quote!({
            drop(loan);
            let post = owner.local_sql();
            let reset = reset?;
            post?;
            close_sql_context(owner)?;
            Ok(reset)
        });
        if functions[0].block.stmts.len() < tail.stmts.len()
            || !functions[0]
                .block
                .stmts
                .iter()
                .rev()
                .take(tail.stmts.len())
                .zip(tail.stmts.iter().rev())
                .all(|(actual, expected)| {
                    actual.to_token_stream().to_string() == expected.to_token_stream().to_string()
                })
        {
            return false;
        }
        let mut calls = Calls(Vec::new());
        calls.visit_block(&functions[0].block);
        let ordered = [
            "MemoryAdmission :: configure (db)",
            "db . deserialize_read_exact (MAIN_DB , & image [..] , image . len () , false)",
            "memory . begin ()",
            "current . application (& tx)",
            "application :: reset_in (& tx , & hook , & selected , & ns , epoch)",
            "tx . commit ()",
            "db . serialize (MAIN_DB)",
            "drop (loan)",
            "owner . local_sql ()",
            "close_sql_context (owner)",
        ];
        let mut previous = None;
        for expected in ordered {
            let all: Vec<_> = calls
                .0
                .iter()
                .enumerate()
                .filter(|(_, c)| c.as_str() == expected)
                .map(|(i, _)| i)
                .collect();
            let expected_count = if expected == "owner . local_sql ()" {
                2
            } else {
                1
            };
            if all.len() != expected_count {
                return false;
            }
            let positions: Vec<_> = all
                .into_iter()
                .filter(|i| previous.is_none_or(|last| last < *i))
                .collect();
            if positions.len() != 1 || previous.is_some_and(|last| last >= positions[0]) {
                return false;
            }
            previous = Some(positions[0]);
        }
        calls
            .0
            .iter()
            .filter(|c| c.as_str() == "owner . local_sql ()")
            .count()
            == 2
            && !calls.0.iter().any(|c| {
                c.contains("stage_reset")
                    || c.contains("inspect_source")
                    || c.contains("Transaction :: new_unchecked")
            })
    }
    let source = include_str!("../restore_staging.rs");
    assert!(valid(source));
    for (from, to) in [
        (
            "let memory = MemoryAdmission::configure(db)?;",
            "let memory = MemoryAdmission::configure(foreign)?;",
        ),
        (
            "let (tx, hook) = memory.begin()?;",
            "let (tx, hook) = memory.begin()?; let repeated = memory.begin()?;",
        ),
        (
            "application::reset_in(&tx, &hook, &selected, &ns, epoch)?",
            "restore::stage_reset(&tx, &ns, epoch)?",
        ),
        (
            "application::reset_in(&tx, &hook, &selected, &ns, epoch)?",
            "{ tx.commit()?; application::reset_in(&tx, &hook, &selected, &ns, epoch)? }",
        ),
        (
            "let selected = current.application(&tx)?;",
            "let selected = current.foreign_application(&tx)?;",
        ),
        ("let post = owner.local_sql();", "let post = Ok(());"),
        (
            "let post = owner.local_sql();",
            "let post = if reset.is_ok() { owner.local_sql() } else { Ok(()) };",
        ),
        (
            "close_sql_context(owner)?;",
            "Ok::<(), anyhow::Error>(())?;",
        ),
        ("drop(loan);", "drop(unrelated);"),
        ("drop(loan);", "drop(loan); let reset=reset?;"),
    ] {
        assert_eq!(source.matches(from).count(), 1);
        assert!(!valid(&source.replacen(from, to, 1)), "{from} -> {to}");
    }
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
                            Digest::new(&std::fs::read(w.source.path().join("app.sqlite"))?),
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
                source: w.source_path()?,
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
                w.source_path()?,
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
                w.owner.application.require_image(&db, true)?;
                assert!(crate::store::require_no_managed_credential_restore_state(&db).is_err());
            }
            if point == Point::FirstWrite {
                assert!(
                    path.metadata()?.len()
                        < std::fs::metadata(w.source.path().join("app.sqlite"))?.len()
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
                Digest::new(&std::fs::read(w.source.path().join("app.sqlite"))?),
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
        SOURCE_SWAP.with(|s| *s.borrow_mut() = Some(w.source.path().join("app.sqlite")));
        TARGET_SWAP.with(|s| s.set(true));
        let result = execute(&mut w.owner)?;
        assert_eq!(result.reset.credentials.newly_revoked, 1);
        assert_eq!(
            Digest::new(&std::fs::read(w.source.path().join("app.sqlite"))?),
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
        w.owner.application.require_image(&target, true)?;
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
fn source_path_replacement_before_execution_cannot_replace_the_owned_input_descriptor() -> Result<()>
{
    effects::scope(simulation::World::new(2099), || -> Result<()> {
        let mut w = world()?;
        let source = w.source.path().join("app.sqlite");
        std::fs::rename(&source, source.with_extension("retained"))?;
        std::fs::write(&source, b"wrong-world")?;
        let projection = execute(&mut w.owner)?;
        assert!(w.owner.state.complete);
        assert_eq!(projection.reset.credentials.newly_revoked, 1);
        assert_eq!(std::fs::read(&source)?, b"wrong-world");
        assert_eq!(
            Digest::new(&std::fs::read(w.owner.state.target_path()?)?),
            projection.image
        );
        Ok(())
    })
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

#[test]
fn production_staging_refuses_a_public_root_without_repairing_it() -> Result<()> {
    let mut w = world()?;
    let root = w.owner.state.root_path.clone();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))?;
    assert!(execute(&mut w.owner).is_err());
    assert!(w.owner.refused);
    assert_eq!(std::fs::metadata(&root)?.mode() & 0o777, 0o755);
    assert!(!w.owner.state.target_dir()?.try_exists()?);
    Ok(())
}

#[test]
fn native_archive_entry_consumes_genuine_executor_and_exposes_no_frame_or_parts() {
    use quote::ToTokens;
    fn valid(source: &str) -> bool {
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let mut definition = None;
        let mut methods = Vec::new();
        for item in file.items {
            match item {
                syn::Item::Struct(item) if item.ident == "PreparedNativeRestoreArchive" => {
                    definition = Some(item)
                }
                syn::Item::Impl(item) if matches!(&*item.self_ty,syn::Type::Path(path) if path.path.is_ident("PreparedNativeRestoreArchive")||path.path.segments.last().is_some_and(|s|s.ident=="PreparedNativeRestoreArchive")) =>
                {
                    if item.trait_.is_some() {
                        return false;
                    }
                    for method in item.items {
                        if let syn::ImplItem::Fn(method) = method {
                            methods.push(method);
                        }
                    }
                }
                _ => {}
            }
        }
        let Some(definition) = definition else {
            return false;
        };
        if definition.fields.len() != 1
            || definition
                .fields
                .iter()
                .any(|f| !matches!(f.vis, syn::Visibility::Inherited))
            || !definition.attrs.iter().all(|a| a.path().is_ident("doc"))
        {
            return false;
        }
        let field = definition.fields.iter().next().unwrap();
        let expected: syn::Type =
            syn::parse_quote!(archive::ArchivePrepared<'metadata, 'storage, 'role>);
        if field.ident.as_ref().is_none_or(|i| i != "prepared")
            || field.ty.to_token_stream().to_string() != expected.to_token_stream().to_string()
        {
            return false;
        }
        if methods.len() != 1 {
            return false;
        }
        let mut method = methods.remove(0);
        let mut expected: syn::ImplItemFn = syn::parse_quote! {
            pub(in crate::security_epoch) fn capture(
                executor:crate::security_epoch::bootstrap::AuthenticatedRestoreExecution<'metadata,'storage,'role>,
                directory:&std::path::Path,
                intent:&crate::security_epoch::kernel::restore::Intent,
            )->Result<Self> {
                let prepared=archive::NativeArchive::capture(executor,directory,intent)?.prepare()?;
                Ok(Self {prepared})
            }
        };
        fn normalize_executor_generic_separator(method: &mut syn::ImplItemFn) -> bool {
            let Some(syn::FnArg::Typed(arg)) = method.sig.inputs.first_mut() else {
                return false;
            };
            let syn::Type::Path(path) = &mut *arg.ty else {
                return false;
            };
            let Some(segment) = path.path.segments.last_mut() else {
                return false;
            };
            let syn::PathArguments::AngleBracketed(args) = &mut segment.arguments else {
                return false;
            };
            args.args = args.args.clone().into_iter().collect();
            true
        }
        normalize_executor_generic_separator(&mut method)
            && normalize_executor_generic_separator(&mut expected)
            && method.to_token_stream().to_string() == expected.to_token_stream().to_string()
    }
    let source = include_str!("../restore_staging.rs");
    assert!(valid(source));
    let optional = "'role,\n        >";
    assert_eq!(source.matches(optional).count(), 1);
    assert!(valid(&source.replacen(optional, "'role\n        >", 1)));
    for (before, after) in [
        (
            "archive::NativeArchive::capture(executor, directory, intent)?.prepare()?",
            "other.prepare()?",
        ),
        (
            "capture(executor, directory, intent)",
            "capture(other, directory, intent)",
        ),
        (
            "capture(executor, directory, intent)",
            "capture(executor, other, intent)",
        ),
        (
            "capture(executor, directory, intent)",
            "capture(executor, directory, other)",
        ),
        ("?.prepare()?", "?.prepare().unwrap()"),
        (
            "prepared: archive::ArchivePrepared",
            "pub(crate) prepared: archive::ArchivePrepared",
        ),
    ] {
        assert_eq!(source.matches(before).count(), 1, "{before}");
        assert!(!valid(&source.replacen(before, after, 1)), "{after}");
    }
    let getter = format!(
        "{source}\nimpl PreparedNativeRestoreArchive<'_, '_, '_> {{fn raw(&self)->&archive::ArchivePrepared<'_, '_, '_>{{&self.prepared}}}}"
    );
    assert!(!valid(&getter));
}
