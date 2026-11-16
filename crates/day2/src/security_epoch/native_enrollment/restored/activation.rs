//! Consume the frozen App file only after its own authenticated current read.
//! Keep the actual first SQLite connection through acknowledgement and release.
//! These resources do not construct an ordinary role or serving owner.
use super::super::{RestoredCurrentPeerPort, RestoredPeerSource};
use super::{
    AcceptedRestoredApp, ActiveRestoredFile, ActiveRestoredReadIdentity, AppInstalledHandoff,
    AppIssuerConfirmation, AppPreparedHandoff, CapturedRestoredFile, DecisionReceiveAttempt,
    PreparedConfirmedRestoredApp, ReceivedDecisionRestoredApp, ReceivedRoleRestoredApp,
    ReleasedRestoredApp, RestoredActiveKeeperInput, RestoredAppHistory, RestoredAppKeeper,
    RestoredConfiguredInput, RestoredHistoryLoan, RestoredKeeperBirth, RestoredObservation,
    RestoredObservationOwner, RestoredReadIdentity, RestoredRuntimeBirth,
    RestoredWriterReadPending, RoleReceiveAttempt,
};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    restore_peer_wire::RestoreBody,
    storage_peer_wire::{Body, Message},
};
use crate::security_epoch::{
    native_clock::NativeAcquisition, native_enrollment::EnrolledRoleStage,
};
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::ensure;

impl RestoredConfiguredInput {
    pub(in crate::security_epoch::native_enrollment) fn enter_writer_phase(
        mut self,
    ) -> Result<RestoredActiveKeeperInput> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut self;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            // The real App performs the fixed ten-record read itself. A
            // Controller message or an earlier returned value cannot replace it.
            self.input.owner = self.input.owner.reobserve_writer()?;
            self.check()?;
            // No I/O/effect/wait occurs between the full frozen check and these
            // moves. Preserve the SAME original, HTTP identity, peer receipts,
            // selected creator and every actual held descriptor.
            let active = ActiveRestoredReadIdentity::consume(self.input.owner)?;
            Ok(RestoredActiveKeeperInput {
                owner: active,
                artifact: self.input.artifact,
                installed: self.input.installed,
                configuration: self.configuration,
            })
        }
    }
}

impl ActiveRestoredReadIdentity {
    fn consume(owner: RestoredReadIdentity) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _pending: RestoredWriterReadPending = owner.owner;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let RestoredReadIdentity {
                owner,
                original,
                http,
                credential,
            } = owner;
            let RestoredWriterReadPending {
                captured,
                activation,
            } = owner;
            let captured = ActiveRestoredFile::consume(captured)?;
            let mut active = Self {
                captured,
                activation,
                original,
                http,
                credential,
                local_only: std::marker::PhantomData,
            };
            active.check()?;
            Ok(active)
        }
    }

    pub(super) fn refuse(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.captured.refused = true;
            self.captured.peer.refused = true;
            self.captured.peer.process.receiver.refuse();
            self.original.refuse();
        }
    }

    pub(super) fn check(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested = self.captured.check();
            let checked = self.original.remaining().map(|_| ());
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            requested?;
            checked
        }
    }

    /// A fixed current ten-record read under the SAME actual App identity and
    /// original after the file becomes mutable. No frozen-image check, new
    /// authentication or replacement clock is substituted for that original.
    pub(super) fn reobserve_writer(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use crate::security_epoch::transport::Route;
            use anyhow::ensure;
            self.check()?;
            let requested: Result<()> = (|| {
                let holder = self.captured.peer.local.holder_data()?;
                let names = crate::security_epoch::firestore::RestoreWriterPeerRead::new(
                    &self.captured.peer.process.receiver.policy.store,
                    &self.captured.peer.projection,
                    &self.activation,
                    &holder,
                )?;
                ensure!(
                    self.http
                        .matches(&Route::EpochRead, &names.endpoint_data())?,
                    "restore_writer_reader_endpoint_changed"
                );
                let body = names.strong_body_data()?;
                self.check()?;
                let authorization = self.credential.authorization()?;
                let response = self.http.request(
                    Route::EpochRead,
                    &authorization,
                    Some(&body),
                    &mut self.original,
                );
                let checked = self.check();
                let response = zeroize::Zeroizing::new(response?);
                checked?;
                names.validate_response_data(&response)
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            requested?;
            checked
        }
    }
}

impl<'borrow> RestoredObservation<'borrow> {
    pub(super) fn frozen(owner: &'borrow mut RestoredReadIdentity) -> Self {
        Self {
            owner: RestoredObservationOwner::Frozen(owner),
        }
    }

    pub(super) fn active(owner: &'borrow mut ActiveRestoredReadIdentity) -> Self {
        Self {
            owner: RestoredObservationOwner::Active(owner),
        }
    }

    pub(super) fn check(&mut self) -> Result<()> {
        match &mut self.owner {
            RestoredObservationOwner::Frozen(owner) => owner.check(),
            RestoredObservationOwner::Active(owner) => owner.check(),
        }
    }

    pub(super) fn refuse(&mut self) {
        match &mut self.owner {
            RestoredObservationOwner::Frozen(owner) => owner.refuse(),
            RestoredObservationOwner::Active(owner) => owner.refuse(),
        }
    }
}

impl ActiveRestoredFile {
    fn consume(captured: CapturedRestoredFile) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = captured;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let file = Self {
                peer: captured.peer,
                root: captured.root,
                private: captured.private,
                directory: captured.directory,
                file: captured.file,
                root_stamp: captured.root_stamp,
                private_stamp: captured.private_stamp,
                directory_stamp: captured.directory_stamp,
                file_stamp: captured.file_stamp,
                component: captured.component,
                refused: captured.refused,
                local_only: captured.local_only,
            };
            // Only the old immutable image bytes are dropped. Every real
            // descriptor moved to this resource owner; no SQLite exists yet.
            drop(captured.image);
            Ok(file)
        }
    }
}

#[cfg(test)]
mod tests {
    use quote::ToTokens;

    fn tokens(source: &str) -> String {
        fn without_commas(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            stream
                .into_iter()
                .filter_map(|token| match token {
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => None,
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '?' => {
                        Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                            '?',
                            proc_macro2::Spacing::Alone,
                        )))
                    }
                    proc_macro2::TokenTree::Group(group) => Some(proc_macro2::TokenTree::Group(
                        proc_macro2::Group::new(group.delimiter(), without_commas(group.stream())),
                    )),
                    other => Some(other),
                })
                .collect()
        }
        without_commas(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
    }

    fn actual_entry() -> String {
        actual_method("RestoredConfiguredInput", "enter_writer_phase")
    }

    fn actual_method(owner_name: &str, name: &str) -> String {
        let file = syn::parse_file(include_str!("activation.rs")).unwrap();
        file.items
            .into_iter()
            .find_map(|item| {
                let syn::Item::Impl(owner) = item else {
                    return None;
                };
                if !matches!(&*owner.self_ty,syn::Type::Path(path) if path.qself.is_none()
                && path.path.segments.len()==1 && path.path.segments[0].ident==owner_name)
                {
                    return None;
                }
                owner.items.into_iter().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == name => {
                        Some(tokens(&method.into_token_stream().to_string()))
                    }
                    _ => None,
                })
            })
            .unwrap()
    }

    fn entry_is_closed(body: &str) -> bool {
        let parts = [
            "self.check()?;",
            "self.input.owner=self.input.owner.reobserve_writer()?;",
            "self.check()?;",
            "let active=ActiveRestoredReadIdentity::consume(self.input.owner)?;",
            "RestoredActiveKeeperInput",
        ];
        let mut remaining = body;
        for part in parts {
            let part = tokens(part);
            let Some(at) = remaining.find(&part) else {
                return false;
            };
            remaining = &remaining[at + part.len()..];
        }
        body.matches(&tokens("self.input.owner.reobserve_writer()"))
            .count()
            == 1
            && ![
                "NativeAcquisition::begin",
                "NativeAcquisition::capture",
                "Connection::open",
                "begin_runtime_database",
                "send_keeper_ack",
            ]
            .iter()
            .any(|part| body.contains(&tokens(part)))
    }

    #[test]
    fn actual_active_transition_performs_own_read_moves_original_and_cannot_open_or_ack() {
        assert_eq!(tokens("self.check()?;"), tokens("self.check() ? ;"));
        assert_ne!(tokens("self.check()?;"), tokens("other.check()?;"));
        let body = actual_entry();
        assert!(entry_is_closed(&body));
        for (before, after) in [
            (
                "self.input.owner=self.input.owner.reobserve_writer()?;",
                "let _lookalike=();",
            ),
            (
                "ActiveRestoredReadIdentity::consume(self.input.owner)?;",
                "ActiveRestoredReadIdentity::consume(other.owner)?;",
            ),
        ] {
            let before = tokens(before);
            let after = tokens(after);
            assert_eq!(body.matches(&before).count(), 1);
            assert!(!entry_is_closed(&body.replacen(&before, &after, 1)));
        }
    }

    fn identity_is_moved(body: &str) -> bool {
        body.contains(&tokens("let RestoredReadIdentity {owner,original,http,credential}=owner;"))
            && body.contains(&tokens("let RestoredWriterReadPending {captured,activation}=owner;"))
            && body.contains(&tokens("let captured=ActiveRestoredFile::consume(captured)?;"))
            && body.contains(&tokens("let mut active=Self {captured,activation,original,http,credential,local_only:std::marker::PhantomData};"))
            && body.contains(&tokens("active.check()?;"))
            && !body.contains(&tokens("NativeAcquisition::"))
    }

    fn files_are_moved(body: &str) -> bool {
        [
            "peer",
            "root",
            "private",
            "directory",
            "file",
            "root_stamp",
            "private_stamp",
            "directory_stamp",
            "file_stamp",
            "component",
            "refused",
            "local_only",
        ]
        .iter()
        .all(|name| {
            body.matches(&tokens(&format!("{name}:captured.{name}")))
                .count()
                == 1
        }) && body.matches("drop").count() == 1
            && body.contains(&tokens("drop(captured.image);"))
            && !body.contains("try_clone")
            && !body.contains(&tokens("File::open"))
    }

    #[test]
    fn actual_private_resource_moves_preserve_original_and_never_close_raw_main() {
        let identity = actual_method("ActiveRestoredReadIdentity", "consume");
        assert!(identity_is_moved(&identity));
        for (before, after) in [
            (
                "activation,original,http,credential,",
                "activation,original:new_original,http,credential,",
            ),
            ("active.check()?;", "let _unchecked=();"),
        ] {
            let before = tokens(before);
            assert_eq!(identity.matches(&before).count(), 1);
            assert!(!identity_is_moved(&identity.replacen(
                &before,
                &tokens(after),
                1
            )));
        }
        let file = actual_method("ActiveRestoredFile", "consume");
        assert!(files_are_moved(&file));
        // All descriptor/anchor fields move verbatim; no clone, reopen or
        // descriptor close can be smuggled into this private conversion.
        for name in [
            "peer",
            "root",
            "private",
            "directory",
            "file",
            "root_stamp",
            "private_stamp",
            "directory_stamp",
            "file_stamp",
            "component",
            "refused",
            "local_only",
        ] {
            let before = tokens(&format!("{name}:captured.{name}"));
            assert_eq!(file.matches(&before).count(), 1);
            let mutant = file.replacen(&before, &tokens(&format!("{name}:other.{name}")), 1);
            assert!(!files_are_moved(&mutant));
        }
    }

    #[test]
    fn actual_material_observation_borrows_only_the_real_frozen_or_active_owner_and_checks_both() {
        for (method, variant) in [("frozen", "Frozen"), ("active", "Active")] {
            let body = actual_method("RestoredObservation", method);
            let expected = tokens(&format!(
                "Self {{owner:RestoredObservationOwner::{variant}(owner)}}"
            ));
            assert!(body.contains(&expected));
            assert!(!body.contains("clone") && !body.contains("NativeAcquisition"));
            let substituted = body.replacen(
                &expected,
                &tokens(&format!(
                    "Self {{owner:RestoredObservationOwner::{variant}(other)}}"
                )),
                1,
            );
            assert!(!substituted.contains(&expected));
        }
        let body = actual_method("RestoredObservation", "check");
        for variant in ["Frozen", "Active"] {
            let expected = tokens(&format!(
                "RestoredObservationOwner::{variant}(owner)=>owner.check()"
            ));
            assert!(body.contains(&expected));
            let bypass = body.replacen(
                &expected,
                &tokens(&format!(
                    "RestoredObservationOwner::{variant}(_owner)=>Ok(())"
                )),
                1,
            );
            assert!(!bypass.contains(&expected));
        }
        assert!(body.contains(&tokens("match &mut self.owner")));
    }

    fn active_read_is_bound(body: &str) -> bool {
        let mut rest = body;
        for part in [
            "RestoreWriterPeerRead::new",
            "self.http.matches",
            "self.check()?;",
            "let authorization=self.credential.authorization()?;",
            "let response=self.http.request(Route::EpochRead,&authorization,Some(&body),&mut self.original);",
            "let checked=self.check();",
            "let response=zeroize::Zeroizing::new(response?);checked?;",
            "names.validate_response_data(&response)",
            "let checked=self.check();",
            "self.refuse();",
            "requested?;checked",
        ] {
            let part = tokens(part);
            let Some(at) = rest.find(&part) else {
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        body.matches(&tokens("self.http.request")).count() == 1
            && ![
                "NativeAcquisition::begin",
                "authenticate_read",
                "check_image",
                "Route::EpochCommit",
            ]
            .iter()
            .any(|part| body.contains(&tokens(part)))
    }

    #[test]
    fn actual_active_writer_read_keeps_the_original_and_checks_after_http_or_decode_error() {
        let actual = actual_method("ActiveRestoredReadIdentity", "reobserve_writer");
        assert!(active_read_is_bound(&actual));
        for (before, after) in [
            ("&mut self.original", "&mut new_original"),
            ("Route::EpochRead", "Route::EpochCommit"),
            (
                "let checked=self.check();",
                "let checked:Result<()>=Ok(());",
            ),
            (
                "let response=zeroize::Zeroizing::new(response?);checked?;",
                "checked?;let response=zeroize::Zeroizing::new(response?);",
            ),
            ("names.validate_response_data(&response)", "Ok(())"),
        ] {
            let before = tokens(before);
            assert!(actual.contains(&before));
            assert!(!active_read_is_bound(&actual.replacen(
                &before,
                &tokens(after),
                1
            )));
        }
    }
}

impl RestoredActiveKeeperInput {
    pub(in crate::security_epoch::native_enrollment) fn create_keeper(
        mut self,
    ) -> Result<RestoredAppKeeper> {
        self.check()?;
        let (path, scope, app) = self.keeper_birth_data()?;
        let artifact = &self.artifact;
        let mut birth = RestoredKeeperBirth {
            owner: &mut self.owner,
            artifact,
            installed: &self.installed,
            configuration: &self.configuration,
            path: path.clone(),
            scope: scope.clone(),
            app,
            completed: false,
        };
        let mut requested =
            crate::store::NativeSqliteKeeper::create_restored(&mut birth, &path, artifact, &scope);
        let checked = birth.check();
        if requested.is_err() || checked.is_err() {
            if let Ok(keeper) = &mut requested {
                keeper.refuse();
            }
            birth.owner.refuse();
        }
        // On post failure this local keeper closes before the actual
        // borrowed App/raw MAIN can drop. A lost birth cannot be retried.
        let keeper = requested?;
        checked?;
        birth.completed = true;
        drop(birth);
        Ok(RestoredAppKeeper {
            keeper,
            input: self,
        })
    }
}

impl RestoredActiveKeeperInput {
    pub(super) fn keeper_birth_data(&self) -> Result<(std::path::PathBuf, String, String)> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let path = std::path::Path::new("/state/day2-native")
                .join(&self.owner.captured.component)
                .join("app.sqlite");
            let scope = &self.owner.captured.peer.process.receiver.policy.store.scope;
            let app = scope.app.as_str().to_owned();
            let scope = format!(
                "{}/{}/{}",
                scope.installation.as_str(),
                scope.environment.as_str(),
                app
            );
            Ok((path, scope, app))
        }
    }
}

impl RestoredKeeperBirth<'_> {
    pub(crate) fn before_open(
        &mut self,
        path: &std::path::Path,
        artifact: &crate::artifact::LoadedArtifact,
        scope: &str,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, artifact, scope);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested: Result<()> = (|| {
                ensure!(
                    path == self.path
                        && scope == self.scope
                        && std::ptr::eq(artifact, self.artifact),
                    "restore_keeper_selected_material_substituted"
                );
                self.owner.reobserve_writer()?;
                self.check()?;
                let absent = crate::store::require_unopened_native_sqlite(
                    &self.owner.captured.directory,
                    crate::store::SqliteKeeperLayout::Restored,
                );
                let checked = self.check();
                absent?;
                checked?;
                // This is the final image read at the actual OPEN boundary,
                // after all configuration/artifact/provider work above.
                self.owner.captured.require_unopened_image()
            })();
            let checked = self.owner.check();
            if requested.is_err() || checked.is_err() {
                self.owner.refuse();
            }
            requested?;
            checked
        }
    }

    /// Pin the first actual connection BEFORE any configuration/schema/WAL.
    pub(crate) fn require_opened(&mut self, connection: &rusqlite::Connection) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = connection;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested = crate::store::NativeSqliteKeeper::require_creator_main(
                connection,
                &self.owner.captured.file,
            );
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.owner.refuse();
            }
            requested?;
            checked
        }
    }

    pub(crate) fn check_database(&mut self, connection: &rusqlite::Connection) -> Result<()> {
        // Refuse an already-open SQL unit before native/file work. This pure
        // precondition preserves its primary error and needs no IO to refuse.
        let closed: Result<()> = (|| {
            anyhow::ensure!(
                connection.is_autocommit(),
                "restore_keeper_sql_unit_still_open"
            );
            Ok(())
        })();
        if closed.is_err() {
            self.owner.refuse();
        }
        closed?;
        self.check()?;
        let requested = (|| {
            anyhow::ensure!(
                connection.is_autocommit(),
                "restore_keeper_sql_unit_still_open"
            );
            crate::store::NativeSqliteKeeper::require_original_main(
                connection,
                &self.owner.captured.file,
            )
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.owner.refuse();
        }
        requested?;
        checked
    }

    /// Provider work is outside EVERY SQL unit, while the SAME first
    /// connection remains owned. It never becomes a business transaction.
    pub(crate) fn reobserve_database(&mut self, connection: &rusqlite::Connection) -> Result<()> {
        self.check_database(connection)?;
        let requested = self.owner.reobserve_writer();
        let checked = self.check_database(connection);
        if requested.is_err() || checked.is_err() {
            self.owner.refuse();
        }
        requested?;
        checked
    }

    pub(crate) fn require_keeper(
        &mut self,
        keeper: &mut crate::store::NativeSqliteKeeper,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = keeper;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested = keeper.check(&self.owner.captured.directory, &self.owner.captured.file);
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                keeper.refuse();
                self.owner.refuse();
            }
            requested?;
            checked
        }
    }
}

impl RestoredAppKeeper {
    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.input.check()?;
            let requested = self.keeper.check(
                &self.input.owner.captured.directory,
                &self.input.owner.captured.file,
            );
            let checked = self.input.check();
            if requested.is_err() || checked.is_err() {
                self.keeper.refuse();
                self.input.owner.refuse();
            }
            requested?;
            checked
        }
    }

    /// Consume the actual keeper before any fallible ACK/sign/send/wait. A
    /// caught unwind or lost result cannot retrieve it for another attempt.
    /// The FIRST connection remains held through every IO and all posts.
    pub(in crate::security_epoch::native_enrollment) fn acknowledge(
        mut self,
    ) -> Result<ReleasedRestoredApp> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut self;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            // Both closed operations independently check/refuse after EVERY
            // result. No IO, effect or wait intervenes after the final released
            // post and this resource move; no extra epoch read is invented.
            self.send_ack()?;
            self.receive_release()?;
            Ok(ReleasedRestoredApp { keeper: self })
        }
    }

    fn reobserve(&mut self) -> Result<()> {
        self.check()?;
        // keeper.check above proves the connection is outside EVERY SQL unit.
        let requested = self.input.owner.reobserve_writer();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.keeper.refuse();
            self.input.owner.refuse();
        }
        requested?;
        checked
    }

    fn send_ack(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.reobserve()?;
            let requested: Result<()> = (|| {
                let exchange = self.input.owner.captured.peer.exchange.digest()?;
                let activation = day2_capabilities::Digest::of(&self.input.owner.activation)?;
                let cohort = self.keeper.cohort_data()?;
                let body = Body::Restore {
                    payload: RestoreBody::ActivatedAck {
                        exchange,
                        activation,
                        cohort,
                    },
                };
                let sender = self.input.owner.captured.peer.local.digest()?;
                self.check()?;
                let signed = self
                    .input
                    .owner
                    .captured
                    .peer
                    .process
                    .receiver
                    .key
                    .sign("restored-storage-message", &(&sender, &body));
                let checked = self.check();
                let signature = signed?;
                checked?;
                let sent = {
                    let peer = &mut self.input.owner.captured.peer;
                    peer.channel.send_restore(
                        &Message {
                            sender,
                            body,
                            signature,
                        },
                        &mut peer.process,
                    )
                };
                let checked = self.check();
                sent?;
                checked
            })();
            let checked = self.reobserve();
            if requested.is_err() || checked.is_err() {
                self.keeper.refuse();
                self.input.owner.refuse();
            }
            requested?;
            checked
        }
    }

    fn receive_release(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested: Result<()> = (|| {
                let received = {
                    let peer = &mut self.input.owner.captured.peer;
                    peer.channel.receive_restore(&mut peer.process)
                };
                let checked = self.check();
                let (message, mut receipt) = received?;
                checked?;
                let peer = &mut self.input.owner.captured.peer;
                receipt.bind(&message, &peer.controller, &mut peer.process)?;
                let Body::Restore {
                    payload:
                        RestoreBody::Released {
                            exchange,
                            activation,
                        },
                } = message.body
                else {
                    anyhow::bail!("restore_peer_expected_keeper_release");
                };
                ensure!(
                    exchange == peer.exchange.digest()?
                        && activation
                            == day2_capabilities::Digest::of(&self.input.owner.activation)?,
                    "restore_peer_keeper_release_changed"
                );
                ensure!(
                    peer.receipts.len() == 4 && peer.channel.transcript.complete(),
                    "restore_peer_keeper_release_order"
                );
                peer.receipts.push(receipt);
                Ok(())
            })();
            let checked = self.reobserve();
            if requested.is_err() || checked.is_err() {
                self.keeper.refuse();
                self.input.owner.refuse();
            }
            requested?;
            checked
        }
    }
}

impl ReleasedRestoredApp {
    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        self.keeper.reobserve()
    }

    pub(in crate::security_epoch::native_enrollment) fn receive_role_handoff(
        mut self,
    ) -> Result<ReceivedRoleRestoredApp> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut self;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use super::super::handshake::{Frame, Protocol, Step};
            use anyhow::Context;
            let (receipt, completion, role_transcript) = {
                let mut attempt = RoleReceiveAttempt {
                    keeper: &mut self.keeper,
                    transcript: None,
                    receipt: None,
                    done: false,
                };
                attempt.fresh()?;
                let requested: Result<super::super::protocol::SignedRestoreIssuerCompletion> =
                    (|| {
                        let message = attempt.receive_role_packet()?;
                        let completion = attempt.authenticate_completion(&message)?;
                        // The negative owner is already armed before EITHER actual
                        // original is reduced. No origin, time or refusal is reset.
                        attempt.narrow_originals(&completion)?;
                        Ok(completion)
                    })();
                let checked = attempt.fresh();
                if requested.is_err() || checked.is_err() {
                    attempt.refuse();
                }
                let completion = requested?;
                checked?;
                attempt.require_completion(&completion)?;
                let observation = attempt.observation()?;
                let transcript = attempt
                    .transcript
                    .as_mut()
                    .context("restore_role_receive_transcript_missing")?;
                transcript.narrow_role_receive(observation.clone())?;
                transcript.delivered(
                    Frame {
                        protocol: Protocol::RestoredRole,
                        step: Step::RoleReady,
                        sequence: None,
                    },
                    observation,
                )?;
                ensure!(transcript.complete(), "restore_role_receive_incomplete");
                let role_transcript = attempt
                    .transcript
                    .take()
                    .context("restore_role_receive_transcript_missing")?;
                let receipt = attempt
                    .receipt
                    .take()
                    .context("restore_role_receive_receipt_missing")?;
                attempt.done = true;
                (receipt, completion, role_transcript)
            };
            // No I/O/effect/wait intervenes after the final actual post and
            // this sole result construction. No SQLite connection is reopened.
            Ok(ReceivedRoleRestoredApp {
                keeper: self.keeper,
                receipt,
                completion,
                role_transcript,
            })
        }
    }
}

impl RoleReceiveAttempt<'_> {
    pub(super) fn refuse(&mut self) {
        self.keeper.keeper.refuse();
        self.keeper.input.owner.refuse();
        #[cfg(target_os = "linux")]
        if let Some(transcript) = &mut self.transcript {
            transcript.refuse();
        }
    }

    fn check_prior_keeper(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        ensure!(
            self.keeper.input.owner.captured.peer.receipts.len() == 5
                && self
                    .keeper
                    .input
                    .owner
                    .captured
                    .peer
                    .channel
                    .transcript
                    .complete(),
            "restore_role_receive_previous_incomplete"
        );
        self.keeper.check()
    }

    pub(super) fn local_check(&mut self) -> Result<()> {
        let requested = self.check_prior_keeper();
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        #[cfg(target_os = "linux")]
        let checked = match &mut self.receipt {
            Some(receipt) => receipt.live(&mut self.keeper.input.owner.captured.peer.process),
            None => Ok(()),
        };
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    fn fresh(&mut self) -> Result<()> {
        let requested = self.keeper.reobserve();
        let checked = self.local_check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(super) fn observation(&mut self) -> Result<super::super::handshake::Observation> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.keeper.input.owner.original.remaining()?;
            let peer = &mut self.keeper.input.owner.captured.peer;
            peer.process.receiver.original.remaining()?;
            let (domain, origin, deadline, now) = peer
                .process
                .receiver
                .original
                .historical_interval_observation();
            let (read_domain, read_origin, read_deadline, read_now) = self
                .keeper
                .input
                .owner
                .original
                .historical_interval_observation();
            ensure!(
                read_domain == domain && read_origin == origin,
                "restore_role_receive_original_join_changed"
            );
            Ok(super::super::handshake::Observation {
                domain,
                origin,
                deadline: deadline.min(read_deadline),
                now: now.max(read_now),
            })
        }
    }

    fn completion_data(&mut self) -> Result<super::super::protocol::RestoreIssuerCompletionData> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let peer = &self.keeper.input.owner.captured.peer;
            Ok(super::super::protocol::RestoreIssuerCompletionData {
                frozen: peer.local.authorization.statement.data.frozen.clone(),
                authorization: peer.local.authorization.digest_data()?,
                app: peer.local.digest()?,
                activation: day2_capabilities::Digest::of(&self.keeper.input.owner.activation)?,
                cohort: self.keeper.keeper.cohort_data()?,
            })
        }
    }

    fn authenticate_completion(
        &mut self,
        message: &super::super::storage_peer_wire::Message,
    ) -> Result<super::super::protocol::SignedRestoreIssuerCompletion> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = message;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            self.local_check()?;
            {
                let peer = &mut self.keeper.input.owner.captured.peer;
                self.receipt
                    .as_mut()
                    .context("restore_role_receive_receipt_missing")?
                    .bind(message, &peer.controller, &mut peer.process)?;
            }
            self.local_check()?;
            let expected = self.completion_data()?;
            let peer = &mut self.keeper.input.owner.captured.peer;
            let super::super::storage_peer_wire::Body::Restore { payload } = &message.body else {
                anyhow::bail!("restore_role_receive_message_kind");
            };
            let completion = payload
                .role_ready_data(
                    &peer.exchange.digest()?,
                    &expected,
                    &peer.process.receiver.policy,
                    &peer.process.certificate,
                    &peer.local,
                    peer.process.receiver.original.sample()?.elapsed,
                )?
                .clone();
            Ok(completion)
        }
    }

    fn require_completion(
        &mut self,
        completion: &super::super::protocol::SignedRestoreIssuerCompletion,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = completion;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested = (|| {
                let expected = self.completion_data()?;
                let peer = &mut self.keeper.input.owner.captured.peer;
                completion.verify_data(
                    &peer.process.receiver.policy,
                    &peer.process.certificate,
                    &expected,
                    &peer.local,
                    peer.process.receiver.original.sample()?.elapsed,
                )
            })();
            // Cohort observation is actual local work. Recheck the retained owners
            // independently even if that observation or signature check failed.
            let checked = self.local_check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            requested?;
            checked
        }
    }

    fn narrow_originals(
        &mut self,
        completion: &super::super::protocol::SignedRestoreIssuerCompletion,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = completion;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.require_completion(completion)?;
            let ceiling =
                std::time::Duration::from_nanos(completion.statement.effective_deadline_ns);
            let native = &mut self
                .keeper
                .input
                .owner
                .captured
                .peer
                .process
                .receiver
                .original;
            *native = native.narrow(5, ceiling)?;
            let read = &mut self.keeper.input.owner.original;
            *read = read.narrow(5, ceiling)?;
            self.local_check()
        }
    }
}

impl ReceivedRoleRestoredApp {
    pub(super) fn refuse(&mut self) {
        #[cfg(target_os = "linux")]
        self.role_transcript.refuse();
        self.keeper.keeper.refuse();
        self.keeper.input.owner.refuse();
    }

    pub(in crate::security_epoch::native_enrollment) fn receive_role_decision(
        mut self,
    ) -> Result<ReceivedDecisionRestoredApp> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut self;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use super::super::handshake::{Frame, Protocol, Step};
            use anyhow::Context;
            let (receipt, decision, transcript) = {
                let mut attempt = DecisionReceiveAttempt {
                    owner: &mut self,
                    transcript: None,
                    receipt: None,
                    done: false,
                };
                attempt.fresh()?;
                let requested: Result<super::super::protocol::SignedRestoreRoleActivation> =
                    (|| {
                        let message = attempt.receive_decision_packet()?;
                        let decision = attempt.authenticate_decision(&message)?;
                        attempt.narrow_originals(&decision)?;
                        Ok(decision)
                    })();
                let checked = attempt.fresh();
                if requested.is_err() || checked.is_err() {
                    attempt.refuse();
                }
                let decision = requested?;
                checked?;
                attempt.require_decision(&decision)?;
                let observation = attempt.observation()?;
                let transcript = attempt
                    .transcript
                    .as_mut()
                    .context("restore_decision_receive_transcript_missing")?;
                transcript.narrow_decision_receive(observation.clone())?;
                transcript.delivered(
                    Frame {
                        protocol: Protocol::RestoredDecision,
                        step: Step::RoleDecision,
                        sequence: None,
                    },
                    observation,
                )?;
                ensure!(transcript.complete(), "restore_decision_receive_incomplete");
                let transcript = attempt
                    .transcript
                    .take()
                    .context("restore_decision_receive_transcript_missing")?;
                let receipt = attempt
                    .receipt
                    .take()
                    .context("restore_decision_receive_receipt_missing")?;
                attempt.done = true;
                (receipt, decision, transcript)
            };
            Ok(ReceivedDecisionRestoredApp {
                received: self,
                receipt,
                decision,
                transcript,
            })
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        let requested = self.keeper.reobserve();
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        #[cfg(target_os = "linux")]
        let checked = (|| {
            {
                let peer = &mut self.keeper.input.owner.captured.peer;
                self.receipt.live(&mut peer.process)?;
            }
            ensure!(
                self.role_transcript.complete(),
                "restore_role_history_incomplete"
            );
            let expected = super::super::protocol::RestoreIssuerCompletionData {
                frozen: self
                    .keeper
                    .input
                    .owner
                    .captured
                    .peer
                    .local
                    .authorization
                    .statement
                    .data
                    .frozen
                    .clone(),
                authorization: self
                    .keeper
                    .input
                    .owner
                    .captured
                    .peer
                    .local
                    .authorization
                    .digest_data()?,
                app: self.keeper.input.owner.captured.peer.local.digest()?,
                activation: day2_capabilities::Digest::of(&self.keeper.input.owner.activation)?,
                cohort: self.keeper.keeper.cohort_data()?,
            };
            let peer = &mut self.keeper.input.owner.captured.peer;
            self.completion.verify_data(
                &peer.process.receiver.policy,
                &peer.process.certificate,
                &expected,
                &peer.local,
                peer.process.receiver.original.sample()?.elapsed,
            )
        })();
        let tail = self.keeper.check();
        if requested.is_err() || checked.is_err() || tail.is_err() {
            #[cfg(target_os = "linux")]
            self.role_transcript.refuse();
            self.keeper.keeper.refuse();
            self.keeper.input.owner.refuse();
        }
        requested?;
        checked?;
        tail
    }
}

impl DecisionReceiveAttempt<'_> {
    pub(super) fn refuse(&mut self) {
        self.owner.refuse();
        #[cfg(target_os = "linux")]
        if let Some(transcript) = &mut self.transcript {
            transcript.refuse();
        }
    }

    pub(super) fn local_check(&mut self) -> Result<()> {
        let requested = self.owner.keeper.check();
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        #[cfg(target_os = "linux")]
        let checked = (|| {
            ensure!(
                self.owner.role_transcript.complete(),
                "restore_role_history_incomplete"
            );
            let peer = &mut self.owner.keeper.input.owner.captured.peer;
            self.owner.receipt.live(&mut peer.process)?;
            if let Some(receipt) = &mut self.receipt {
                receipt.live(&mut peer.process)?;
            }
            Ok(())
        })();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    fn fresh(&mut self) -> Result<()> {
        let requested = self.owner.check();
        let checked = self.local_check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(super) fn observation(&mut self) -> Result<super::super::handshake::Observation> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.owner.keeper.input.owner.original.remaining()?;
            let native = &mut self
                .owner
                .keeper
                .input
                .owner
                .captured
                .peer
                .process
                .receiver
                .original;
            native.remaining()?;
            let (domain, origin, deadline, now) = native.historical_interval_observation();
            let (read_domain, read_origin, read_deadline, read_now) = self
                .owner
                .keeper
                .input
                .owner
                .original
                .historical_interval_observation();
            ensure!(
                read_domain == domain && read_origin == origin,
                "restore_decision_receive_original_join_changed"
            );
            Ok(super::super::handshake::Observation {
                domain,
                origin,
                deadline: deadline.min(read_deadline),
                now: now.max(read_now),
            })
        }
    }

    fn authenticate_decision(
        &mut self,
        message: &super::super::storage_peer_wire::Message,
    ) -> Result<super::super::protocol::SignedRestoreRoleActivation> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = message;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            self.local_check()?;
            {
                let peer = &mut self.owner.keeper.input.owner.captured.peer;
                self.receipt
                    .as_mut()
                    .context("restore_decision_receive_receipt_missing")?
                    .bind(message, &peer.controller, &mut peer.process)?;
            }
            self.local_check()?;
            let peer = &mut self.owner.keeper.input.owner.captured.peer;
            let super::super::storage_peer_wire::Body::Restore { payload } = &message.body else {
                anyhow::bail!("restore_decision_receive_message_kind")
            };
            Ok(payload
                .role_decision_data(
                    &peer.exchange.digest()?,
                    &self.owner.completion,
                    &peer.process.receiver.policy,
                    &peer.process.certificate,
                    &peer.local,
                    peer.process.receiver.original.sample()?.elapsed,
                )?
                .clone())
        }
    }

    fn require_decision(
        &mut self,
        decision: &super::super::protocol::SignedRestoreRoleActivation,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = decision;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested = (|| {
                let peer = &mut self.owner.keeper.input.owner.captured.peer;
                decision.verify_data(
                    &peer.process.receiver.policy,
                    &peer.process.certificate,
                    &self.owner.completion,
                    &peer.local,
                    (&decision.statement.request, &decision.statement.challenge),
                    peer.process.receiver.original.sample()?.elapsed,
                )
            })();
            let checked = self.local_check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            requested?;
            checked
        }
    }

    fn narrow_originals(
        &mut self,
        decision: &super::super::protocol::SignedRestoreRoleActivation,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = decision;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.require_decision(decision)?;
            let ceiling = std::time::Duration::from_nanos(decision.statement.effective_deadline_ns);
            let native = &mut self
                .owner
                .keeper
                .input
                .owner
                .captured
                .peer
                .process
                .receiver
                .original;
            *native = native.narrow(5, ceiling)?;
            let read = &mut self.owner.keeper.input.owner.original;
            *read = read.narrow(5, ceiling)?;
            self.local_check()
        }
    }
}

impl ReceivedDecisionRestoredApp {
    pub(super) fn refuse(&mut self) {
        #[cfg(target_os = "linux")]
        self.transcript.refuse();
        self.received.refuse();
    }

    /// One fixed direct issuer exchange. No fresh key/acquisition, raw parts,
    /// ordinary role or Runtime can be created from the returned preparation.
    pub(in crate::security_epoch::native_enrollment) fn confirm_with_issuer(
        self,
    ) -> Result<PreparedConfirmedRestoredApp> {
        let mut attempt = AppIssuerConfirmation {
            input: Some(self),
            #[cfg(target_os = "linux")]
            channel: None,
            #[cfg(target_os = "linux")]
            nonce_peer: None,
            #[cfg(target_os = "linux")]
            grant_peer: None,
            #[cfg(target_os = "linux")]
            request: None,
            #[cfg(target_os = "linux")]
            challenge: None,
            #[cfg(target_os = "linux")]
            confirmation: None,
            complete: false,
            refused: false,
        };
        let requested: Result<()> = (|| {
            attempt.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use super::super::{
                    channel::Channel,
                    protocol::{self, Packet},
                };
                use anyhow::Context;
                let request = protocol::nonce("restore-app-prepared-request");
                let checked = attempt.check();
                let request = request?;
                checked?;
                attempt.request = Some(request.clone());
                let connected = {
                    let input = attempt
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    Channel::connect(
                        &mut input
                            .received
                            .keeper
                            .input
                            .owner
                            .captured
                            .peer
                            .process
                            .receiver
                            .original,
                    )
                };
                let checked = attempt.check();
                let channel = connected?;
                checked?;
                attempt.channel = Some(channel);
                let decision = attempt
                    .input
                    .as_ref()
                    .context("restore_prepared_input_missing")?
                    .decision
                    .clone();
                let sent = {
                    let input = attempt
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    attempt
                        .channel
                        .as_mut()
                        .context("restore_prepared_channel_missing")?
                        .send(
                            &Packet::RestoreAppConfirmHello {
                                decision: Box::new(decision.clone()),
                                request: request.clone(),
                            },
                            &mut input
                                .received
                                .keeper
                                .input
                                .owner
                                .captured
                                .peer
                                .process
                                .receiver
                                .original,
                        )
                };
                let checked = attempt.check();
                sent?;
                checked?;
                let received = {
                    let input = attempt
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    attempt
                        .channel
                        .as_mut()
                        .context("restore_prepared_channel_missing")?
                        .receive_issuer(
                            &mut input
                                .received
                                .keeper
                                .input
                                .owner
                                .captured
                                .peer
                                .process
                                .receiver
                                .original,
                        )
                };
                let checked = attempt.check();
                let (packet, mut receipt) = received?;
                // Bind the actual raw SCM receipt to the already known issuer
                // BEFORE interpreting this packet's claimed challenge fields.
                let bound = {
                    let input = attempt
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    let process = &mut input.received.keeper.input.owner.captured.peer.process;
                    receipt.bind(
                        &process.certificate,
                        &process.receiver.policy,
                        &mut process.receiver.original,
                    )
                };
                attempt.nonce_peer = Some(receipt);
                let receipt_post = attempt.check();
                checked?;
                bound?;
                receipt_post?;
                let Packet::RestoreAppConfirmNonce {
                    decision: echoed_decision,
                    request: echoed,
                    challenge,
                } = packet
                else {
                    anyhow::bail!("restore_prepared_nonce_expected")
                };
                ensure!(
                    echoed_decision == decision.digest_data()? && echoed == request,
                    "restore_prepared_nonce_changed"
                );
                attempt.challenge = Some(challenge.clone());
                let signed = {
                    let input = attempt
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    input
                        .received
                        .keeper
                        .input
                        .owner
                        .captured
                        .peer
                        .process
                        .receiver
                        .key
                        .sign(
                            "restore-app-prepared-bind-v1",
                            &(&decision, &request, &challenge),
                        )
                };
                let checked = attempt.check();
                let signature = signed?;
                checked?;
                let sent = {
                    let input = attempt
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    attempt
                        .channel
                        .as_mut()
                        .context("restore_prepared_channel_missing")?
                        .send(
                            &Packet::RestoreAppConfirmBind {
                                decision: Box::new(decision),
                                request,
                                challenge,
                                signature,
                            },
                            &mut input
                                .received
                                .keeper
                                .input
                                .owner
                                .captured
                                .peer
                                .process
                                .receiver
                                .original,
                        )
                };
                let checked = attempt.check();
                sent?;
                checked?;
                let received = {
                    let input = attempt
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    attempt
                        .channel
                        .as_mut()
                        .context("restore_prepared_channel_missing")?
                        .receive_issuer(
                            &mut input
                                .received
                                .keeper
                                .input
                                .owner
                                .captured
                                .peer
                                .process
                                .receiver
                                .original,
                        )
                };
                let checked = attempt.check();
                let (packet, mut receipt) = received?;
                let bound = {
                    let input = attempt
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    let process = &mut input.received.keeper.input.owner.captured.peer.process;
                    receipt.bind(
                        &process.certificate,
                        &process.receiver.policy,
                        &mut process.receiver.original,
                    )
                };
                attempt.grant_peer = Some(receipt);
                let receipt_post = attempt.check();
                checked?;
                bound?;
                receipt_post?;
                let Packet::RestoreAppConfirmGrant { confirmation } = packet else {
                    anyhow::bail!("restore_prepared_grant_expected")
                };
                {
                    let input = attempt
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    let peer = &mut input.received.keeper.input.owner.captured.peer;
                    confirmation.verify_data(
                        &peer.process.receiver.policy,
                        &peer.process.certificate,
                        (&input.decision, &input.received.completion),
                        &peer.local,
                        (
                            attempt
                                .request
                                .as_ref()
                                .context("restore_prepared_request_missing")?,
                            attempt
                                .challenge
                                .as_ref()
                                .context("restore_prepared_challenge_missing")?,
                        ),
                        peer.process.receiver.original.sample()?.elapsed,
                    )?;
                    // The negative root already owns BOTH original views before
                    // either is reduced. Preserve domain/origin/spent/refusal.
                    let ceiling = std::time::Duration::from_nanos(
                        confirmation.statement.effective_deadline_ns,
                    );
                    let native = &mut peer.process.receiver.original;
                    *native = native.narrow(5, ceiling)?;
                    let read = &mut input.received.keeper.input.owner.original;
                    *read = read.narrow(5, ceiling)?;
                }
                attempt.confirmation = Some(*confirmation);
                attempt.complete = true;
                Ok(())
            }
        })();
        // Actual current writer/keeper/native and every received issuer anchor
        // are checked independently, even when the requested exchange failed.
        let checked = attempt.check();
        if requested.is_err() || checked.is_err() {
            attempt.refuse();
        }
        requested?;
        checked?;
        Ok(PreparedConfirmedRestoredApp { pending: attempt })
    }

    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        let requested = self.received.check();
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        #[cfg(target_os = "linux")]
        let checked = (|| {
            ensure!(
                self.transcript.complete(),
                "restore_decision_history_incomplete"
            );
            let peer = &mut self.received.keeper.input.owner.captured.peer;
            self.receipt.live(&mut peer.process)?;
            self.decision.verify_data(
                &peer.process.receiver.policy,
                &peer.process.certificate,
                &self.received.completion,
                &peer.local,
                (
                    &self.decision.statement.request,
                    &self.decision.statement.challenge,
                ),
                peer.process.receiver.original.sample()?.elapsed,
            )
        })();
        let tail = self.received.keeper.check();
        if requested.is_err() || checked.is_err() || tail.is_err() {
            #[cfg(target_os = "linux")]
            self.transcript.refuse();
            self.received.refuse();
        }
        requested?;
        checked?;
        tail
    }
}

impl AppIssuerConfirmation {
    pub(super) fn refuse(&mut self) {
        self.refused = true;
        if let Some(input) = &mut self.input {
            input.refuse();
        }
    }

    fn check(&mut self) -> Result<()> {
        if self.refused {
            anyhow::bail!("restore_prepared_confirmation_refused");
        }
        let requested = (|| {
            let input = self
                .input
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_prepared_input_missing"))?;
            input.check()
        })();
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        #[cfg(target_os = "linux")]
        let checked = (|| {
            use anyhow::Context;
            let input = self
                .input
                .as_mut()
                .context("restore_prepared_input_missing")?;
            let peer = &mut input.received.keeper.input.owner.captured.peer;
            if let Some(receipt) = &mut self.nonce_peer {
                receipt.check_live(&mut peer.process.receiver.original)?;
            }
            if let Some(receipt) = &mut self.grant_peer {
                receipt.check_live(&mut peer.process.receiver.original)?;
            }
            if self.complete {
                ensure!(
                    self.channel.is_some()
                        && self.nonce_peer.is_some()
                        && self.grant_peer.is_some()
                        && self.confirmation.is_some(),
                    "restore_prepared_native_completion_missing"
                );
            }
            if let Some(confirmation) = &self.confirmation {
                confirmation.verify_data(
                    &peer.process.receiver.policy,
                    &peer.process.certificate,
                    (&input.decision, &input.received.completion),
                    &peer.local,
                    (
                        self.request
                            .as_ref()
                            .context("restore_prepared_request_missing")?,
                        self.challenge
                            .as_ref()
                            .context("restore_prepared_challenge_missing")?,
                    ),
                    peer.process.receiver.original.sample()?.elapsed,
                )?;
            }
            Ok(())
        })();
        let tail = (|| {
            self.input
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_prepared_input_missing"))?
                .received
                .keeper
                .check()
        })();
        if requested.is_err() || checked.is_err() || tail.is_err() {
            self.refuse();
        }
        requested?;
        checked?;
        tail
    }
}

impl PreparedConfirmedRestoredApp {
    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        if !self.pending.complete {
            self.pending.refuse();
            anyhow::bail!("restore_prepared_confirmation_incomplete");
        }
        self.pending.check()
    }
}

impl PreparedConfirmedRestoredApp {
    /// Consume the prepared App before signing or IO. A real authenticated
    /// Controller acceptance is mandatory; sending an ACK is never completion.
    pub(in crate::security_epoch::native_enrollment) fn await_controller_acceptance(
        self,
    ) -> Result<AcceptedRestoredApp> {
        let mut attempt = AppPreparedHandoff {
            input: Some(self),
            #[cfg(target_os = "linux")]
            transcript: None,
            #[cfg(target_os = "linux")]
            acknowledgement: None,
            #[cfg(target_os = "linux")]
            receipt: None,
            ack_delivered: false,
            accepted: false,
            installation_attempted: false,
            refused: false,
        };
        let requested: Result<()> = (|| {
            attempt.check()?;
            attempt.prepare_ack()?;
            attempt.send_prepared_ack()?;
            let message = attempt.receive_prepared_acceptance()?;
            attempt.authenticate_acceptance(&message)?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use super::super::handshake::{Frame, Protocol, Step};
                use anyhow::Context;
                attempt.check()?;
                let observation = attempt.observation()?;
                let transcript = attempt
                    .transcript
                    .as_mut()
                    .context("restore_prepared_handoff_history_missing")?;
                transcript.narrow_prepared_acceptance(observation.clone())?;
                transcript.delivered(
                    Frame {
                        protocol: Protocol::RestoredConfirmation,
                        step: Step::PreparedAccepted,
                        sequence: None,
                    },
                    observation,
                )?;
                ensure!(
                    transcript.complete(),
                    "restore_prepared_acceptance_incomplete"
                );
                attempt.accepted = true;
                Ok(())
            }
        })();
        let checked = attempt.check();
        if requested.is_err() || checked.is_err() {
            attempt.refuse();
        }
        requested?;
        checked?;
        Ok(AcceptedRestoredApp {
            pending: attempt,
            installed_attempted: false,
            #[cfg(target_os = "linux")]
            installed: None,
        })
    }
}

impl AppPreparedHandoff {
    pub(super) fn refuse(&mut self) {
        self.refused = true;
        if let Some(input) = &mut self.input {
            input.pending.refuse();
        }
        #[cfg(target_os = "linux")]
        if let Some(transcript) = &mut self.transcript {
            transcript.refuse();
        }
    }

    pub(super) fn check(&mut self) -> Result<()> {
        if self.refused {
            anyhow::bail!("restore_prepared_handoff_refused");
        }
        let requested: Result<()> = (|| {
            self.input
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_prepared_handoff_input_missing"))?
                .check()
        })();
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        #[cfg(target_os = "linux")]
        let checked: Result<()> = (|| {
            use anyhow::Context;
            let input = self
                .input
                .as_mut()
                .context("restore_prepared_handoff_input_missing")?
                .pending
                .input
                .as_mut()
                .context("restore_prepared_input_missing")?;
            let peer = &mut input.received.keeper.input.owner.captured.peer;
            if let Some(receipt) = &mut self.receipt {
                receipt.live(&mut peer.process)?;
            }
            if self.accepted {
                ensure!(
                    self.ack_delivered
                        && self.receipt.is_some()
                        && self
                            .transcript
                            .as_ref()
                            .is_some_and(|transcript| transcript.complete()),
                    "restore_prepared_acceptance_native_receipt_missing"
                );
            }
            Ok(())
        })();
        let tail = (|| {
            self.input
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_prepared_handoff_input_missing"))?
                .pending
                .input
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_prepared_input_missing"))?
                .received
                .keeper
                .check()
        })();
        if requested.is_err() || checked.is_err() || tail.is_err() {
            self.refuse();
        }
        requested?;
        checked?;
        tail
    }

    pub(super) fn observation(&mut self) -> Result<super::super::handshake::Observation> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let input = self
                .input
                .as_mut()
                .context("restore_prepared_handoff_input_missing")?
                .pending
                .input
                .as_mut()
                .context("restore_prepared_input_missing")?;
            input.received.keeper.input.owner.original.remaining()?;
            let native = &mut input
                .received
                .keeper
                .input
                .owner
                .captured
                .peer
                .process
                .receiver
                .original;
            native.remaining()?;
            let (domain, origin, deadline, now) = native.historical_interval_observation();
            let (read_domain, read_origin, read_deadline, read_now) = input
                .received
                .keeper
                .input
                .owner
                .original
                .historical_interval_observation();
            ensure!(
                domain == read_domain && origin == read_origin,
                "restore_prepared_handoff_original_changed"
            );
            Ok(super::super::handshake::Observation {
                domain,
                origin,
                deadline: deadline.min(read_deadline),
                now: now.max(read_now),
            })
        }
    }

    fn prepare_ack(&mut self) -> Result<()> {
        self.check()?;
        let requested: Result<()> = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                ensure!(
                    !self.ack_delivered
                        && !self.accepted
                        && self.transcript.is_none()
                        && self.acknowledgement.is_none(),
                    "restore_prepared_ack_attempt_spent"
                );
                let observation = self.observation()?;
                let input = self
                    .input
                    .as_mut()
                    .context("restore_prepared_handoff_input_missing")?;
                let confirmation = input
                    .pending
                    .confirmation
                    .as_ref()
                    .context("restore_prepared_confirmation_missing")?
                    .clone();
                let actual = input
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_input_missing")?;
                // Derive only from THIS actual completed decision history,
                // already narrowed to the directly confirmed issuer ceiling.
                self.transcript = Some(
                    actual
                        .transcript
                        .derive_restored_confirmation(observation)?,
                );
                let cohort = actual.received.keeper.keeper.cohort_data()?;
                let peer = &mut actual.received.keeper.input.owner.captured.peer;
                let payload = RestoreBody::AppPrepared {
                    exchange: peer.exchange.digest()?,
                    confirmation: Box::new(confirmation),
                    cohort,
                };
                payload.prepared_confirmation_data(
                    &peer.exchange.digest()?,
                    (&actual.decision, &actual.received.completion),
                    &peer.process.receiver.policy,
                    &peer.local,
                    peer.process.receiver.original.sample()?.elapsed,
                )?;
                let body = Body::Restore { payload };
                let sender = peer.local.digest()?;
                self.check()?;
                let signed = {
                    let actual = self
                        .input
                        .as_mut()
                        .context("restore_prepared_handoff_input_missing")?
                        .pending
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    actual
                        .received
                        .keeper
                        .input
                        .owner
                        .captured
                        .peer
                        .process
                        .receiver
                        .key
                        .sign("restored-storage-message", &(&sender, &body))
                };
                let checked = self.check();
                let signature = signed?;
                checked?;
                self.acknowledgement = Some(Message {
                    sender,
                    body,
                    signature,
                });
                Ok(())
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    fn authenticate_acceptance(
        &mut self,
        message: &super::super::storage_peer_wire::Message,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            self.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = message;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                ensure!(
                    self.ack_delivered && !self.accepted,
                    "restore_prepared_acceptance_order"
                );
                let bound = {
                    let actual = self
                        .input
                        .as_mut()
                        .context("restore_prepared_handoff_input_missing")?
                        .pending
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    let peer = &mut actual.received.keeper.input.owner.captured.peer;
                    self.receipt
                        .as_mut()
                        .context("restore_prepared_acceptance_sender_missing")?
                        .bind(message, &peer.controller, &mut peer.process)
                };
                let checked = self.check();
                bound?;
                checked?;
                let input = self
                    .input
                    .as_mut()
                    .context("restore_prepared_handoff_input_missing")?;
                let confirmation = input
                    .pending
                    .confirmation
                    .as_ref()
                    .context("restore_prepared_confirmation_missing")?;
                let actual = input
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_input_missing")?;
                let cohort = actual.received.keeper.keeper.cohort_data()?;
                let peer = &mut actual.received.keeper.input.owner.captured.peer;
                let Body::Restore { payload } = &message.body else {
                    anyhow::bail!("restore_prepared_acceptance_message_kind")
                };
                let ceiling = payload.prepared_acceptance_deadline_data(
                    &peer.exchange.digest()?,
                    confirmation,
                    &cohort,
                    peer.process.receiver.original.sample()?.elapsed,
                )?;
                // The negative root already owns every handle before either
                // reduction. No original, high-water or refusal is reset.
                let native = &mut peer.process.receiver.original;
                *native = native.narrow(5, ceiling)?;
                let read = &mut actual.received.keeper.input.owner.original;
                *read = read.narrow(5, ceiling)?;
                Ok(())
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }
}

impl AcceptedRestoredApp {
    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        if !self.pending.accepted {
            self.pending.refuse();
            anyhow::bail!("restore_prepared_acceptance_incomplete");
        }
        let requested = self.pending.check();
        #[cfg(target_os = "linux")]
        let checked: Result<()> = (|| {
            if let Some(installed) = &mut self.installed {
                use anyhow::Context;
                ensure!(
                    self.installed_attempted
                        && installed
                            .transcript
                            .as_ref()
                            .is_some_and(|history| history.complete()),
                    "restore_installed_history_incomplete"
                );
                let actual = self
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_handoff_input_missing")?
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_input_missing")?;
                installed
                    .receipt
                    .as_mut()
                    .context("restore_installed_receipt_transferred")?
                    .live(&mut actual.received.keeper.input.owner.captured.peer.process)?;
                let Body::Restore { payload } = &installed.acknowledgement.body else {
                    anyhow::bail!("restore_installed_ack_kind");
                };
                let Body::Restore {
                    payload: acceptance,
                } = &installed.acceptance.body
                else {
                    anyhow::bail!("restore_installed_acceptance_kind");
                };
                let peer = &mut actual.received.keeper.input.owner.captured.peer;
                acceptance.installed_acceptance_deadline_data(
                    &peer.exchange.digest()?,
                    payload,
                    peer.process.receiver.original.sample()?.elapsed,
                )?;
            }
            Ok(())
        })();
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }
}

impl AcceptedRestoredApp {
    /// Consumes the actual accepted owner before the first check, clone or role
    /// construction. Only fixed installation work can use the returned pending
    /// owner; no ordinary request, signing or SQL entry point is exposed.
    pub(in crate::security_epoch::native_enrollment) fn prepare_ordinary_role(
        mut self,
    ) -> Result<super::super::owner::PendingRestoredEnrollment> {
        if self.pending.installation_attempted {
            self.pending.refuse();
            anyhow::bail!("restore_ordinary_install_attempt_spent");
        }
        self.pending.installation_attempted = true;
        self.check()?;
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            use std::rc::Rc;
            // No RefCell guard survives this block. Cloning the SAME private
            // resources does not duplicate the consumed installation attempt.
            let requested: Result<_> = (|| {
                let input = self
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_handoff_input_missing")?
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_input_missing")?;
                let peer = &mut input.received.keeper.input.owner.captured.peer;
                let process = &mut peer.process;
                let receiver = &mut process.receiver;
                let (_, deadline) = receiver.original.interval_data()?;
                let original = receiver.original.narrow(5, deadline)?;
                let clock = receiver
                    .original
                    .narrow(5, deadline)?
                    .into_connection_clock()?;
                Ok((
                    receiver.policy.clone(),
                    Rc::clone(&receiver.key),
                    process.certificate.clone(),
                    Rc::clone(&receiver.policy_file),
                    Rc::clone(&receiver.current),
                    Rc::clone(&process.grant_peer),
                    Rc::clone(&process.nonce_peer),
                    Rc::clone(&process.channel),
                    input.decision.statement.stage.clone(),
                    original,
                    clock,
                ))
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.pending.refuse();
            }
            let (
                policy,
                key,
                certificate,
                policy_file,
                current,
                issuer,
                nonce_peer,
                channel,
                admission,
                original,
                clock,
            ) = requested?;
            checked?;
            let runtime = self.prepare_runtime()?;
            let port = super::super::RestoredRoleInstallPort {
                history: self,
                runtime,
                policy,
                key,
                certificate,
                policy_file,
                current,
                issuer,
                nonce_peer,
                channel,
                admission,
                original,
                clock,
            };
            super::super::owner::PendingRestoredEnrollment::from_restore(port)
        }
    }

    /// Pure names and expected versions from the retained writer activation.
    /// Only the fixed Pending reader operation exposes these DATA, while its
    /// negative attempt spans full native/keeper/both-original pre and post.
    pub(in crate::security_epoch::native_enrollment) fn restored_reader_data(
        &self,
        selection: &day2_capabilities::security_epoch::EpochStore,
    ) -> Result<crate::security_epoch::firestore::RestoreWriterPeerRead> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = selection;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let input = self
                .pending
                .input
                .as_ref()
                .context("restore_prepared_handoff_input_missing")?
                .pending
                .input
                .as_ref()
                .context("restore_prepared_input_missing")?;
            let actual = &input.received.keeper.input.owner;
            let peer = &actual.captured.peer;
            anyhow::ensure!(
                &peer.process.receiver.policy.store == selection,
                "restore_pending_reader_store_changed"
            );
            let holder = peer.local.holder_data()?;
            crate::security_epoch::firestore::RestoreWriterPeerRead::new(
                selection,
                &peer.projection,
                &actual.activation,
                &holder,
            )
        }
    }

    // Private to this fixed accepting-App factory. It never opens SQLite or
    // returns a Runtime outside the consumed pending installation attempt.
    fn prepare_runtime(&mut self) -> Result<crate::store::Runtime> {
        self.check()?;
        let requested: Result<crate::store::Runtime> = (|| {
            let input = self
                .pending
                .input
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_prepared_handoff_input_missing"))?
                .pending
                .input
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_prepared_input_missing"))?;
            let mut birth = RestoredRuntimeBirth {
                keeper: &mut input.received.keeper,
                completed: false,
            };
            let requested = crate::store::Runtime::load_restored_storage(&mut birth);
            let checked = birth.check();
            if requested.is_err() || checked.is_err() {
                birth.refuse();
            }
            let runtime = requested?;
            checked?;
            birth.completed = true;
            Ok(runtime)
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.pending.refuse();
        }
        let runtime = requested?;
        checked?;
        Ok(runtime)
    }

    /// Negative only; used by the pending role's teardown without borrowing a
    /// mutable native resource. It always poisons the same original identity.
    pub(in crate::security_epoch::native_enrollment) fn refuse(&mut self) {
        self.pending.refuse();
    }
}

impl RestoredHistoryLoan<'_> {
    fn take(root: &RestoredAppHistory) -> Result<RestoredHistoryLoan<'_>> {
        let requested = (|| {
            anyhow::ensure!(!root.refused.get(), "restore_history_refused");
            #[cfg(target_os = "linux")]
            anyhow::ensure!(
                !root.channel_refusal.get(),
                "restore_history_channel_refused"
            );
            let history = root
                .retained
                .take()
                .ok_or_else(|| anyhow::anyhow!("restore_history_busy_or_spent"))?;
            Ok(RestoredHistoryLoan {
                root,
                history: Some(history),
                completed: false,
            })
        })();
        if requested.is_err() {
            root.refuse();
        }
        requested
    }

    fn finish(mut self) -> Result<()> {
        let history = self
            .history
            .take()
            .ok_or_else(|| anyhow::anyhow!("restore_history_loan_missing"))?;
        if let Some(unexpected) = self.root.retained.replace(Some(history)) {
            self.root.refuse();
            drop(unexpected);
            anyhow::bail!("restore_history_slot_changed");
        }
        anyhow::ensure!(!self.root.refused.get(), "restore_history_refused");
        self.completed = true;
        Ok(())
    }
}

impl RestoredAppHistory {
    /// Negative-only root; no slot borrow, sampling, callback, wait or hook.
    pub(in crate::security_epoch::native_enrollment) fn refuse(&self) {
        self.refused.set(true);
        #[cfg(target_os = "linux")]
        {
            self.receiver_refusal.refuse();
            self.reader_refusal.refuse();
            self.channel_refusal.set(true);
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn check(&self) -> Result<()> {
        let mut loan = RestoredHistoryLoan::take(self)?;
        let requested = loan
            .history
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("restore_history_loan_missing"))?
            .check();
        if requested.is_err() {
            self.refuse();
        }
        let checked = loan.finish();
        requested?;
        checked
    }

    pub(in crate::security_epoch::native_enrollment) fn restored_reader_data(
        &self,
        selection: &day2_capabilities::security_epoch::EpochStore,
    ) -> Result<crate::security_epoch::firestore::RestoreWriterPeerRead> {
        let loan = RestoredHistoryLoan::take(self)?;
        let requested = loan
            .history
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("restore_history_loan_missing"))?
            .restored_reader_data(selection);
        if requested.is_err() {
            self.refuse();
        }
        let checked = loan.finish();
        let reader = requested?;
        checked?;
        Ok(reader)
    }

    /// Physical resources only under the caller's ACTUAL fresh stage. Never
    /// check or sample an old Accepted/Pending original, lease or transcript.
    pub(in crate::security_epoch::native_enrollment) fn check_current_resources(
        &self,
        stage: &mut super::super::EnrolledRoleStage<'_>,
    ) -> Result<()> {
        let mut loan = RestoredHistoryLoan::take(self)?;
        let requested = loan
            .history
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("restore_history_loan_missing"))
            .and_then(|accepted| accepted.check_current_keeper(stage));
        let checked = stage.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let restored = loan.finish();
        requested?;
        checked?;
        restored
    }
}

impl AcceptedRestoredApp {
    pub(in crate::security_epoch::native_enrollment) fn retain_history(
        mut self,
    ) -> Result<std::rc::Rc<RestoredAppHistory>> {
        self.check()?;
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested: Result<_> = (|| {
                let input = self
                    .pending
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("restore_prepared_handoff_input_missing"))?
                    .pending
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("restore_prepared_input_missing"))?;
                let actual = &input.received.keeper.input.owner;
                Ok((
                    actual
                        .captured
                        .peer
                        .process
                        .receiver
                        .original
                        .retained_refusal(),
                    actual.original.retained_refusal(),
                    std::rc::Rc::clone(&actual.captured.peer.channel.refused),
                ))
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            let (receiver_refusal, reader_refusal, channel_refusal) = requested?;
            checked?;
            Ok(std::rc::Rc::new(RestoredAppHistory {
                retained: std::cell::Cell::new(Some(self)),
                refused: std::cell::Cell::new(false),
                receiver_refusal,
                reader_refusal,
                channel_refusal,
            }))
        }
    }
}

#[cfg(test)]
mod keeper_birth_tests {
    use quote::ToTokens;

    pub(super) fn tokens(source: &str) -> String {
        fn strip(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            stream
                .into_iter()
                .filter_map(|token| match token {
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => None,
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '?' => {
                        Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                            '?',
                            proc_macro2::Spacing::Alone,
                        )))
                    }
                    proc_macro2::TokenTree::Group(group) => Some(proc_macro2::TokenTree::Group(
                        proc_macro2::Group::new(group.delimiter(), strip(group.stream())),
                    )),
                    other => Some(other),
                })
                .collect()
        }
        strip(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
    }

    pub(super) fn method(source: &str, owner_name: &str, name: &str) -> String {
        let file = syn::parse_file(source).unwrap();
        let mut found = file.items.into_iter().filter_map(|item| {
            let syn::Item::Impl(owner) = item else {
                return None;
            };
            if !matches!(&*owner.self_ty,syn::Type::Path(path) if path.path.segments.len()==1
                && path.path.segments[0].ident==owner_name)
            {
                return None;
            }
            owner.items.into_iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => {
                    Some(tokens(&method.into_token_stream().to_string()))
                }
                _ => None,
            })
        });
        let found_method = found.next().unwrap();
        assert!(found.next().is_none());
        found_method
    }

    pub(super) fn ordered(body: &str, parts: &[&str]) -> bool {
        let mut rest = body;
        for part in parts {
            let part = tokens(part);
            let Some(at) = rest.find(&part) else {
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        true
    }

    fn store_birth_is_closed(body: &str) -> bool {
        ordered(
            body,
            &[
                "birth.before_open(path,artifact,scope)?;",
                "let mut keeper=Self",
                "connection:open_existing(path)?",
                "birth.require_opened(&keeper.connection)?;",
                "configure_connection(&mut keeper.connection)",
                "birth.check_database(&keeper.connection)",
                "configured?;checked?;",
                "birth.admit_database(&mut keeper.connection)?;",
                "birth.reobserve_database(&keeper.connection)?;",
                "keeper.connection.pragma_update(None,\"journal_mode\",\"WAL\")",
                "birth.check_database(&keeper.connection)",
                "wal?;checked?;",
                "keeper.capture_created_files()",
                "birth.check_database(&keeper.connection)",
                "captured?;checked?;",
                "birth.reobserve_database(&keeper.connection)?;",
                "birth.require_keeper(&mut keeper)?;",
                "Ok(keeper)",
            ],
        ) && body.matches(&tokens("open_existing(path)")).count() == 1
            && ![
                "Connection::open",
                "SQLITE_OPEN_CREATE",
                "initialize",
                "drop(keeper)",
                "Runtime",
            ]
            .iter()
            .any(|part| body.contains(&tokens(part)))
    }

    #[test]
    fn actual_first_connection_is_retained_and_pinned_before_configuration_schema_and_wal() {
        assert_eq!(
            tokens("birth.before_open(path,artifact,scope)?;"),
            tokens("birth.before_open(path,artifact,scope) ? ;")
        );
        assert_ne!(
            tokens("birth.before_open(path,artifact,scope)?;"),
            tokens("other.before_open(path,artifact,scope)?;")
        );
        let body = method(
            include_str!("../../../store/native_storage.rs"),
            "NativeSqliteKeeper",
            "create_restored",
        );
        assert!(store_birth_is_closed(&body));
        for (before, after) in [
            (
                "birth.before_open(path,artifact,scope)?;",
                "let _unchecked=();",
            ),
            (
                "birth.require_opened(&keeper.connection)?;",
                "let _unchecked=();",
            ),
            (
                "connection:open_existing(path)?",
                "connection:Connection::open(path)?",
            ),
            (
                "configure_connection(&mut keeper.connection)",
                "configure_connection(&mut another.connection)",
            ),
            (
                "birth.admit_database(&mut keeper.connection)?;",
                "let _unchecked=();",
            ),
            (
                "birth.reobserve_database(&keeper.connection)?;",
                "let _unchecked=();",
            ),
            ("captured?;checked?;", "checked?;captured?;"),
        ] {
            let before = tokens(before);
            assert!(body.contains(&before));
            assert!(!store_birth_is_closed(&body.replacen(
                &before,
                &tokens(after),
                1
            )));
        }
    }

    #[test]
    fn actual_native_factory_checks_actual_inputs_and_raw_image_at_first_open_and_holds_negative_loan()
     {
        let source = include_str!("activation.rs");
        let before = method(source, "RestoredKeeperBirth", "before_open");
        let pre_parts = [
            "path==self.path && scope==self.scope && std::ptr::eq(artifact,self.artifact)",
            "self.owner.reobserve_writer()?;",
            "self.check()?;",
            "require_unopened_native_sqlite",
            "let checked=self.check();",
            "absent?;checked?;",
            "self.owner.captured.require_unopened_image()",
            "let checked=self.owner.check();",
            "self.owner.refuse();",
            "requested?;checked",
        ];
        assert!(ordered(&before, &pre_parts));
        for (from, to) in [
            ("path==self.path", "path==other.path"),
            ("scope==self.scope", "scope==other.scope"),
            (
                "std::ptr::eq(artifact,self.artifact)",
                "artifact.id()==self.artifact.id()",
            ),
            ("self.owner.reobserve_writer()?;", "let _unchecked=();"),
            ("self.owner.captured.require_unopened_image()", "Ok(())"),
            (
                "let checked=self.owner.check();",
                "let checked:Result<()>=Ok(());",
            ),
            ("requested?;checked", "checked?;requested"),
        ] {
            let from = tokens(from);
            assert!(before.contains(&from));
            assert!(!ordered(
                &before.replacen(&from, &tokens(to), 1),
                &pre_parts
            ));
        }
        let factory = method(source, "RestoredActiveKeeperInput", "create_keeper");
        assert!(ordered(
            &factory,
            &[
                "let mut birth=RestoredKeeperBirth",
                "completed:false",
                "NativeSqliteKeeper::create_restored",
                "let checked=birth.check();",
                "keeper.refuse();",
                "let keeper=requested?;checked?;",
                "birth.completed=true;",
                "drop(birth);",
                "RestoredAppKeeper"
            ]
        ));
        let check = method(source, "RestoredKeeperBirth", "check_database");
        let db_parts = [
            "connection.is_autocommit()",
            "require_original_main(connection,&self.owner.captured.file)",
            "let checked=self.check();",
            "self.owner.refuse();",
            "requested?;checked",
        ];
        assert!(ordered(&check, &db_parts));
        for (from, to) in [
            ("connection.is_autocommit()", "true"),
            ("&self.owner.captured.file", "&other.file"),
            (
                "let checked=self.check();",
                "let checked:Result<()>=Ok(());",
            ),
        ] {
            let from = tokens(from);
            // There is now both the pure early closed-unit precondition and
            // the retained requested-unit guard. Remove both for this lower
            // oracle; the common-factory control separately pins the FIRST
            // precondition before any native/file/authority work.
            let expected = if from == tokens("connection.is_autocommit()") {
                2
            } else {
                1
            };
            assert_eq!(check.matches(&from).count(), expected);
            assert!(!ordered(&check.replace(&from, &tokens(to)), &db_parts));
        }
        let reobserve = method(source, "RestoredKeeperBirth", "reobserve_database");
        assert!(ordered(
            &reobserve,
            &[
                "self.check_database(connection)?;",
                "self.owner.reobserve_writer()",
                "let checked=self.check_database(connection);",
                "self.owner.refuse();",
                "requested?;checked"
            ]
        ));
    }

    fn connection_drops_first(source: &str) -> bool {
        let file = syn::parse_file(source).unwrap();
        let mut found = false;
        for item in file.items {
            match item {
                syn::Item::Struct(item) if item.ident == "RestoredAppKeeper" => {
                    let syn::Fields::Named(fields) = item.fields else {
                        return false;
                    };
                    found = fields.named.len() == 2
                        && fields.named[0]
                            .ident
                            .as_ref()
                            .is_some_and(|id| id == "keeper")
                        && fields.named[1]
                            .ident
                            .as_ref()
                            .is_some_and(|id| id == "input");
                }
                syn::Item::Impl(item)
                    if matches!(&*item.self_ty,syn::Type::Path(path) if path.path.is_ident("RestoredAppKeeper"))
                        && item.trait_.is_some() =>
                {
                    return false;
                }
                _ => {}
            }
        }
        found
    }

    #[test]
    fn actual_keeper_drops_first_sqlite_before_raw_same_inode_files_without_earlier_drop_body() {
        let source = include_str!("../restored.rs");
        assert!(connection_drops_first(source));
        let changed = source.replacen(
            "keeper: crate::store::NativeSqliteKeeper,\n    input: RestoredActiveKeeperInput,",
            "input: RestoredActiveKeeperInput,\n    keeper: crate::store::NativeSqliteKeeper,",
            1,
        );
        assert_ne!(source, changed);
        assert!(!connection_drops_first(&changed));
        assert!(!connection_drops_first(&format!(
            "{source}\nimpl Drop for RestoredAppKeeper {{fn drop(&mut self){{}}}}"
        )));
    }
}

#[cfg(test)]
mod keeper_delivery_tests {
    use super::keeper_birth_tests::{method, ordered, tokens};

    fn delivery_is_closed(ack: &str, send: &str, receive: &str) -> bool {
        ordered(
            ack,
            &[
                "self.send_ack()?;",
                "self.receive_release()?;",
                "Ok(ReleasedRestoredApp {keeper:self})",
            ],
        ) && ordered(
            send,
            &[
                "self.reobserve()?;",
                "let cohort=self.keeper.cohort_data()?;",
                "RestoreBody::ActivatedAck",
                "self.check()?;",
                "key.sign(\"restored-storage-message\",&(&sender,&body))",
                "let checked=self.check();",
                "let signature=signed?;checked?;",
                "peer.channel.send_restore",
                "let checked=self.check();",
                "sent?;checked",
                "let checked=self.reobserve();",
                "self.keeper.refuse();",
                "requested?;checked",
            ],
        ) && ordered(
            receive,
            &[
                "peer.channel.receive_restore(&mut peer.process)",
                "let checked=self.check();",
                "let (message,mut receipt)=received?;checked?;",
                "receipt.bind(&message,&peer.controller,&mut peer.process)?;",
                "RestoreBody::Released",
                "exchange==peer.exchange.digest()?",
                "activation==day2_capabilities::Digest::of(&self.input.owner.activation)?",
                "peer.receipts.len()==4 && peer.channel.transcript.complete()",
                "peer.receipts.push(receipt);",
                "let checked=self.reobserve();",
                "self.keeper.refuse();",
                "requested?;checked",
            ],
        ) && [ack, send, receive].iter().all(|body| {
            ![
                "Runtime::load",
                "NativeAcquisition::begin",
                "open_existing",
                "Connection::open",
            ]
            .iter()
            .any(|part| body.contains(&tokens(part)))
        })
    }

    #[test]
    fn actual_ack_consumes_and_retains_the_real_first_keeper_through_signed_delivery_and_release() {
        let source = include_str!("activation.rs");
        let ack = method(source, "RestoredAppKeeper", "acknowledge");
        let send = method(source, "RestoredAppKeeper", "send_ack");
        let receive = method(source, "RestoredAppKeeper", "receive_release");
        assert!(ack.contains(&tokens("fn acknowledge(mut self)")));
        assert!(delivery_is_closed(&ack, &send, &receive));
        for (which, before, after) in [
            (0, "self.send_ack()?;", "let _unchecked=();"),
            (0, "self.receive_release()?;", "let _unchecked=();"),
            (
                1,
                "let cohort=self.keeper.cohort_data()?;",
                "let cohort=other_keeper.cohort_data()?;",
            ),
            (
                1,
                "let checked=self.check();",
                "let checked:Result<()>=Ok(());",
            ),
            (
                2,
                "receipt.bind(&message,&peer.controller,&mut peer.process)?;",
                "let _unauthenticated=();",
            ),
            (
                2,
                "exchange==peer.exchange.digest()?",
                "exchange==other_exchange",
            ),
            (
                2,
                "activation==day2_capabilities::Digest::of(&self.input.owner.activation)?",
                "true",
            ),
            (2, "peer.channel.transcript.complete()", "true"),
            (2, "peer.receipts.push(receipt);", "drop(receipt);"),
        ] {
            let mut bodies = [ack.clone(), send.clone(), receive.clone()];
            let before = tokens(before);
            assert!(bodies[which].contains(&before));
            bodies[which] = bodies[which].replacen(&before, &tokens(after), 1);
            assert!(!delivery_is_closed(&bodies[0], &bodies[1], &bodies[2]));
        }
        let reobserve = method(source, "RestoredAppKeeper", "reobserve");
        assert!(ordered(
            &reobserve,
            &[
                "self.check()?;",
                "self.input.owner.reobserve_writer()",
                "let checked=self.check();",
                "self.keeper.refuse();",
                "self.input.owner.refuse();",
                "requested?;checked"
            ]
        ));
    }
}

#[cfg(test)]
mod role_receive_source_tests {
    use super::keeper_birth_tests::{method, ordered, tokens};
    use quote::ToTokens;

    fn actual_factory(body: &str) -> bool {
        ordered(
            body,
            &[
                "fn receive_role_handoff(mut self)",
                "let mut attempt=RoleReceiveAttempt {keeper: &mut self.keeper,transcript:None,receipt:None,done:false};",
                "attempt.fresh()?;",
                "let requested:Result<super::super::protocol::SignedRestoreIssuerCompletion> =",
                "attempt.receive_role_packet()?;",
                "attempt.authenticate_completion(&message)?;",
                "attempt.narrow_originals(&completion)?;",
                "let checked=attempt.fresh();",
                "requested.is_err() || checked.is_err()",
                "attempt.refuse();",
                "let completion=requested?;checked?;",
                "attempt.require_completion(&completion)?;",
                "transcript.narrow_role_receive(observation.clone())?;",
                "transcript.delivered(Frame {protocol:Protocol::RestoredRole,step:Step::RoleReady,sequence:None},observation)?;",
                "transcript.complete()",
                "let role_transcript=attempt.transcript.take()",
                "let receipt=attempt.receipt.take()",
                "attempt.done=true;",
                "Ok(ReceivedRoleRestoredApp {keeper:self.keeper,receipt,completion,role_transcript})",
            ],
        ) && body.matches(&tokens("attempt.done=true;")).count() == 1
            && body
                .matches(&tokens(
                    "Ok(ReceivedRoleRestoredApp {keeper:self.keeper,receipt,completion,role_transcript})",
                ))
                .count()
                == 1
            && !body.contains(&tokens("NativeAcquisition::begin"))
            && !body.contains(&tokens("open_existing"))
    }

    #[test]
    fn actual_role_receive_consumes_the_first_keeper_and_only_postchecked_delivery_returns_it() {
        let binding: syn::Stmt = syn::parse_quote!(let requested: Result<super::super::protocol::SignedRestoreIssuerCompletion> = Ok(completion););
        assert!(
            tokens(&binding.to_token_stream().to_string()).starts_with(&tokens(
                "let requested:Result<super::super::protocol::SignedRestoreIssuerCompletion> ="
            ))
        );
        let source = include_str!("activation.rs");
        let actual = method(source, "ReleasedRestoredApp", "receive_role_handoff");
        assert!(actual_factory(&actual));
        for (before, after) in [
            ("done:false", "done:true"),
            ("attempt.fresh()?;", "let _unchecked=();"),
            (
                "attempt.authenticate_completion(&message)?;",
                "caller_completion;",
            ),
            (
                "attempt.narrow_originals(&completion)?;",
                "let _not_reduced=();",
            ),
            (
                "let checked=attempt.fresh();",
                "let checked=Ok::<(),anyhow::Error>(());",
            ),
            (
                "let completion=requested?;checked?;",
                "checked?;let completion=requested?;",
            ),
            ("keeper:self.keeper", "keeper:other_keeper"),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !actual_factory(&actual.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
        let mut premature = actual.replace(
            &tokens("attempt.done=true;"),
            &tokens("let _not_settled=();"),
        );
        let target = tokens("attempt.narrow_originals(&completion)?;");
        premature = premature.replacen(
            &target,
            &format!("{} {target}", tokens("attempt.done=true;")),
            1,
        );
        assert!(!actual_factory(&premature));
        let root = include_str!("../restored.rs");
        let drop = method(root, "RoleReceiveAttempt", "drop");
        assert!(ordered(
            &drop,
            &[
                "if !self.done",
                "self.keeper.keeper.refuse();",
                "self.keeper.input.owner.refuse();"
            ]
        ));
        let original_refusal = method(source, "ActiveRestoredReadIdentity", "refuse");
        assert!(ordered(
            &original_refusal,
            &[
                "self.captured.peer.process.receiver.refuse();",
                "self.original.refuse();"
            ]
        ));
        let root: syn::File = syn::parse_str(root).unwrap();
        let received = root
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "ReceivedRoleRestoredApp" => Some(item),
                _ => None,
            })
            .unwrap();
        assert!(
            received
                .fields
                .iter()
                .next()
                .unwrap()
                .ident
                .as_ref()
                .is_some_and(|name| name == "keeper")
        );
    }

    #[test]
    fn actual_clock_reductions_follow_authentication_and_keep_both_originals_under_refusal() {
        let source = include_str!("activation.rs");
        let narrow = method(source, "RoleReceiveAttempt", "narrow_originals");
        let actual = |body: &str| {
            ordered(
                body,
                &[
                    "self.require_completion(completion)?;",
                    "completion.statement.effective_deadline_ns",
                    "let native = &mut self.keeper.input.owner.captured.peer.process.receiver.original;",
                    "*native=native.narrow(5,ceiling)?;",
                    "let read = &mut self.keeper.input.owner.original;",
                    "*read=read.narrow(5,ceiling)?;",
                    "self.local_check()",
                ],
            )
        };
        assert!(actual(&narrow));
        for (before, after) in [
            (
                "self.require_completion(completion)?;",
                "let _unverified=();",
            ),
            ("*native=native.narrow(5,ceiling)?;", "let _not_reduced=();"),
            ("*read=read.narrow(5,ceiling)?;", "let _not_reduced=();"),
            ("read.narrow(5,ceiling)", "NativeAcquisition::begin(5)"),
        ] {
            let before = tokens(before);
            assert_eq!(narrow.matches(&before).count(), 1, "{before}");
            assert!(
                !actual(&narrow.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
        let authenticate = method(source, "RoleReceiveAttempt", "authenticate_completion");
        assert!(ordered(
            &authenticate,
            &[
                "self.local_check()?;",
                ".bind(message, &peer.controller, &mut peer.process)?;",
                "self.local_check()?;",
                "self.completion_data()?;",
                "payload.role_ready_data"
            ]
        ));
        let completion = method(source, "RoleReceiveAttempt", "require_completion");
        let completion_is_postchecked = |body: &str| {
            ordered(
                body,
                &[
                    "let requested=",
                    "self.completion_data()?;",
                    "completion.verify_data",
                    "let checked=self.local_check();",
                    "if requested.is_err() || checked.is_err() {self.refuse();}",
                    "requested?;checked",
                ],
            )
        };
        assert!(completion_is_postchecked(&completion));
        let target = tokens("let checked=self.local_check();");
        assert_eq!(completion.matches(&target).count(), 1);
        assert!(!completion_is_postchecked(&completion.replacen(
            &target,
            &tokens("let checked=Ok::<(),anyhow::Error>(());"),
            1
        )));
        let data = method(source, "RoleReceiveAttempt", "completion_data");
        assert!(data.contains(&tokens("cohort:self.keeper.keeper.cohort_data()?")));
        assert!(!data.contains(&tokens("caller_cohort")));
    }

    #[test]
    fn retained_role_receipt_rechecks_actual_authority_and_always_runs_the_final_keeper_post() {
        let source = include_str!("activation.rs");
        let actual = method(source, "ReceivedRoleRestoredApp", "check");
        let closed = |body: &str| {
            ordered(
                body,
                &[
                    "let requested=self.keeper.reobserve();",
                    "self.receipt.live(&mut peer.process)?;",
                    "self.role_transcript.complete()",
                    "cohort:self.keeper.keeper.cohort_data()?",
                    "self.completion.verify_data",
                    "let tail=self.keeper.check();",
                    "requested.is_err() || checked.is_err() || tail.is_err()",
                    "self.role_transcript.refuse();",
                    "self.keeper.keeper.refuse();self.keeper.input.owner.refuse();",
                    "requested?;checked?;tail",
                ],
            )
        };
        assert!(closed(&actual));
        for (before, after) in [
            (
                "let requested=self.keeper.reobserve();",
                "let requested=Ok::<(),anyhow::Error>(());",
            ),
            (
                "self.receipt.live(&mut peer.process)?;",
                "let _unobserved=();",
            ),
            ("self.role_transcript.complete()", "true"),
            (
                "cohort:self.keeper.keeper.cohort_data()?",
                "cohort:caller_cohort",
            ),
            (
                "let tail=self.keeper.check();",
                "let tail=Ok::<(),anyhow::Error>(());",
            ),
            ("requested?;checked?;tail", "tail?;requested?;checked"),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !closed(&actual.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
        let observation = method(source, "RoleReceiveAttempt", "observation");
        assert!(ordered(
            &observation,
            &[
                "self.keeper.input.owner.original.remaining()?;",
                "peer.process.receiver.original.remaining()?;",
                "read_domain==domain && read_origin==origin",
                "deadline:deadline.min(read_deadline)",
                "now:now.max(read_now)",
            ]
        ));
    }

    #[test]
    fn actual_role_local_check_preserves_history_and_independent_receipt_post() {
        let source = include_str!("activation.rs");
        let helper = method(source, "RoleReceiveAttempt", "check_prior_keeper");
        let guard = r#"ensure!(self.keeper.input.owner.captured.peer.receipts.len()==5 && self.keeper.input.owner.captured.peer.channel.transcript.complete(),"restore_role_receive_previous_incomplete");"#;
        assert!(ordered(&helper, &[guard, "self.keeper.check()"]));
        let guard = tokens(guard);
        assert_eq!(helper.matches(&guard).count(), 1);
        assert!(!ordered(
            &helper.replacen(&guard, "", 1),
            &[&guard, "self.keeper.check()"]
        ));
        let actual = method(source, "RoleReceiveAttempt", "local_check");
        let parts = [
            "let requested=self.check_prior_keeper();",
            "let checked",
            "receipt.live(&mut self.keeper.input.owner.captured.peer.process)",
            "requested.is_err() || checked.is_err()",
            "self.refuse();",
            "requested?;checked",
        ];
        assert!(ordered(&actual, &parts));
        let target = tokens("let requested=self.check_prior_keeper();");
        assert_eq!(actual.matches(&target).count(), 1);
        assert!(!ordered(
            &actual.replacen(
                &target,
                &tokens("let requested=Ok::<(),anyhow::Error>(());"),
                1
            ),
            &parts
        ));
    }

    #[test]
    fn actual_receive_and_poll_keep_the_same_socket_pidfd_and_independent_error_posts() {
        let source = include_str!("transport.rs");
        let receive = method(source, "RoleReceiveAttempt", "receive_role_packet");
        let parts = [
            "self.local_check()?;",
            "self.transcript.is_none() && self.receipt.is_none()",
            "peer.channel.transcript.derive_restored_role(observation.clone())?",
            ".begin(Direction::Receive,observation)?;",
            "let mut bytes=[0u8;MAX_PACKET];",
            "net::recv_pidfd_packet(&peer.channel.socket, &mut [IoSliceMut::new(&mut bytes)])",
            "let checked=self.local_check();",
            "RestoredControllerReceipt::received(ReceivedRestorePacket {packet,local_only:PhantomData}, &mut peer.process)?",
            "self.receipt=Some(receipt);",
            "self.local_check()?;",
            "storage_peer_wire::decode(&bytes[..count])",
            "let checked=self.local_check();",
            "if requested.is_err() || checked.is_err() {self.refuse();}",
            "let message=requested?;checked?;Ok(message)",
        ];
        let receive_is_closed = |body: &str| ordered(body, &parts);
        let mut rest = receive.as_str();
        for part in &parts {
            let expected = tokens(part);
            let at = rest
                .find(&expected)
                .unwrap_or_else(|| panic!("missing or reordered actual receive wiring: {part}"));
            rest = &rest[at + expected.len()..];
        }
        assert!(receive_is_closed(&receive));
        // The actual received-pidfd constructor is the tail expression of
        // its lexical block, not a semicolon-terminated statement.
        let receipt: syn::Expr = syn::parse_quote!(RestoredControllerReceipt::received(
            ReceivedRestorePacket {
                packet,
                local_only: PhantomData
            },
            &mut peer.process
        )?);
        assert!(receive.contains(&tokens(&receipt.to_token_stream().to_string())));
        let call: syn::Expr = syn::parse_quote!(net::recv_pidfd_packet(
            &peer.channel.socket,
            &mut [IoSliceMut::new(&mut bytes)]
        ));
        assert_eq!(
            tokens(&call.to_token_stream().to_string()),
            tokens(
                "net::recv_pidfd_packet(&peer.channel.socket, &mut [IoSliceMut::new(&mut bytes)])"
            )
        );
        for (before, after) in [
            (
                "net::recv_pidfd_packet(&peer.channel.socket, &mut [IoSliceMut::new(&mut bytes)])",
                "net::recv_pidfd_packet(&other_socket, &mut [IoSliceMut::new(&mut bytes)])",
            ),
            ("self.receipt=Some(receipt);", "let _discarded=receipt;"),
            (
                "let message=requested?;checked?;Ok(message)",
                "checked?;let message=requested?;Ok(message)",
            ),
        ] {
            let before = tokens(before);
            assert_eq!(receive.matches(&before).count(), 1);
            assert!(!receive_is_closed(&receive.replacen(
                &before,
                &tokens(after),
                1
            )));
        }
        let poll = method(source, "RoleReceiveAttempt", "poll_role_once");
        for required in [
            "observation.deadline.checked_sub(observation.now)",
            "PollFd::new(&peer.channel.socket,PollFlags::IN|PollFlags::RDHUP)",
            "PollFlags::HUP|PollFlags::RDHUP|PollFlags::ERR|PollFlags::NVAL",
            "let checked=self.local_check();",
            "let transport=requested?;checked?;Ok(transport)",
        ] {
            assert!(poll.contains(&tokens(required)), "{required}");
        }
        assert!(!poll.contains(&tokens("Duration::from_secs(5)")));
        assert!(!poll.contains(&tokens("NativeAcquisition::begin")));
        // These oracles inspect actual production methods, without creating a
        // portable Native Current, role, first keeper or received kernel handle.
        let parsed: syn::Block = syn::parse_quote!({
            let actual = &mut owner.original;
        });
        assert_eq!(
            tokens("{let actual = &mut owner.original;}"),
            tokens(&parsed.to_token_stream().to_string())
        );
    }
}

#[cfg(test)]
mod decision_receive_source_tests {
    use super::keeper_birth_tests::{method, ordered, tokens};
    use quote::ToTokens;

    fn factory_valid(actual: &str) -> bool {
        ordered(
            actual,
            &[
                "fn receive_role_decision(mut self)",
                "let mut attempt=DecisionReceiveAttempt {owner: &mut self,transcript:None,receipt:None,done:false};",
                "attempt.fresh()?;",
                "let message=attempt.receive_decision_packet()?;",
                "let decision=attempt.authenticate_decision(&message)?;",
                "attempt.narrow_originals(&decision)?;",
                "let checked=attempt.fresh();",
                "requested.is_err() || checked.is_err()",
                "attempt.refuse();",
                "let decision=requested?;checked?;",
                "attempt.require_decision(&decision)?;",
                "transcript.narrow_decision_receive(observation.clone())?;",
                "transcript.delivered(Frame {protocol:Protocol::RestoredDecision,step:Step::RoleDecision,sequence:None},observation)?;",
                r#"ensure!(transcript.complete(),"restore_decision_receive_incomplete");"#,
                "let transcript=attempt.transcript.take()",
                "let receipt=attempt.receipt.take()",
                "attempt.done=true;",
                "Ok(ReceivedDecisionRestoredApp {received:self,receipt,decision,transcript})",
            ],
        ) && !actual.contains(&tokens("NativeAcquisition::begin"))
            && !actual.contains(&tokens("open_existing"))
    }

    #[test]
    fn actual_decision_receive_consumes_the_same_role_and_keeper_after_all_posts() {
        // Pin source punctuation to real syn output without erasing the
        // borrow or constructor identity in these non-executed syntax controls.
        let constructor: syn::Stmt = syn::parse_quote!(let mut attempt=DecisionReceiveAttempt {owner: &mut self,transcript:None,receipt:None,done:false};);
        assert_eq!(
            tokens(
                "let mut attempt=DecisionReceiveAttempt {owner: &mut self,transcript:None,receipt:None,done:false};"
            ),
            tokens(&constructor.to_token_stream().to_string())
        );
        for witness in [
            "let native= &mut self.owner.keeper.input.owner.captured.peer.process.receiver.original;",
            "let read= &mut self.owner.keeper.input.owner.original;",
        ] {
            let parsed: syn::Stmt = syn::parse_str(witness).unwrap();
            assert_eq!(
                tokens(witness),
                tokens(&parsed.to_token_stream().to_string())
            );
        }
        let actual = method(
            include_str!("activation.rs"),
            "ReceivedRoleRestoredApp",
            "receive_role_decision",
        );
        assert!(factory_valid(&actual));
        for before in [
            "done:false",
            "attempt.fresh()?;",
            "attempt.authenticate_decision(&message)?;",
            "attempt.narrow_originals(&decision)?;",
            "let checked=attempt.fresh();",
            "let decision=requested?;checked?;",
            "attempt.require_decision(&decision)?;",
            "transcript.narrow_decision_receive(observation.clone())?;",
            "attempt.done=true;",
        ] {
            let before = tokens(before);
            let count = actual.matches(&before).count();
            assert_eq!(count, 1, "{before}");
            assert!(!factory_valid(&actual.replacen(&before, "", 1)), "{before}");
        }
        let drop = method(
            include_str!("../restored.rs"),
            "DecisionReceiveAttempt",
            "drop",
        );
        assert!(ordered(&drop, &["if !self.done", "self.owner.refuse();"]));
        let narrow = method(
            include_str!("activation.rs"),
            "DecisionReceiveAttempt",
            "narrow_originals",
        );
        assert!(ordered(
            &narrow,
            &[
                "self.require_decision(decision)?;",
                "let ceiling=std::time::Duration::from_nanos(decision.statement.effective_deadline_ns);",
                "let native= &mut self.owner.keeper.input.owner.captured.peer.process.receiver.original;",
                "*native=native.narrow(5,ceiling)?;",
                "let read= &mut self.owner.keeper.input.owner.original;",
                "*read=read.narrow(5,ceiling)?;",
                "self.local_check()",
            ]
        ));
    }

    #[test]
    fn decision_receive_authenticates_actual_controller_and_retained_completion_before_reduction() {
        let auth = method(
            include_str!("activation.rs"),
            "DecisionReceiveAttempt",
            "authenticate_decision",
        );
        assert!(ordered(
            &auth,
            &[
                "self.local_check()?;",
                r#"self.receipt.as_mut().context("restore_decision_receive_receipt_missing")?.bind(message,&peer.controller,&mut peer.process)?;"#,
                "self.local_check()?;",
                "payload.role_decision_data(&peer.exchange.digest()?,&self.owner.completion,&peer.process.receiver.policy,&peer.process.certificate,&peer.local,peer.process.receiver.original.sample()?.elapsed)?",
            ]
        ));
        let check = method(
            include_str!("activation.rs"),
            "ReceivedDecisionRestoredApp",
            "check",
        );
        let parts = [
            "let requested=self.received.check();",
            r#"ensure!(self.transcript.complete(),"restore_decision_history_incomplete");"#,
            "self.receipt.live(&mut peer.process)?;",
            "self.decision.verify_data(&peer.process.receiver.policy,&peer.process.certificate,&self.received.completion,&peer.local,(&self.decision.statement.request,&self.decision.statement.challenge),peer.process.receiver.original.sample()?.elapsed)",
            "let tail=self.received.keeper.check();",
            "requested.is_err() || checked.is_err() || tail.is_err()",
            "self.transcript.refuse();self.received.refuse();",
            "requested?;checked?;tail",
        ];
        assert!(ordered(&check, &parts));
        for before in parts {
            let before = tokens(before);
            assert_eq!(check.matches(&before).count(), 1);
            assert!(!ordered(&check.replacen(&before, "", 1), &parts));
        }
    }

    #[test]
    fn decision_receive_keeps_actual_pidfd_before_decode_and_checks_io_errors() {
        let receive = method(
            include_str!("transport.rs"),
            "DecisionReceiveAttempt",
            "receive_decision_packet",
        );
        let parts = [
            "self.owner.role_transcript.derive_restored_decision(observation.clone())?;",
            "transcript",
            "self.local_check()?;",
            "net::recv_pidfd_packet(&peer.channel.socket,&mut [IoSliceMut::new(&mut bytes)])",
            "let checked=self.local_check();",
            "Err(error)",
            "let _=checked;return Err(error.into());",
            "RestoredControllerReceipt::received(ReceivedRestorePacket {packet,local_only:PhantomData},&mut peer.process)?",
            "self.receipt=Some(receipt);",
            "self.local_check()?;",
            "super::super::storage_peer_wire::decode(&bytes[..count])",
            "let checked=self.local_check();",
            "requested.is_err() || checked.is_err()",
            "self.refuse();",
            "let message=requested?;checked?;Ok(message)",
        ];
        assert!(ordered(&receive, &parts));
        for before in [
            "self.owner.role_transcript.derive_restored_decision(observation.clone())?;",
            "self.receipt=Some(receipt);",
            "let message=requested?;checked?;Ok(message)",
        ] {
            let before = tokens(before);
            assert_eq!(receive.matches(&before).count(), 1);
            assert!(!ordered(&receive.replacen(&before, "", 1), &parts));
        }
        let poll = method(
            include_str!("transport.rs"),
            "DecisionReceiveAttempt",
            "poll_decision_once",
        );
        assert!(ordered(
            &poll,
            &[
                "self.local_check()?;",
                "self.observation()?;",
                "observation.deadline.checked_sub(observation.now)",
                "PollFlags::IN | PollFlags::RDHUP",
                "rustix::event::poll(&mut fds,Some(&timeout))",
                "let checked=self.local_check();",
                "requested.is_err() || checked.is_err()",
                "self.refuse();",
                "let transport=requested?;checked?;Ok(transport)",
            ]
        ));
    }
}

#[cfg(test)]
mod prepared_confirmation_client_source_tests {
    use super::keeper_birth_tests::{method, ordered, tokens};
    use syn::visit::Visit;

    #[test]
    fn actual_prepared_client_consumes_the_same_app_and_retains_each_actual_issuer_before_data() {
        let source = include_str!("activation.rs");
        let actual = method(source, "ReceivedDecisionRestoredApp", "confirm_with_issuer");
        let parts = [
            "input:Some(self)",
            "complete:false",
            "refused:false",
            "attempt.check()?;",
            r#"let request=protocol::nonce("restore-app-prepared-request");"#,
            "let checked=attempt.check();let request=request?;checked?;",
            "attempt.request=Some(request.clone());",
            "Channel::connect(&mut input.received.keeper.input.owner.captured.peer.process.receiver.original)",
            "let checked=attempt.check();let channel=connected?;checked?;attempt.channel=Some(channel);",
            "Packet::RestoreAppConfirmHello",
            "let checked=attempt.check();sent?;checked?;",
            "let received",
            "let checked=attempt.check();",
            "let (packet,mut receipt)=received?;",
            "receipt.bind(&process.certificate,&process.receiver.policy,&mut process.receiver.original)",
            "attempt.nonce_peer=Some(receipt);",
            "let receipt_post=attempt.check();checked?;bound?;receipt_post?;",
            "let Packet::RestoreAppConfirmNonce",
            "echoed_decision==decision.digest_data()? && echoed==request",
            "attempt.challenge=Some(challenge.clone());",
            r#".key.sign("restore-app-prepared-bind-v1",&(&decision,&request,&challenge))"#,
            "let checked=attempt.check();let signature=signed?;checked?;",
            "Packet::RestoreAppConfirmBind",
            "let checked=attempt.check();sent?;checked?;",
            "let received",
            "let checked=attempt.check();let (packet,mut receipt)=received?;",
            "receipt.bind(&process.certificate,&process.receiver.policy,&mut process.receiver.original)",
            "attempt.grant_peer=Some(receipt);",
            "let receipt_post=attempt.check();checked?;bound?;receipt_post?;",
            "let Packet::RestoreAppConfirmGrant",
            "confirmation.verify_data",
            "*native=native.narrow(5,ceiling)?;",
            "*read=read.narrow(5,ceiling)?;",
            "attempt.confirmation=Some(*confirmation);",
            "attempt.complete=true;",
            "let checked=attempt.check();",
            "requested.is_err() || checked.is_err()",
            "attempt.refuse();",
            "requested?;checked?;",
            "Ok(PreparedConfirmedRestoredApp {pending:attempt})",
        ];
        assert!(ordered(&actual, &parts));
        for before in [
            "input:Some(self)",
            "attempt.nonce_peer=Some(receipt);",
            "attempt.grant_peer=Some(receipt);",
            "attempt.challenge=Some(challenge.clone());",
            "*native=native.narrow(5,ceiling)?;",
            "*read=read.narrow(5,ceiling)?;",
            "attempt.complete=true;",
            "requested?;checked?;",
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !ordered(&actual.replacen(&before, "", 1), &parts),
                "{before}"
            );
        }
        for forbidden in [
            "NativeAcquisition::begin",
            "KeyOwner::generate",
            "store::open",
            "open_existing",
            "Runtime::",
        ] {
            assert!(!actual.contains(&tokens(forbidden)));
        }
        // Only this actual consuming method constructs either retained owner.
        struct Origins {
            method: Option<String>,
            pending: Vec<String>,
            prepared: Vec<String>,
        }
        impl<'ast> Visit<'ast> for Origins {
            fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                let prior = self.method.replace(item.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, item);
                self.method = prior;
            }
            fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                if item.path.is_ident("AppIssuerConfirmation") {
                    self.pending.push(self.method.clone().unwrap_or_default());
                }
                if item.path.is_ident("PreparedConfirmedRestoredApp") {
                    self.prepared.push(self.method.clone().unwrap_or_default());
                }
                syn::visit::visit_expr_struct(self, item);
            }
        }
        let mut origins = Origins {
            method: None,
            pending: vec![],
            prepared: vec![],
        };
        origins.visit_file(&syn::parse_file(source).unwrap());
        assert_eq!(origins.pending, ["confirm_with_issuer"]);
        assert_eq!(origins.prepared, ["confirm_with_issuer"]);
        let drop = method(
            include_str!("../restored.rs"),
            "AppIssuerConfirmation",
            "drop",
        );
        assert!(drop.contains(&tokens("self.refuse();")));
        // Syntax/ownership controls only; no native process or receipt is minted.
    }

    #[test]
    fn prepared_client_checks_current_authority_all_retained_issuer_handles_and_final_keeper_on_error()
     {
        let actual = method(
            include_str!("activation.rs"),
            "AppIssuerConfirmation",
            "check",
        );
        let parts = [
            "if self.refused",
            "let requested",
            "input.check()",
            "let checked",
            "self.nonce_peer",
            "receipt.check_live(&mut peer.process.receiver.original)?;",
            "self.grant_peer",
            "receipt.check_live(&mut peer.process.receiver.original)?;",
            "if self.complete",
            "self.channel.is_some() && self.nonce_peer.is_some() && self.grant_peer.is_some() && self.confirmation.is_some()",
            "confirmation.verify_data",
            "self.request.as_ref()",
            "self.challenge.as_ref()",
            "let tail",
            ".received.keeper.check()",
            "requested.is_err() || checked.is_err() || tail.is_err()",
            "self.refuse();",
            "requested?;checked?;tail",
        ];
        assert!(ordered(&actual, &parts));
        for before in [
            "input.check()",
            "confirmation.verify_data",
            ".received.keeper.check()",
            "self.refuse();",
            "requested?;checked?;tail",
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(!ordered(&actual.replacen(&before, "", 1), &parts));
        }
        let prepared = method(
            include_str!("activation.rs"),
            "PreparedConfirmedRestoredApp",
            "check",
        );
        assert!(ordered(
            &prepared,
            &[
                "!self.pending.complete",
                "self.pending.refuse();",
                "self.pending.check()"
            ]
        ));
    }
}

#[cfg(test)]
mod prepared_acceptance_source_tests {
    use super::keeper_birth_tests::tokens;
    use quote::ToTokens;
    use syn::visit::Visit;

    fn method(source: &str, owner: &str, name: &str) -> String {
        let file = syn::parse_file(source).unwrap();
        let actual = file
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                let syn::Type::Path(path) = &*item.self_ty else {
                    return None;
                };
                if !path.path.is_ident(owner) {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == name => {
                        Some(method.to_token_stream())
                    }
                    _ => None,
                })
            })
            .unwrap();
        tokens(&actual.to_string())
    }

    fn ordered(actual: &str, parts: &[&str]) -> bool {
        let mut rest = actual;
        for part in parts {
            let part = tokens(part);
            let Some(index) = rest.find(&part) else {
                return false;
            };
            rest = &rest[index + part.len()..];
        }
        true
    }

    #[test]
    fn actual_app_consumes_preparation_and_requires_native_acceptance_before_returning() {
        let source = include_str!("activation.rs");
        let actual = method(
            source,
            "PreparedConfirmedRestoredApp",
            "await_controller_acceptance",
        );
        let parts = [
            "input:Some(self)",
            "attempt.check()?;",
            "attempt.prepare_ack()?;",
            "attempt.send_prepared_ack()?;",
            "attempt.receive_prepared_acceptance()?;",
            "attempt.authenticate_acceptance(&message)?;",
            "attempt.check()?;",
            "transcript.narrow_prepared_acceptance(observation.clone())?;",
            "Step::PreparedAccepted",
            r#"ensure!(transcript.complete(),"restore_prepared_acceptance_incomplete");"#,
            "attempt.accepted=true;",
            "let checked=attempt.check();",
            "requested.is_err() || checked.is_err()",
            "attempt.refuse();",
            "requested?;checked?;",
            r#"Ok(AcceptedRestoredApp {pending:attempt,installed_attempted:false,#[cfg(target_os="linux")] installed:None})"#,
        ];
        assert!(ordered(&actual, &parts));
        for target in [
            "input:Some(self)",
            "attempt.receive_prepared_acceptance()?;",
            "attempt.authenticate_acceptance(&message)?;",
            "transcript.narrow_prepared_acceptance(observation.clone())?;",
            "attempt.accepted=true;",
            "requested?;checked?;",
        ] {
            let target = tokens(target);
            assert_eq!(actual.matches(&target).count(), 1);
            assert!(!ordered(&actual.replacen(&target, "", 1), &parts));
        }
        for forbidden in [
            "NativeAcquisition::begin",
            "KeyOwner::generate",
            "store::open",
            "Runtime::",
            "install_into",
        ] {
            assert!(!actual.contains(&tokens(forbidden)));
        }
        #[derive(Default)]
        struct Origins {
            name: Option<String>,
            attempt: Vec<String>,
            accepted: Vec<String>,
        }
        impl<'ast> Visit<'ast> for Origins {
            fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                let prior = self.name.replace(item.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, item);
                self.name = prior;
            }
            fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                if item.path.is_ident("AppPreparedHandoff") {
                    self.attempt.push(self.name.clone().unwrap_or_default());
                }
                if item.path.is_ident("AcceptedRestoredApp") {
                    self.accepted.push(self.name.clone().unwrap_or_default());
                }
                syn::visit::visit_expr_struct(self, item);
            }
        }
        let mut origins = Origins::default();
        origins.visit_file(&syn::parse_file(source).unwrap());
        assert_eq!(origins.attempt, ["await_controller_acceptance"]);
        assert_eq!(origins.accepted, ["await_controller_acceptance"]);
        assert!(
            method(include_str!("../restored.rs"), "AppPreparedHandoff", "drop")
                .contains(&tokens("self.refuse();"))
        );
    }

    #[test]
    fn actual_acceptance_authenticates_known_controller_before_meeting_both_originals() {
        let actual = method(
            include_str!("activation.rs"),
            "AppPreparedHandoff",
            "authenticate_acceptance",
        );
        let parts = [
            "let bound",
            r#"self.receipt.as_mut().context("restore_prepared_acceptance_sender_missing")?.bind(message,&peer.controller,&mut peer.process)"#,
            "let checked=self.check();bound?;checked?;",
            ".keeper.cohort_data()?;",
            "payload.prepared_acceptance_deadline_data",
            "*native=native.narrow(5,ceiling)?;",
            "*read=read.narrow(5,ceiling)?;",
            "let checked=self.check();",
            "self.refuse();",
            "requested?;checked",
        ];
        assert!(ordered(&actual, &parts));
        for target in [
            "let checked=self.check();bound?;checked?;",
            "*native=native.narrow(5,ceiling)?;",
            "*read=read.narrow(5,ceiling)?;",
        ] {
            let target = tokens(target);
            assert_eq!(actual.matches(&target).count(), 1);
            assert!(!ordered(&actual.replacen(&target, "", 1), &parts));
        }
        let check = method(include_str!("activation.rs"), "AppPreparedHandoff", "check");
        assert!(ordered(
            &check,
            &[
                "let requested",
                ".check()",
                "let checked",
                "receipt.live(&mut peer.process)?;",
                "let tail",
                ".received.keeper.check()",
                "requested?;checked?;tail"
            ]
        ));
        let send = method(
            include_str!("transport.rs"),
            "AppPreparedHandoff",
            "send_prepared_ack",
        );
        assert!(ordered(
            &send,
            &[
                "transcript.begin(Direction::Send,observation)?;",
                "net::send",
                "let checked=self.check();",
                "match sent",
                "count==bytes.len()",
                ".delivered(frame,observation)?;",
                "self.ack_delivered=true;"
            ]
        ));
        let receive = method(
            include_str!("transport.rs"),
            "AppPreparedHandoff",
            "receive_prepared_acceptance",
        );
        assert!(ordered(
            &receive,
            &[
                ".begin(Direction::Receive,observation)?;",
                "net::recv_pidfd_packet",
                "let checked=self.check();",
                "match received",
                "RestoredControllerReceipt::received",
                "self.receipt=Some(receipt);",
                "self.check()?;",
                "storage_peer_wire::decode"
            ]
        ));
        let wait = method(
            include_str!("transport.rs"),
            "AppPreparedHandoff",
            "wait_prepared",
        );
        assert!(ordered(
            &wait,
            &[
                "observation.deadline.checked_sub(observation.now)",
                "rustix::event::poll",
                "let checked=self.check();let transport=polled?;checked?;"
            ]
        ));
    }
}

#[cfg(test)]
mod common_factory_source_tests {
    use super::keeper_birth_tests::tokens;
    use quote::ToTokens;
    use syn::visit::Visit;

    fn method(source: &str, owner: &str, name: &str) -> syn::ImplItemFn {
        syn::parse_file(source)
            .unwrap()
            .items
            .into_iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                let syn::Type::Path(path) = &*item.self_ty else {
                    return None;
                };
                if !path
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == owner)
                {
                    return None;
                }
                item.items.into_iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                    _ => None,
                })
            })
            .unwrap()
    }

    fn unguarded_factory(method: &syn::ImplItemFn, name: &str) -> bool {
        struct Calls<'name> {
            name: &'name str,
            gated: usize,
            actual: usize,
        }
        impl<'ast> Visit<'ast> for Calls<'_> {
            fn visit_expr_block(&mut self, item: &'ast syn::ExprBlock) {
                let cfg = item
                    .attrs
                    .iter()
                    .any(|attribute| attribute.path().is_ident("cfg"));
                self.gated += usize::from(cfg);
                syn::visit::visit_expr_block(self, item);
                self.gated -= usize::from(cfg);
            }
            fn visit_expr_call(&mut self, item: &'ast syn::ExprCall) {
                if self.gated == 0
                    && matches!(&*item.func,syn::Expr::Path(path) if path.path.segments.last().is_some_and(|part|part.ident==self.name))
                {
                    self.actual += 1;
                }
                syn::visit::visit_expr_call(self, item);
            }
        }
        let mut calls = Calls {
            name,
            gated: 0,
            actual: 0,
        };
        calls.visit_block(&method.block);
        calls.actual == 1
    }

    #[test]
    fn restored_snapshot_validator_export_is_available_to_the_shared_factory() {
        fn exported(source: &str) -> bool {
            let file = syn::parse_file(source).unwrap();
            let selected = file
                .items
                .iter()
                .filter_map(|item| match item {
                    syn::Item::Use(item)
                        if item.tree.to_token_stream().to_string()
                            == "native_storage :: admit_restored_snapshot" =>
                    {
                        Some(item)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            selected.len() == 1
                && selected[0].attrs.is_empty()
                && matches!(selected[0].vis, syn::Visibility::Restricted(_))
        }
        let source = include_str!("../../../store.rs");
        assert!(exported(source));
        let target = "pub(crate) use native_storage::admit_restored_snapshot;";
        assert_eq!(source.matches(target).count(), 1);
        let gated = source.replacen(
            target,
            &format!("#[cfg(target_os = \"linux\")]\n{target}"),
            1,
        );
        assert_ne!(gated, source);
        assert!(!exported(&gated));
        assert!(!exported(&source.replacen(target, "", 1)));
    }

    #[test]
    fn actual_restore_factories_share_one_body_and_keep_native_refusal_before_io() {
        for (source, owner, name, call) in [
            (
                include_str!("activation.rs"),
                "RestoredActiveKeeperInput",
                "create_keeper",
                "create_restored",
            ),
            (
                include_str!("activation.rs"),
                "RestoredKeeperBirth",
                "check_database",
                "require_original_main",
            ),
            (
                include_str!("artifact.rs"),
                "RestoredReadIdentity",
                "admit_installed_artifact",
                "load_restored_app",
            ),
            (
                include_str!("configuration.rs"),
                "RestoredKeeperBirth",
                "admit_database",
                "admit_restored_snapshot",
            ),
        ] {
            let actual = method(source, owner, name);
            assert!(unguarded_factory(&actual, call), "{owner}::{name}");
            let mut gated = actual.clone();
            let body = gated.block.clone();
            gated.block = syn::parse_quote!({#[cfg(target_os="linux")] {#body}});
            assert!(!unguarded_factory(&gated, call), "{owner}::{name}");
            let text = tokens(&actual.block.to_token_stream().to_string());
            let (guard, selected) = if name == "admit_installed_artifact" {
                (
                    "InstalledArtifact::capture(&mut self)?",
                    "LoadedArtifact::load_restored_app",
                )
            } else if name == "admit_database" {
                (
                    "self.check_database(connection)?;",
                    "crate::store::admit_restored_snapshot",
                )
            } else {
                ("self.check()?;", call)
            };
            assert!(text.find(&tokens(guard)).unwrap() < text.find(&tokens(selected)).unwrap());
            assert!(!text.contains(&tokens("NativeAcquisition::begin")));
        }
    }

    #[test]
    fn actual_open_sql_unit_refuses_before_any_native_file_or_authority_precheck() {
        let actual = method(
            include_str!("activation.rs"),
            "RestoredKeeperBirth",
            "check_database",
        );
        let actual = tokens(&actual.block.to_token_stream().to_string());
        let parts = [
            "let closed:Result<()>",
            r#"anyhow::ensure!(connection.is_autocommit(),"restore_keeper_sql_unit_still_open");"#,
            "if closed.is_err()",
            "self.owner.refuse();",
            "closed?;",
            "self.check()?;",
            "NativeSqliteKeeper::require_original_main",
        ];
        fn ordered(actual: &str, parts: &[&str]) -> bool {
            let mut rest = actual;
            for part in parts {
                let part = tokens(part);
                let Some(at) = rest.find(&part) else {
                    return false;
                };
                rest = &rest[at + part.len()..];
            }
            true
        }
        assert!(ordered(&actual, &parts));
        let target = tokens("closed?;");
        assert_eq!(actual.matches(&target).count(), 1);
        assert!(!ordered(&actual.replacen(&target, "", 1), &parts));
        // Moving the guard past the actual first native check is rejected.
        let late = actual.replacen(
            &format!("{target} {}", tokens("self.check()?;")),
            &format!("{} {target}", tokens("self.check()?;")),
            1,
        );
        assert_ne!(late, actual);
        assert!(!ordered(&late, &parts));
    }

    #[test]
    fn actual_birth_label_is_bound_to_the_current_app_before_snapshot_validation() {
        let check = method(
            include_str!("configuration.rs"),
            "RestoredKeeperBirth",
            "check",
        );
        let actual = tokens(&check.block.to_token_stream().to_string());
        let guard = tokens(
            r#"ensure!(self.app==self.owner.captured.peer.process.receiver.policy.store.scope.app.as_str(),"restore_keeper_app_label_changed");"#,
        );
        assert_eq!(actual.matches(&guard).count(), 1);
        let material = tokens("RestoredMaterialBorrow::active");
        assert!(actual.find(&guard).unwrap() < actual.find(&material).unwrap());
        assert!(!actual.replacen(&guard, "", 1).contains(&guard));
        let admitted = method(
            include_str!("configuration.rs"),
            "RestoredKeeperBirth",
            "admit_database",
        );
        assert!(
            tokens(&admitted.block.to_token_stream().to_string()).contains(&tokens("&self.app"))
        );
        let selector = method(
            include_str!("activation.rs"),
            "RestoredActiveKeeperInput",
            "keeper_birth_data",
        );
        let selector = tokens(&selector.block.to_token_stream().to_string());
        assert!(selector.contains(&tokens(
            "let scope= &self.owner.captured.peer.process.receiver.policy.store.scope;"
        )));
        for forbidden in [
            "NativeAcquisition::begin",
            "Connection::open",
            "KeyOwner::generate",
            "std::fs::read",
        ] {
            assert!(!selector.contains(&tokens(forbidden)));
        }
    }
}

impl RestoredAppHistory {
    /// SAME retained socket and received pidfds only, under the actual current
    /// local stage/acquisition. Historical statement DATA is identity, never a
    /// grant: the later Current exchange must still authenticate fresh remote
    /// purpose/interval/nonce and complete the genuine installed handoff.
    /// No old Accepted/Pending clock, check, transcript or I/O path is entered.
    pub(in crate::security_epoch::native_enrollment) fn check_current_peer_anchors(
        &self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let mut loan = RestoredHistoryLoan::take(self)?;
        let requested = loan
            .history
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("restore_history_loan_missing"))
            .and_then(|accepted| accepted.check_current_peer_anchors(stage, acquisition));
        let checked = stage
            .storage()
            .and_then(|mut storage| storage.check_storage_acquisition(acquisition));
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let restored = loan.finish();
        requested?;
        checked?;
        restored
    }
}

impl RestoredAppHistory {
    /// Fixed installed exchange only. The actual same first keeper stays in the
    /// private loan across signing, socket waits, authentication and all posts.
    pub(in crate::security_epoch::native_enrollment) fn confirm_installation(
        &self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        let mut loan = RestoredHistoryLoan::take(self)?;
        let owner = loan
            .history
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("restore_history_loan_missing"))?;
        let requested = AppInstalledHandoff {
            owner,
            stage,
            #[cfg(target_os = "linux")]
            original: None,
            #[cfg(target_os = "linux")]
            transcript: None,
            #[cfg(target_os = "linux")]
            acknowledgement: None,
            #[cfg(target_os = "linux")]
            receipt: None,
            ack_delivered: false,
            accepted: false,
            done: false,
        }
        .perform();
        let checked = stage.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
            stage.refuse_serving();
        }
        let retained = loan.finish();
        requested?;
        checked?;
        retained
    }
}

impl AppInstalledHandoff<'_, '_, '_> {
    pub(super) fn refuse(&mut self) {
        self.owner.refuse();
        self.stage.refuse_serving();
        #[cfg(target_os = "linux")]
        {
            if let Some(original) = &mut self.original {
                original.refuse();
            }
            if let Some(transcript) = &mut self.transcript {
                transcript.refuse();
            }
        }
    }

    pub(super) fn check(&mut self) -> Result<()> {
        let requested = self.owner.check();
        #[cfg(not(target_os = "linux"))]
        let checked: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        #[cfg(target_os = "linux")]
        let checked: Result<()> = (|| {
            use anyhow::Context;
            self.stage.require_current_role()?;
            if let Some(original) = &mut self.original {
                self.stage.storage()?.check_storage_acquisition(original)?;
                let actual = self
                    .owner
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_handoff_input_missing")?
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_input_missing")?;
                let owner = &mut actual.received.keeper.input.owner;
                original.exchange_current_views(&mut owner.original)?;
                original
                    .exchange_current_views(&mut owner.captured.peer.process.receiver.original)?;
                if let Some(receipt) = &mut self.receipt {
                    receipt.live(&mut owner.captured.peer.process)?;
                }
                self.stage.storage()?.check_storage_acquisition(original)?;
            }
            Ok(())
        })();
        let tail = self.owner.check();
        let post = self.stage.check();
        if requested.is_err() || checked.is_err() || tail.is_err() || post.is_err() {
            self.owner.refuse();
            self.stage.refuse_serving();
            #[cfg(target_os = "linux")]
            if let Some(original) = &mut self.original {
                original.refuse();
            }
        }
        requested?;
        checked?;
        tail?;
        post
    }

    pub(super) fn observation(&mut self) -> Result<super::super::handshake::Observation> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let retained = self.owner.pending.observation()?;
            let original = self
                .original
                .as_mut()
                .context("restore_installed_app_original_missing")?;
            original.remaining()?;
            let (domain, origin, deadline, now) = original.historical_interval_observation();
            ensure!(
                domain == retained.domain && origin == retained.origin,
                "restore_installed_app_original_changed"
            );
            Ok(super::super::handshake::Observation {
                domain,
                origin,
                deadline: deadline.min(retained.deadline),
                now: now.max(retained.now),
            })
        }
    }

    fn perform(mut self) -> Result<()> {
        if self.owner.installed_attempted {
            self.owner.refuse();
            anyhow::bail!("restore_installed_app_attempt_spent");
        }
        self.owner.installed_attempted = true;
        self.check()?;
        let requested: Result<()> = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                self.original = Some(self.stage.narrow_io_acquisition(5)?);
                self.check()?;
                self.prepare_installed_ack()?;
                self.send_installed_ack()?;
                let message = self.receive_installed_acceptance()?;
                self.authenticate_installed_acceptance(&message)?;
                let observation = self.observation()?;
                let transcript = self
                    .transcript
                    .as_mut()
                    .context("restore_installed_app_transcript_missing")?;
                transcript.narrow_installed_acceptance(observation.clone())?;
                transcript.delivered(message.body.frame(), observation)?;
                ensure!(
                    transcript.complete(),
                    "restore_installed_app_exchange_incomplete"
                );
                self.accepted = true;
                self.check()?;
                self.owner.installed = Some(self.retain_installed_history(message)?);
                Ok(())
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.owner.refuse();
            self.stage.refuse_serving();
        }
        requested?;
        checked?;
        self.done = true;
        Ok(())
    }

    fn prepare_installed_ack(&mut self) -> Result<()> {
        self.check()?;
        let requested: Result<()> = (|| {
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                ensure!(
                    !self.ack_delivered
                        && !self.accepted
                        && self.transcript.is_none()
                        && self.acknowledgement.is_none(),
                    "restore_installed_app_ack_spent"
                );
                let statement = self.stage.storage()?.storage_statement()?;
                let observation = self.observation()?;
                let prepared = self
                    .owner
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_handoff_input_missing")?;
                let confirmation = prepared
                    .pending
                    .confirmation
                    .as_ref()
                    .context("restore_prepared_confirmation_missing")?;
                let actual = prepared
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_input_missing")?;
                self.transcript = Some(
                    self.owner
                        .pending
                        .transcript
                        .as_mut()
                        .context("restore_prepared_handoff_history_missing")?
                        .derive_restored_installation(observation)?,
                );
                let cohort = actual.received.keeper.keeper.cohort_data()?;
                let peer = &mut actual.received.keeper.input.owner.captured.peer;
                let payload = RestoreBody::AppInstalled {
                    exchange: peer.exchange.digest()?,
                    prepared: confirmation.digest_data()?,
                    cohort,
                    app: Box::new(statement),
                };
                payload.installed_confirmation_data(
                    &peer.exchange.digest()?,
                    (confirmation, &actual.decision, &actual.received.completion),
                    &peer.process.receiver.policy,
                    &peer.local,
                    peer.process.receiver.original.sample()?.elapsed,
                )?;
                let body = Body::Restore { payload };
                let sender = peer.local.digest()?;
                self.check()?;
                let signed = {
                    let actual = self
                        .owner
                        .pending
                        .input
                        .as_mut()
                        .context("restore_prepared_handoff_input_missing")?
                        .pending
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    actual
                        .received
                        .keeper
                        .input
                        .owner
                        .captured
                        .peer
                        .process
                        .receiver
                        .key
                        .sign("restored-storage-message", &(&sender, &body))
                };
                let checked = self.check();
                let signature = signed?;
                checked?;
                self.acknowledgement = Some(Message {
                    sender,
                    body,
                    signature,
                });
                Ok(())
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.owner.refuse();
            self.stage.refuse_serving();
        }
        requested?;
        checked
    }

    fn authenticate_installed_acceptance(
        &mut self,
        message: &super::super::storage_peer_wire::Message,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            self.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = message;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                ensure!(
                    self.ack_delivered && !self.accepted,
                    "restore_installed_app_acceptance_order"
                );
                let actual = self
                    .owner
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_handoff_input_missing")?
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_input_missing")?;
                let peer = &mut actual.received.keeper.input.owner.captured.peer;
                let bound = self
                    .receipt
                    .as_mut()
                    .context("restore_installed_app_receipt_missing")?
                    .bind(message, &peer.controller, &mut peer.process);
                let checked = self.check();
                bound?;
                checked?;
                let actual = self
                    .owner
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_handoff_input_missing")?
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_input_missing")?;
                let peer = &mut actual.received.keeper.input.owner.captured.peer;
                let Body::Restore { payload } = &message.body else {
                    anyhow::bail!("restore_installed_app_acceptance_kind");
                };
                let Body::Restore { payload: installed } = &self
                    .acknowledgement
                    .as_ref()
                    .context("restore_installed_app_ack_missing")?
                    .body
                else {
                    anyhow::bail!("restore_installed_app_ack_kind");
                };
                let ceiling = payload.installed_acceptance_deadline_data(
                    &peer.exchange.digest()?,
                    installed,
                    peer.process.receiver.original.sample()?.elapsed,
                )?;
                let original = self
                    .original
                    .as_mut()
                    .context("restore_installed_app_original_missing")?;
                *original = original.narrow(5, ceiling)?;
                let native = &mut peer.process.receiver.original;
                *native = native.narrow(5, ceiling)?;
                let read = &mut actual.received.keeper.input.owner.original;
                *read = read.narrow(5, ceiling)?;
                Ok(())
            }
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.owner.refuse();
            self.stage.refuse_serving();
        }
        requested?;
        checked
    }
}

#[cfg(test)]
mod app_installed_source_tests {
    use super::keeper_birth_tests::{method, ordered, tokens};

    #[test]
    fn actual_app_installed_exchange_keeps_same_keeper_original_and_final_native_receipt() {
        let source = include_str!("activation.rs");
        let actual = method(source, "AppInstalledHandoff", "perform");
        let parts = [
            "self.owner.installed_attempted=true;",
            "self.check()?;",
            "self.original=Some(self.stage.narrow_io_acquisition(5)?);",
            "self.prepare_installed_ack()?;",
            "self.send_installed_ack()?;",
            "let message=self.receive_installed_acceptance()?;",
            "self.authenticate_installed_acceptance(&message)?;",
            "transcript.narrow_installed_acceptance(observation.clone())?;",
            "transcript.delivered(message.body.frame(),observation)?;",
            "transcript.complete()",
            "self.accepted=true;",
            "self.check()?;",
            "self.owner.installed=Some",
            "let checked=self.check();",
            "requested?;checked?;self.done=true;Ok(())",
        ];
        assert!(ordered(&actual, &parts));
        for target in [
            parts[0], parts[2], parts[4], parts[5], parts[6], parts[7], parts[10], parts[14],
        ] {
            let target = tokens(target);
            assert_eq!(actual.matches(&target).count(), 1, "{target}");
            assert!(!ordered(&actual.replacen(&target, "", 1), &parts));
        }
        for forbidden in [
            "NativeAcquisition::begin",
            "retire_checked",
            "into_connection_clock",
            "store::open",
        ] {
            assert!(!actual.contains(&tokens(forbidden)));
        }
        let prepare = method(source, "AppInstalledHandoff", "prepare_installed_ack");
        assert!(ordered(
            &prepare,
            &[
                "self.stage.storage()?.storage_statement()?",
                "derive_restored_installation(observation)?",
                "actual.received.keeper.keeper.cohort_data()?",
                "RestoreBody::AppInstalled",
                "payload.installed_confirmation_data",
                "self.check()?;",
                "key.sign(\"restored-storage-message\",&(&sender,&body))",
                "let checked=self.check();",
                "let signature=signed?;checked?;",
                "self.acknowledgement=Some(Message{sender,body,signature})",
            ]
        ));
        let auth = method(
            source,
            "AppInstalledHandoff",
            "authenticate_installed_acceptance",
        );
        assert!(ordered(
            &auth,
            &[
                "self.receipt.as_mut()",
                ".bind(message,&peer.controller,&mut peer.process)",
                "let checked=self.check();bound?;checked?;",
                "payload.installed_acceptance_deadline_data",
                "*original=original.narrow(5,ceiling)?;",
                "*native=native.narrow(5,ceiling)?;",
                "*read=read.narrow(5,ceiling)?;",
                "let checked=self.check();",
                "requested?;checked",
            ]
        ));
    }

    #[test]
    fn actual_app_installed_transport_retains_kernel_receipt_before_decode_and_posts_after_io() {
        let source = include_str!("transport.rs");
        let receive = method(
            source,
            "AppInstalledHandoff",
            "receive_installed_acceptance",
        );
        let parts = [
            "self.check()?;",
            ".begin(Direction::Receive,observation)?;",
            "net::recv_pidfd_packet",
            "let checked=self.check();",
            "RestoredControllerReceipt::received",
            "self.receipt=Some(receipt);",
            "self.check()?;",
            "storage_peer_wire::decode",
            "let checked=self.check();",
            "let message=requested?;checked?;Ok(message)",
        ];
        assert!(ordered(&receive, &parts));
        for target in [parts[2], parts[4], parts[5], parts[7], parts[9]] {
            let target = tokens(target);
            assert_eq!(receive.matches(&target).count(), 1, "{target}");
            assert!(!ordered(&receive.replacen(&target, "", 1), &parts));
        }
        let send = method(source, "AppInstalledHandoff", "send_installed_ack");
        assert!(ordered(
            &send,
            &[
                "self.check()?;",
                "serde_json::to_vec(message)?",
                "bytes.len()<=MAX_PACKET",
                "transcript.begin(Direction::Send,observation)?;",
                "net::send",
                "let checked=self.check();",
                "count==bytes.len()",
                "self.transcript",
                ".delivered(frame,observation)?;",
                "self.ack_delivered=true;",
                "let checked=self.check();",
                "requested?;checked",
            ]
        ));
        let check = method(
            include_str!("activation.rs"),
            "AppInstalledHandoff",
            "check",
        );
        assert!(ordered(
            &check,
            &[
                "let requested=self.owner.check();",
                "self.stage.require_current_role()?;",
                "original.exchange_current_views(&mut owner.original)?;",
                "original.exchange_current_views(&mut owner.captured.peer.process.receiver.original)?;",
                "receipt.live(&mut owner.captured.peer.process)?;",
                "let tail=self.owner.check();",
                "let post=self.stage.check();",
                "requested?;checked?;tail?;post",
            ]
        ));
        let drop = method(
            include_str!("../restored.rs"),
            "AppInstalledHandoff",
            "drop",
        );
        for target in [
            "if !self.done",
            "self.owner.refuse();",
            "self.stage.refuse_serving();",
            "original.refuse();",
        ] {
            assert!(drop.contains(&tokens(target)));
        }
    }
}

impl RestoredAppHistory {
    /// Actual completed native ACK history only, never a caller boolean or a
    /// parsed receipt. Both the whole live owner and the slot return are checked.
    pub(in crate::security_epoch::native_enrollment) fn check_installed(&self) -> Result<()> {
        let mut loan = RestoredHistoryLoan::take(self)?;
        let requested: Result<()> = (|| {
            let owner = loan
                .history
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_history_loan_missing"))?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = owner;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                ensure!(
                    owner.installed_attempted && owner.installed.is_some(),
                    "restore_installed_native_history_missing"
                );
                owner.check()
            }
        })();
        if requested.is_err() {
            self.refuse();
        }
        let retained = loan.finish();
        requested?;
        retained
    }
}

#[cfg(test)]
mod installed_history_factory_tests {
    use super::keeper_birth_tests::{method, ordered, tokens};
    #[test]
    fn actual_installed_history_factory_collects_only_complete_owned_exchange() {
        let actual = method(
            include_str!("../restored.rs"),
            "AppInstalledHandoff",
            "retain_installed_history",
        );
        let parts = [
            "self.accepted&&self.ack_delivered",
            "self.transcript.as_ref().is_some_and(|history|history.complete())",
            "self.receipt.is_some()",
            "InstalledAppHistory",
            "self.acknowledgement.take()",
            "acceptance:message",
            "self.receipt.take()",
            "self.transcript.take()",
        ];
        assert!(ordered(&actual, &parts));
        for target in [parts[0], parts[1], parts[2], parts[4], parts[6], parts[7]] {
            let target = tokens(target);
            assert_eq!(actual.matches(&target).count(), 1);
            assert!(!ordered(&actual.replacen(&target, "", 1), &parts));
        }
        let caller = method(
            include_str!("activation.rs"),
            "AppInstalledHandoff",
            "perform",
        );
        assert!(ordered(
            &caller,
            &[
                "self.accepted=true;",
                "self.check()?;",
                "self.owner.installed=Some(self.retain_installed_history(message)?);",
                "let checked=self.check();",
                "requested?;checked?;self.done=true;"
            ]
        ));
        for forbidden in ["NativeAcquisition::begin", "retire_checked", "Runtime::"] {
            assert!(!actual.contains(&tokens(forbidden)));
        }
    }
}

impl AcceptedRestoredApp {
    fn check_current_keeper(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let accepted = self;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (accepted, stage);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let input = accepted
                .pending
                .input
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_prepared_handoff_input_missing"))?
                .pending
                .input
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_prepared_input_missing"))?;
            let keeper = &mut input.received.keeper;
            let policy = &keeper.input.owner.captured.peer.process.receiver.policy;
            stage.require_current_role()?;
            stage.check_selection(
                &policy.bootstrap,
                &policy.store,
                super::super::NativeRole::AppHost,
            )?;
            keeper.input.owner.captured.check_anchors()?;
            keeper.keeper.check(
                &keeper.input.owner.captured.directory,
                &keeper.input.owner.captured.file,
            )
        }
    }

    fn check_current_peer_anchors(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let accepted = self;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (accepted, stage, acquisition);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let input = accepted
                .pending
                .input
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_prepared_handoff_input_missing"))?
                .pending
                .input
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_prepared_input_missing"))?;
            let peer = &mut input.received.keeper.input.owner.captured.peer;
            stage.require_current_role()?;
            stage.check_selection(
                &peer.process.receiver.policy.bootstrap,
                &peer.process.receiver.policy.store,
                super::super::NativeRole::AppHost,
            )?;
            ensure!(
                !peer.refused && (2..=5).contains(&peer.receipts.len()),
                "restore_peer_owner_refused"
            );
            for receipt in &mut peer.receipts {
                receipt.check_current_anchor(&peer.controller, stage, acquisition)?;
            }
            peer.channel.check_current_anchor(stage, acquisition)
        }
    }
}

impl RestoredAppHistory {
    /// Move the actual final cursor behind the whole-history negative loan.
    /// The old endpoint keeps only physical/negative anchors; its operation
    /// latch closes before the cursor/receipt move. No old clock is sampled.
    pub(in crate::security_epoch::native_enrollment) fn take_current_peer(
        self: &std::rc::Rc<Self>,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<RestoredCurrentPeerPort<'static>> {
        let mut loan = RestoredHistoryLoan::take(self)?;
        let requested = (|| {
            let accepted = loan
                .history
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_history_loan_missing"))?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = accepted;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use super::super::{RestoredPeerAnchor, RestoredPeerTail, handshake::Actor};
                use anyhow::Context;
                use std::rc::Rc;
                stage.require_current_role()?;
                let mut original = stage.narrow_io_acquisition(5)?;
                {
                    let input = accepted
                        .pending
                        .input
                        .as_mut()
                        .context("restore_prepared_handoff_input_missing")?
                        .pending
                        .input
                        .as_mut()
                        .context("restore_prepared_input_missing")?;
                    input
                        .received
                        .keeper
                        .input
                        .owner
                        .captured
                        .peer
                        .process
                        .receiver
                        .original
                        .require_retired_predecessor(&mut original)?;
                }
                // Both independent physical families run, even on the first
                // refusal; selecting the first Result happens only afterward.
                let keeper = accepted.check_current_keeper(stage);
                let peer_post = accepted.check_current_peer_anchors(stage, &mut original);
                let native = stage.check();
                keeper?;
                peer_post?;
                native?;
                ensure!(
                    accepted.installed_attempted,
                    "restore_installed_native_history_missing"
                );
                let input = accepted
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_handoff_input_missing")?
                    .pending
                    .input
                    .as_mut()
                    .context("restore_prepared_input_missing")?;
                let peer = &mut input.received.keeper.input.owner.captured.peer;
                ensure!(
                    !peer.refused
                        && !peer.channel.refused.get()
                        && peer.channel.operation == super::RestoreTransportOperation::Restoring,
                    "restore_current_peer_already_transferred"
                );
                let remote = peer.controller.clone();
                let installed = accepted
                    .installed
                    .as_mut()
                    .context("restore_installed_native_history_missing")?;
                installed
                    .transcript
                    .as_ref()
                    .context("restore_current_cursor_already_spent")?
                    .require_installed_current_data(Actor::App)?;
                installed
                    .receipt
                    .as_mut()
                    .context("restore_current_receipt_already_spent")?
                    .check_current_anchor(&remote, stage, &mut original)?;
                let Body::Restore { payload: ack } = &installed.acknowledgement.body else {
                    anyhow::bail!("restore_current_installed_packet_kind");
                };
                let Body::Restore { payload: reply } = &installed.acceptance.body else {
                    anyhow::bail!("restore_current_acceptance_packet_kind");
                };
                let RestoreBody::AppInstalled { app, .. } = ack else {
                    anyhow::bail!("restore_current_installed_packet_kind");
                };
                let local = app.as_ref().clone();
                let binding = ack.current_connection_binding_data(reply)?;
                let current = stage.storage()?.storage_statement()?;
                ensure!(
                    local.same_enrollment(&current),
                    "restore_current_app_owner_changed"
                );
                current.original.require_later_request(&local.original)?;
                let same = stage.capture_same_owner()?;
                // This is a one-way operational spend, before moving ANY
                // actual installed cursor. No error restores the old route.
                peer.channel.operation = super::RestoreTransportOperation::Transferred;
                let installed = accepted
                    .installed
                    .as_mut()
                    .context("restore_installed_native_history_missing")?;
                let native_refusal = original.retained_refusal();
                Ok(RestoredCurrentPeerPort {
                    socket: Some(Rc::clone(&peer.channel.socket)),
                    transcript: Some(
                        installed
                            .transcript
                            .take()
                            .context("restore_current_cursor_already_spent")?,
                    ),
                    anchor: Some(RestoredPeerAnchor::Controller(
                        installed
                            .receipt
                            .take()
                            .context("restore_current_receipt_already_spent")?,
                    )),
                    same: Some(same),
                    local,
                    remote,
                    binding,
                    native_refusal: Some(native_refusal),
                    original: Some(original),
                    channel_refusal: Rc::clone(&peer.channel.refused),
                    tail: Some(RestoredPeerTail::App(Rc::clone(self))),
                    completed: false,
                    local_only: std::marker::PhantomData,
                })
            }
        })();
        let checked = stage.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
            stage.refuse_serving();
        }
        let retained = loan.finish();
        let port = requested?;
        checked?;
        retained?;
        Ok(port)
    }
}

impl RestoredAppHistory {
    /// Compare the actual moved channel with this same retained native owner.
    /// No descriptor, original or clock permission is returned or reconstructed.
    pub(in crate::security_epoch::native_enrollment) fn check_current_source(
        &self,
        source: &RestoredPeerSource<'_>,
    ) -> Result<()> {
        let loan = RestoredHistoryLoan::take(self)?;
        let requested = (|| {
            let accepted = loan
                .history
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("restore_history_loan_missing"))?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (accepted, source);
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                use std::rc::Rc;
                let input = accepted
                    .pending
                    .input
                    .as_ref()
                    .context("restore_prepared_handoff_input_missing")?
                    .pending
                    .input
                    .as_ref()
                    .context("restore_prepared_input_missing")?;
                let peer = &input.received.keeper.input.owner.captured.peer;
                let installed = accepted
                    .installed
                    .as_ref()
                    .context("restore_installed_native_history_missing")?;
                ensure!(
                    !peer.refused
                        && !peer.channel.refused.get()
                        && peer.channel.operation == super::RestoreTransportOperation::Transferred
                        && installed.transcript.is_none()
                        && installed.receipt.is_none(),
                    "restore_current_source_not_transferred"
                );
                ensure!(
                    Rc::ptr_eq(&peer.channel.socket, source.socket)
                        && Rc::ptr_eq(&peer.channel.refused, source.refusal),
                    "restore_current_source_native_identity_changed"
                );
                let Body::Restore { payload: ack } = &installed.acknowledgement.body else {
                    anyhow::bail!("restore_current_installed_packet_kind");
                };
                let Body::Restore { payload: reply } = &installed.acceptance.body else {
                    anyhow::bail!("restore_current_acceptance_packet_kind");
                };
                let RestoreBody::AppInstalled { app, .. } = ack else {
                    anyhow::bail!("restore_current_installed_packet_kind");
                };
                ensure!(
                    app.as_ref() == source.local
                        && &peer.controller == source.remote
                        && &ack.current_connection_binding_data(reply)? == source.binding,
                    "restore_current_source_packet_binding_changed"
                );
                Ok(())
            }
        })();
        if requested.is_err() {
            self.refuse();
        }
        let checked = loan.finish();
        requested?;
        checked
    }

    /// Historical comparison/negative state only. The real cursor and receipt
    /// must be absent here because the actual Current core now owns them.
    pub(in crate::security_epoch::native_enrollment) fn check_current_transfer(
        &self,
        expected: &day2_capabilities::Digest,
    ) -> Result<()> {
        let loan = RestoredHistoryLoan::take(self)?;
        let requested = (|| {
            let accepted = loan
                .history
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("restore_history_loan_missing"))?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (accepted, expected);
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context;
                let input = accepted
                    .pending
                    .input
                    .as_ref()
                    .context("restore_prepared_handoff_input_missing")?
                    .pending
                    .input
                    .as_ref()
                    .context("restore_prepared_input_missing")?;
                let peer = &input.received.keeper.input.owner.captured.peer;
                let installed = accepted
                    .installed
                    .as_ref()
                    .context("restore_installed_native_history_missing")?;
                ensure!(
                    !peer.refused
                        && !peer.channel.refused.get()
                        && peer.channel.operation == super::RestoreTransportOperation::Transferred
                        && installed.transcript.is_none()
                        && installed.receipt.is_none(),
                    "restore_current_app_operational_slot_not_transferred"
                );
                let Body::Restore { payload: ack } = &installed.acknowledgement.body else {
                    anyhow::bail!("restore_current_installed_packet_kind");
                };
                let Body::Restore { payload: reply } = &installed.acceptance.body else {
                    anyhow::bail!("restore_current_acceptance_packet_kind");
                };
                ensure!(
                    &ack.current_connection_binding_data(reply)? == expected,
                    "restore_current_app_tail_binding_changed"
                );
                Ok(())
            }
        })();
        if requested.is_err() {
            self.refuse();
        }
        let retained = loan.finish();
        requested?;
        retained
    }
}
