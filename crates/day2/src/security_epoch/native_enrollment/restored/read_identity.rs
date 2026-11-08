//! Restore-only App READ identity, derived from the actual prepared process.
//! No ordinary stage, serving acquisition, write port, token or route escapes.
use super::{RestoreReadAuthentication, RestoredReadIdentity, RestoredWriterReadPending};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::NativeRole;
#[cfg(target_os = "linux")]
use crate::security_epoch::{
    credential_material::CredentialMaterial,
    identity_protocol, runtime_profile,
    transport::{NativeHttp, Route},
};
use crate::security_epoch::{identity_protocol::ReviewedSubject, runtime_profile::ContainerFacts};
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, ensure};
#[cfg(target_os = "linux")]
use day2_capabilities::{Digest, security_epoch::bootstrap::WorkloadKind};
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

// These are DATA joins inside the actual owning factory, not admission
// predicates that could replace a live process, token review or file owner.
fn require_actual_subject_data(reviewed: &ReviewedSubject, actual: &ContainerFacts) -> Result<()> {
    ensure!(
        reviewed.pod_name == actual.pod_name && reviewed.pod_uid == actual.pod_uid,
        "restore_read_subject_not_actual_app"
    );
    Ok(())
}

fn require_actual_container_data(observed: &ContainerFacts, actual: &ContainerFacts) -> Result<()> {
    ensure!(observed == actual, "restore_read_actual_container_changed");
    Ok(())
}

impl RestoredWriterReadPending {
    /// Consume the exact pending receiver before provider work. Its Root
    /// admission already owns the executable/process/policy/namespace proof;
    /// the provider subject below must join that SAME actual container.
    pub(in crate::security_epoch::native_enrollment) fn authenticate_read(
        mut self,
    ) -> Result<RestoredReadIdentity> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut self;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested: Result<_> = (|| {
                let original = &mut self.captured.peer.process.receiver.original;
                let (_, ceiling) = original.interval_data()?;
                original.narrow(5, ceiling)
            })();
            let checked = self.check();
            let original = requested?;
            checked?;
            let mut attempt = RestoreReadAuthentication {
                owner: self,
                original,
            };
            let requested = attempt.acquire();
            let checked = attempt.check();
            if requested.is_err() || checked.is_err() {
                attempt.refuse();
            }
            let (http, credential) = requested?;
            checked?;
            Ok(RestoredReadIdentity {
                owner: attempt.owner,
                original: attempt.original,
                http,
                credential,
            })
        }
    }
}

impl RestoreReadAuthentication {
    fn refuse(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.owner.captured.refused = true;
            self.owner.captured.peer.refused = true;
            self.owner.captured.peer.process.receiver.refuse();
            self.original.refuse();
        }
    }

    fn check(&mut self) -> Result<()> {
        let requested = self.owner.check();
        #[cfg(target_os = "linux")]
        let checked = self.original.remaining().map(|_| ());
        #[cfg(not(target_os = "linux"))]
        let checked = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    // One checked native identity operation. Only this child calls it, with
    // fixed identity routes; it cannot dispatch a ledger read or mutation.
    fn request(
        &mut self,
        http: &crate::security_epoch::transport::NativeHttp,
        route: crate::security_epoch::transport::Route<'_>,
        authorization: &reqwest::header::HeaderValue,
        body: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, http, route, authorization, body);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested: Result<_> = (|| {
                ensure!(
                    !matches!(
                        route,
                        Route::EpochRead | Route::EpochRollback | Route::EpochCommit
                    ),
                    "restore_read_identity_route_required"
                );
                http.request(route, authorization, body, &mut self.original)
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            let bytes = requested?;
            checked?;
            Ok(bytes)
        }
    }

    fn acquire(
        &mut self,
    ) -> Result<(
        crate::security_epoch::transport::NativeHttp,
        crate::security_epoch::credential_material::CredentialMaterial,
    )> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            // Clone selection DATA only. The actual owner below is checked
            // at every native operation and is never replaced by these fields.
            let policy = self.owner.captured.peer.process.receiver.policy.clone();
            let authorized = &self
                .owner
                .captured
                .peer
                .process
                .authorization
                .statement
                .data;
            ensure!(
                policy.bootstrap.scope == authorized.target.scope
                    && policy.store.scope == authorized.target.scope
                    && Digest::of(&policy.store)? == authorized.target.selection
                    && policy.store.authority_key()? == authorized.target.authority,
                "restore_read_selected_instance_changed"
            );
            let selected = policy.bootstrap.native_role(NativeRole::AppHost);
            let role = selected.workload;
            let runtime = self
                .owner
                .captured
                .peer
                .process
                .admission
                .statement
                .runtime
                .clone();

            let requested: Result<Vec<u8>> = (|| {
                self.original.remaining()?;
                let file = std::fs::File::from(rustix::fs::open(
                    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )?);
                ensure!(
                    file.metadata()?.is_file(),
                    "epoch_native_projection_not_regular"
                );
                let mut ca = Vec::new();
                file.take(65_537).read_to_end(&mut ca)?;
                self.original.remaining()?;
                Ok(ca)
            })();
            let checked = self.check();
            let ca = requested?;
            checked?;
            let requested = NativeHttp::new(&policy.store, &policy.bootstrap.cluster, &ca);
            let checked = self.check();
            let mut http = requested?;
            checked?;
            let requested = CredentialMaterial::metadata_source(&mut self.original);
            let checked = self.check();
            let source = requested?;
            checked?;
            identity_protocol::project(
                &policy.store,
                &self.request(&http, Route::Project, &source.authorization()?, None)?,
            )?;
            self.check()?;
            let requested = http.verify_cluster(&ca, &source.authorization()?, &mut self.original);
            let checked = self.check();
            requested?;
            checked?;
            let requested = CredentialMaterial::kubernetes_api(&mut self.original);
            let checked = self.check();
            let api = requested?;
            checked?;
            let requested = CredentialMaterial::subject(&mut self.original);
            let checked = self.check();
            let subject = requested?;
            checked?;
            let request = Zeroizing::new(serde_json::to_vec(&serde_json::json!({
                "apiVersion":"authentication.k8s.io/v1", "kind":"TokenReview",
                "spec":{"token":subject.subject_text()?, "audiences":[role.token_review_audience]},
            }))?);
            let response = Zeroizing::new(self.request(
                &http,
                Route::TokenReview,
                &api.authorization()?,
                Some(&request),
            )?);
            let reviewed = identity_protocol::token_review(role, &response)?;
            require_actual_subject_data(&reviewed, &runtime.container)?;
            let ns = &role.namespace.name;
            identity_protocol::namespace(
                role,
                &self.request(&http, Route::Namespace(ns), &api.authorization()?, None)?,
            )?;
            identity_protocol::service_account(
                role,
                &self.request(
                    &http,
                    Route::ServiceAccount {
                        namespace: ns,
                        name: &role.kubernetes_service_account.name,
                    },
                    &api.authorization()?,
                    None,
                )?,
            )?;
            let pod = self.request(
                &http,
                Route::Pod {
                    namespace: ns,
                    name: &reviewed.pod_name,
                },
                &api.authorization()?,
                None,
            )?;
            let observed = runtime_profile::container(role, &reviewed, &pod)?;
            require_actual_container_data(&observed.facts, &runtime.container)?;
            let owner = observed.owner;
            let replica = match role.workload_kind {
                WorkloadKind::DeploymentV1 => Some(
                    self.request(
                        &http,
                        Route::ReplicaSet {
                            namespace: ns,
                            name: owner
                                .get("name")
                                .and_then(serde_json::Value::as_str)
                                .context("epoch_identity_replica_set_name")?,
                        },
                        &api.authorization()?,
                        None,
                    )?,
                ),
                WorkloadKind::StatefulSetV1 => None,
            };
            let route = match role.workload_kind {
                WorkloadKind::DeploymentV1 => Route::Deployment {
                    namespace: ns,
                    name: &role.workload.name,
                },
                WorkloadKind::StatefulSetV1 => Route::StatefulSet {
                    namespace: ns,
                    name: &role.workload.name,
                },
            };
            identity_protocol::workload(
                role,
                &owner,
                replica.as_deref(),
                &self.request(&http, route, &api.authorization()?, None)?,
            )?;
            identity_protocol::google_service_account(
                &role.google_service_account,
                &policy.bootstrap.cluster.project,
                &self.request(
                    &http,
                    Route::GoogleAccount(&role.google_service_account),
                    &source.authorization()?,
                    None,
                )?,
            )?;
            self.check()?;
            let requested = CredentialMaterial::mint_target(
                &source,
                &role.google_service_account,
                &http,
                &mut self.original,
            );
            let checked = self.check();
            let credential = requested?;
            checked?;
            identity_protocol::database(
                &policy.store,
                &self.request(&http, Route::Database, &credential.authorization()?, None)?,
            )?;
            self.check()?;
            Ok((http, credential))
        }
    }
}

impl RestoredReadIdentity {
    /// The App performs its OWN exact strong read after actual Activated. The
    /// result remains this readonly identity/file owner, not keeper authority
    /// or a detachable readiness value. The fixed future RW birth must invoke
    /// this operation at its own boundary while retaining the composite P3.
    pub(in crate::security_epoch::native_enrollment) fn reobserve_writer(mut self) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut self;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested: Result<()> = (|| {
                let captured = &self.owner.captured;
                let holder = captured.peer.local.holder_data()?;
                let names = crate::security_epoch::firestore::RestoreWriterPeerRead::new(
                    &captured.peer.process.receiver.policy.store,
                    &captured.peer.projection,
                    &self.owner.activation,
                    &holder,
                )?;
                ensure!(
                    self.http
                        .matches(&Route::EpochRead, &names.endpoint_data())?,
                    "restore_writer_reader_endpoint_changed"
                );
                let body = names.strong_body_data()?;
                // The sender, actual file and SAME original are checked
                // immediately before HTTP and independently after every result.
                self.check()?;
                let authorization = self.credential.authorization()?;
                let response = self.http.request(
                    Route::EpochRead,
                    &authorization,
                    Some(&body),
                    &mut self.original,
                );
                let checked = self.check();
                let response = Zeroizing::new(response?);
                checked?;
                names.validate_response_data(&response)
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            requested?;
            checked?;
            Ok(self)
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn refuse(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.owner.captured.refused = true;
            self.owner.captured.peer.refused = true;
            self.owner.captured.peer.process.receiver.refuse();
            self.original.refuse();
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        let requested = self.owner.check();
        #[cfg(target_os = "linux")]
        let checked = self.original.remaining().map(|_| ());
        #[cfg(not(target_os = "linux"))]
        let checked = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use day2_capabilities::Digest;

    fn actual_writer_method() -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("read_identity.rs")).unwrap();
        file.items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                let syn::Type::Path(owner) = &*item.self_ty else {
                    return None;
                };
                if !owner.path.is_ident("RestoredReadIdentity") {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == "reobserve_writer" => {
                        Some(method.clone())
                    }
                    _ => None,
                })
            })
            .unwrap()
    }

    fn requested_body(method: &mut syn::ImplItemFn) -> &mut syn::Block {
        fn requested(pattern: &syn::Pat) -> bool {
            match pattern {
                syn::Pat::Ident(name) => name.ident == "requested",
                syn::Pat::Type(typed) => requested(&typed.pat),
                _ => false,
            }
        }
        let linux = method.block.stmts.iter_mut().find_map(|statement| match statement {
            syn::Stmt::Expr(syn::Expr::Block(block), _) if block.attrs.iter().any(|attribute|
                attribute.path().is_ident("cfg") && matches!(attribute.parse_args::<syn::Meta>(), Ok(syn::Meta::NameValue(value))
                    if value.path.is_ident("target_os") && matches!(&value.value, syn::Expr::Lit(value)
                        if matches!(&value.lit, syn::Lit::Str(value) if value.value() == "linux")))) => Some(&mut block.block),
            _ => None,
        }).unwrap();
        let local = linux
            .stmts
            .iter_mut()
            .find_map(|statement| match statement {
                syn::Stmt::Local(local) if requested(&local.pat) => Some(local),
                _ => None,
            })
            .unwrap();
        let syn::Expr::Call(call) = &mut *local.init.as_mut().unwrap().expr else {
            unreachable!();
        };
        let syn::Expr::Paren(paren) = &mut *call.func else {
            unreachable!();
        };
        let syn::Expr::Closure(closure) = &mut *paren.expr else {
            unreachable!();
        };
        let syn::Expr::Block(body) = &mut *closure.body else {
            unreachable!();
        };
        &mut body.block
    }

    fn self_field(expression: &syn::Expr, expected: &str) -> bool {
        matches!(expression, syn::Expr::Field(field)
            if matches!(&*field.base, syn::Expr::Path(path) if path.path.is_ident("self"))
                && matches!(&field.member, syn::Member::Named(name) if name == expected))
    }

    fn fixed_read_and_error_post(block: &syn::Block) -> bool {
        let requests = block.stmts.iter().enumerate().filter_map(|(index, statement)| match statement {
            syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "response") =>
                match local.init.as_ref().map(|init| &*init.expr) {
                    Some(syn::Expr::MethodCall(call)) if call.method == "request" => Some((index, call)),
                    _ => None,
                },
            _ => None,
        }).collect::<Vec<_>>();
        let [(index, call)] = requests.as_slice() else {
            return false;
        };
        if !self_field(&call.receiver, "http")
            || call.args.len() != 4
            || !matches!(&call.args[0], syn::Expr::Path(path) if path.path.segments.len() == 2
                && path.path.segments[0].ident == "Route" && path.path.segments[1].ident == "EpochRead")
            || !matches!(&call.args[3], syn::Expr::Reference(reference) if reference.mutability.is_some()
                && self_field(&reference.expr, "original"))
        {
            return false;
        }
        let Some(syn::Stmt::Local(post)) = block.stmts.get(index + 1) else {
            return false;
        };
        if !matches!(&post.pat, syn::Pat::Ident(name) if name.ident == "checked")
            || !matches!(post.init.as_ref().map(|init| &*init.expr), Some(syn::Expr::MethodCall(call))
                if call.method == "check" && call.args.is_empty()
                    && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("self")))
        {
            return false;
        }
        let Some(syn::Stmt::Local(response)) = block.stmts.get(index + 2) else {
            return false;
        };
        let primary_first = matches!(response.init.as_ref().map(|init| &*init.expr), Some(syn::Expr::Call(call))
            if call.args.len() == 1 && matches!(call.args.first(), Some(syn::Expr::Try(tried))
                if matches!(&*tried.expr, syn::Expr::Path(path) if path.path.is_ident("response"))));
        primary_first
            && matches!(block.stmts.get(index + 3), Some(syn::Stmt::Expr(syn::Expr::Try(tried), Some(_)))
            if matches!(&*tried.expr, syn::Expr::Path(path) if path.path.is_ident("checked")))
    }

    #[test]
    fn actual_writer_read_is_fixed_readonly_same_original_and_checks_after_failed_http() {
        let mut actual = actual_writer_method();
        let body = requested_body(&mut actual);
        assert!(fixed_read_and_error_post(body));
        let index = body.stmts.iter().position(|statement| matches!(statement,
            syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "response")
                && matches!(local.init.as_ref().map(|init| &*init.expr), Some(syn::Expr::MethodCall(call)) if call.method == "request"))).unwrap();
        for cut in 0..5 {
            let mut mutant = body.clone();
            if cut == 1 {
                mutant.stmts[index + 1] = syn::parse_quote!(let checked: Result<()> = Ok(()););
            } else if cut == 4 {
                mutant.stmts.swap(index + 2, index + 3);
            } else {
                let syn::Stmt::Local(local) = &mut mutant.stmts[index] else {
                    unreachable!();
                };
                let init = local.init.as_mut().unwrap();
                if cut == 3 {
                    let expression = init.expr.clone();
                    *init.expr = syn::parse_quote!((#expression)?);
                } else {
                    let syn::Expr::MethodCall(call) = &mut *init.expr else {
                        unreachable!();
                    };
                    if cut == 0 {
                        call.args[0] = syn::parse_quote!(Route::EpochCommit);
                    } else {
                        call.args[3] = syn::parse_quote!(&mut other_original);
                    }
                }
            }
            assert!(
                !fixed_read_and_error_post(&mutant),
                "actual readonly/original/error boundary cut {cut}"
            );
        }
    }

    fn container() -> ContainerFacts {
        ContainerFacts {
            pod_name: "restored-app-7c4d9f6f7b-abc12".to_owned(),
            pod_uid: "actual-pod-uid".to_owned(),
            node_name: "actual-node".to_owned(),
            container_name: "app".to_owned(),
            container_id: format!("containerd://{}", "a".repeat(64)),
            image: Digest::new(b"admitted-image"),
            restart_count: 0,
        }
    }

    #[test]
    fn reviewed_provider_subject_must_be_the_actual_admitted_app_not_another_same_role_pod()
    -> Result<()> {
        let actual = container();
        let mut reviewed = ReviewedSubject {
            pod_name: actual.pod_name.clone(),
            pod_uid: actual.pod_uid.clone(),
        };
        require_actual_subject_data(&reviewed, &actual)?;
        reviewed.pod_name.push_str("-other");
        assert!(require_actual_subject_data(&reviewed, &actual).is_err());
        reviewed.pod_name = actual.pod_name.clone();
        reviewed.pod_uid = "other-pod-with-same-policy-and-account".to_owned();
        assert!(require_actual_subject_data(&reviewed, &actual).is_err());
        Ok(())
    }

    #[test]
    fn every_fresh_provider_container_fact_must_retain_the_actual_native_runtime_binding()
    -> Result<()> {
        let actual = container();
        require_actual_container_data(&actual, &actual)?;
        // Native admission is intentionally NOT manufactured here. These
        // wrong-world DATA controls cover the additional provider-to-App join.
        for field in 0..7 {
            let mut other = actual.clone();
            match field {
                0 => other.pod_name.push_str("-other"),
                1 => other.pod_uid.push_str("-other"),
                2 => other.node_name.push_str("-other"),
                3 => other.container_name.push_str("-other"),
                4 => other.container_id = format!("containerd://{}", "b".repeat(64)),
                5 => other.image = Digest::new(b"another-image"),
                _ => other.restart_count += 1,
            }
            assert!(require_actual_container_data(&other, &actual).is_err());
        }
        Ok(())
    }
}
