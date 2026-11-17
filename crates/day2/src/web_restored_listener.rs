//! Private restored listener resources. The parent cannot extract the server;
//! only this fixed genuine-startup builder can create the opaque value.
use super::{ListenerOptions, ListenerSql, LocalServer, PresentationSource, SignIn};
use crate::store::Runtime;
use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::net::TcpListener;

/// Existing listener settings only. Sharing readiness DATA grants no Current,
/// native owner, Runtime access or startup permission.
pub(crate) struct RestoredListenerOptions {
    pub(crate) concurrency: usize,
    pub(crate) admission: Arc<AtomicBool>,
}

/// Concrete restored listener resources only. No method can expose the raw
/// server, start serving or extract native parts before the fixed installer
/// owns both completed startup settlements and the whole native parent.
pub(crate) struct BoundRestoredListener {
    // Retain and drop the real resource without exposing an operational exit.
    _server: LocalServer,
    admission: Arc<AtomicBool>,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}

pub(super) fn bind(
    runtime: Arc<Runtime>,
    listener: TcpListener,
    edge: &crate::artifact::Edge,
    verifier: crate::iap::Verifier,
    receiver: Arc<crate::oauth::shell_transport::AppApprovalReceiver>,
    options: RestoredListenerOptions,
    current: &mut crate::oauth::native_management::RuntimeConsumer<'_, '_>,
) -> Result<BoundRestoredListener> {
    current.require_restored_startup_sql(&runtime)?;
    let request_timing = super::request_timing_setting(&runtime).unwrap_or(true);
    let mut server = LocalServer::bind_listener_with_sql(
        runtime,
        listener,
        edge.authority().into(),
        edge.origin.clone(),
        SignIn::Edge(verifier),
        ListenerOptions {
            concurrency: options.concurrency,
            health_endpoints: true,
            presentation: PresentationSource::Environment,
            request_timing,
        },
        ListenerSql::Restored(current),
    )?;
    server.mount_oauth(receiver)?;
    Ok(BoundRestoredListener {
        _server: server,
        admission: options.admission,
        local: std::marker::PhantomData,
    })
}

/// Prepared resources plus the actual executor's negative lifetime guard.
/// There is no resource/Runtime/native-owner getter or callback constructor.
pub(crate) struct InstalledRestoredListener {
    endpoint: crate::oauth::native_http::Endpoint,
    listener: TcpListener,
    admission: Arc<AtomicBool>,
    owner: crate::oauth::native_management::RestoredExecutorGuard,
}

pub(super) fn install(
    prepared: BoundRestoredListener,
    routing: crate::oauth::native_management::RestoredHostRouting,
) -> Result<InstalledRestoredListener> {
    let BoundRestoredListener {
        _server: server,
        admission,
        local: _,
    } = prepared;
    let (host, listener) = server.into_native_parts(Arc::clone(&admission))?;
    let owner = crate::oauth::native_management::install_restored_owner(routing, &host.runtime)?;
    Ok(InstalledRestoredListener {
        endpoint: crate::oauth::native_http::Endpoint::App(host),
        listener,
        admission,
        owner,
    })
}

impl InstalledRestoredListener {
    pub(crate) async fn serve(self, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
        crate::oauth::native_http::serve_restored(
            self.endpoint,
            self.listener,
            self.admission,
            self.owner,
            shutdown,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn installed_listener_moves_its_actual_lifetime_guard_into_the_same_async_server() {
        use quote::ToTokens;
        let file = syn::parse_file(include_str!("web_restored_listener.rs")).unwrap();
        let actual = file.items.iter().find_map(|item| {
            let syn::Item::Impl(item) = item else { return None; };
            if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("InstalledRestoredListener")) { return None; }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == "serve" => Some(item),
                _ => None,
            })
        }).unwrap();
        assert!(actual.sig.asyncness.is_some());
        assert!(
            matches!(actual.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver)) if receiver.reference.is_none())
        );
        let expected: syn::Block = syn::parse_quote!({
            crate::oauth::native_http::serve_restored(
                self.endpoint,
                self.listener,
                self.admission,
                self.owner,
                shutdown,
            )
            .await
        });
        let guarded = |body: &syn::Block| {
            body.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&actual.block));
        let mut replaced = actual.block.clone();
        replaced.stmts[0] = syn::Stmt::Expr(
            syn::parse_quote!(
                crate::oauth::native_http::serve_restored(
                    self.endpoint,
                    self.listener,
                    self.admission,
                    other_owner,
                    shutdown
                )
                .await
            ),
            None,
        );
        assert!(!guarded(&replaced));
        let mut early = actual.block.clone();
        early.stmts.insert(0, syn::parse_quote!(drop(self.owner);));
        assert!(!guarded(&early));
        let complete: syn::Block = syn::parse_quote!({ Ok(()) });
        assert!(!guarded(&complete));
    }

    #[test]
    fn restored_listener_resources_have_no_raw_server_exit_or_operational_conversion() {
        use quote::ToTokens;
        use syn::visit::Visit;
        let file = syn::parse_file(include_str!("web_restored_listener.rs")).unwrap();
        let bound = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "BoundRestoredListener" => Some(item),
                _ => None,
            })
            .unwrap();
        let fields = bound
            .fields
            .iter()
            .map(|field| {
                (
                    field.ident.as_ref().unwrap().to_string(),
                    field.ty.to_token_stream().to_string(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            fields,
            [
                ("_server".into(), "LocalServer".into()),
                ("admission".into(), "Arc < AtomicBool >".into()),
                (
                    "local".into(),
                    "std :: marker :: PhantomData < std :: rc :: Rc < () > >".into()
                )
            ]
        );
        assert!(
            bound
                .fields
                .iter()
                .all(|field| matches!(field.vis, syn::Visibility::Inherited))
        );
        assert!(!file.items.iter().any(|item| matches!(item, syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().unwrap().ident == "BoundRestoredListener"))));
        let actual = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "bind" => Some(item),
                _ => None,
            })
            .unwrap();
        let expected_type: syn::ReturnType = syn::parse_quote!(-> Result<BoundRestoredListener>);
        assert_eq!(
            actual.sig.output.to_token_stream().to_string(),
            expected_type.to_token_stream().to_string()
        );
        let guarded = |block: &syn::Block| {
            let Some(syn::Stmt::Expr(syn::Expr::Call(tail), None)) = block.stmts.last() else {
                return false;
            };
            if !matches!(&*tail.func, syn::Expr::Path(path) if path.path.is_ident("Ok"))
                || tail.args.len() != 1
            {
                return false;
            }
            let syn::Expr::Struct(bound) = &tail.args[0] else {
                return false;
            };
            let expected: syn::ExprStruct = syn::parse_quote!(BoundRestoredListener {
                _server: server,
                admission: options.admission,
                local: std::marker::PhantomData
            });
            let same_fields = bound.fields.len() == expected.fields.len()
                && bound
                    .fields
                    .iter()
                    .zip(&expected.fields)
                    .all(|(actual, expected)| {
                        actual.to_token_stream().to_string()
                            == expected.to_token_stream().to_string()
                    });
            let mount: syn::Stmt = syn::parse_quote!(server.mount_oauth(receiver)?;);
            let startup: syn::Stmt =
                syn::parse_quote!(current.require_restored_startup_sql(&runtime)?;);
            let timing: syn::Stmt = syn::parse_quote!(
                let request_timing = super::request_timing_setting(&runtime).unwrap_or(true);
            );
            bound.path.is_ident("BoundRestoredListener")
                && bound.rest.is_none()
                && same_fields
                && block.stmts.len() == 5
                && block.stmts[0].to_token_stream().to_string()
                    == startup.to_token_stream().to_string()
                && block.stmts[1].to_token_stream().to_string()
                    == timing.to_token_stream().to_string()
                && block.stmts[3].to_token_stream().to_string()
                    == mount.to_token_stream().to_string()
        };
        assert!(guarded(&actual.block));
        let mut raw = actual.block.clone();
        *raw.stmts.last_mut().unwrap() = syn::Stmt::Expr(syn::parse_quote!(Ok(server)), None);
        assert!(!guarded(&raw));
        let mut parts = actual.block.clone();
        *parts.stmts.last_mut().unwrap() =
            syn::Stmt::Expr(syn::parse_quote!(server.into_native_parts(admission)), None);
        assert!(!guarded(&parts));
        let mut foreign_admission = actual.block.clone();
        *foreign_admission.stmts.last_mut().unwrap() = syn::Stmt::Expr(
            syn::parse_quote!(Ok(BoundRestoredListener {
                _server: server,
                admission: Arc::new(AtomicBool::new(true)),
                local: std::marker::PhantomData,
            })),
            None,
        );
        assert!(!guarded(&foreign_admission));
        let mut unmounted = actual.block.clone();
        unmounted.stmts.remove(3);
        assert!(!guarded(&unmounted));
        let mut timing_before_owner = actual.block.clone();
        timing_before_owner.stmts.swap(0, 1);
        assert!(!guarded(&timing_before_owner));
        let mut ignored_instance_setting = actual.block.clone();
        ignored_instance_setting.stmts[1] = syn::parse_quote!(let request_timing = true;);
        assert!(!guarded(&ignored_instance_setting));
        struct Factories(usize);
        impl<'ast> Visit<'ast> for Factories {
            fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
                self.0 += usize::from(value.path.is_ident("BoundRestoredListener"));
                syn::visit::visit_expr_struct(self, value);
            }
        }
        let mut factories = Factories(0);
        factories.visit_file(&file);
        assert_eq!(factories.0, 1);
    }
}
