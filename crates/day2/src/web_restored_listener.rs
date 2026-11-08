//! Private restored listener resources. The parent cannot extract the server;
//! only this fixed genuine-startup builder can create the opaque value.
use super::{ListenerOptions, ListenerSql, LocalServer, PresentationSource, SignIn};
use crate::store::Runtime;
use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Concrete restored listener resources only. No method can expose the raw
/// server, start serving or extract native parts before the fixed installer
/// owns both completed startup settlements and the whole native parent.
pub(crate) struct BoundRestoredListener {
    // Retain and drop the real resource without exposing an operational exit.
    _server: LocalServer,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}

pub(super) fn bind(
    runtime: Arc<Runtime>,
    listener: TcpListener,
    edge: &crate::artifact::Edge,
    verifier: crate::iap::Verifier,
    receiver: Arc<crate::oauth::shell_transport::AppApprovalReceiver>,
    concurrency: usize,
    current: &mut crate::oauth::native_management::RuntimeConsumer<'_, '_>,
) -> Result<BoundRestoredListener> {
    current.require_restored_startup_sql(&runtime)?;
    let mut server = LocalServer::bind_listener_with_sql(
        runtime,
        listener,
        edge.authority().into(),
        edge.origin.clone(),
        SignIn::Edge(verifier),
        ListenerOptions {
            concurrency,
            health_endpoints: true,
            presentation: PresentationSource::Environment,
        },
        ListenerSql::Restored(current),
    )?;
    server.mount_oauth(receiver)?;
    Ok(BoundRestoredListener {
        _server: server,
        local: std::marker::PhantomData,
    })
}

#[cfg(test)]
mod tests {
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
            bound.path.is_ident("BoundRestoredListener")
                && bound.rest.is_none()
                && same_fields
                && block.stmts.len() == 4
                && block.stmts[2].to_token_stream().to_string()
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
        let mut unmounted = actual.block.clone();
        unmounted.stmts.remove(2);
        assert!(!guarded(&unmounted));
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
