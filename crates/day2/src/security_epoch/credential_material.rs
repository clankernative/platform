//! Native request credentials are secret material, not a transferable identity
//! proof. UID-target minting must retain its authenticated request provenance.

use super::{
    admission_work::{self, Bytes, Work},
    controller::evidence::{PreparationFailure, PreparationStep},
    native_clock::NativeAcquisition,
    transport::{NativeHttp, Route, check_response_length, check_response_status},
};
use anyhow::{Result, ensure};
use day2_capabilities::security_epoch::EpochIam;
use reqwest::{StatusCode, blocking::Client, header::HeaderValue};
use serde::Deserialize;
use std::{io::Read, marker::PhantomData, rc::Rc, time::Duration};
use zeroize::{Zeroize, Zeroizing};

pub(crate) struct CredentialMaterial {
    bytes: Vec<u8>,
    local: PhantomData<Rc<()>>,
}

/// Secret material with an expiry observed from the exact token at full
/// admission. This is not a role, connection, writer or current counter proof.
/// The actual retained connection must check its same enrolled owner/clock
/// anchors before applying this ceiling to each distinct request interval.
pub(super) struct CounterMaterial {
    material: CredentialMaterial,
    deadline: Duration,
    latest: Duration,
    valid: bool,
}

// Dispatch pacing DATA only. Leave time for the existing 30-second socket
// delivery bound and a separate five-second authentication operation. This
// does not extend either bound or the actual credential expiry; delayed drain,
// suspension or an earlier cap still makes re-admission refuse.
const COUNTER_READMISSION_LEAD: Duration = Duration::from_secs(45);

fn check_counter_response_status(status: StatusCode) -> Result<()> {
    check_response_status(status, "epoch_counter_tokeninfo_status_or_bound")
}

fn check_counter_response_length(length: Option<u64>) -> Result<()> {
    check_response_length(length, 16_384, "epoch_counter_tokeninfo_status_or_bound")
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<A> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <CounterMaterial as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
};

impl CounterMaterial {
    /// Issue this hint once after successful admission, never on a request.
    /// A runtime timer may wake maintenance from it, but only the actual idle
    /// owner, original and old expiry checks can authorize re-admission.
    pub(super) fn readmission_delay(&self, now: Duration) -> Duration {
        self.deadline
            .saturating_sub(COUNTER_READMISSION_LEAD)
            .saturating_sub(now)
    }

    pub(super) fn check(
        &mut self,
        acquisition: &mut NativeAcquisition,
        max_lease_seconds: u32,
    ) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "epoch_counter_credential_refused");
            ensure!(
                acquisition.sample()?.elapsed >= self.latest,
                "epoch_counter_connection_clock_rewind"
            );
            *acquisition = acquisition.narrow(max_lease_seconds, self.deadline)?;
            self.latest = acquisition.sample()?.elapsed;
            Ok(())
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }

    pub(super) fn authorization(
        &mut self,
        acquisition: &mut NativeAcquisition,
        max_lease_seconds: u32,
    ) -> Result<HeaderValue> {
        let result = (|| {
            // Narrow the actual request; do not retain or renew the admission
            // acquisition, and do not equate separate request domains.
            self.check(acquisition, max_lease_seconds)?;
            self.material.authorization()
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }
}

impl CredentialMaterial {
    fn from_bytes(mut bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty()
            || bytes.len() > 8192
            || !bytes.iter().all(|byte| byte.is_ascii_graphic())
        {
            bytes.zeroize();
            anyhow::bail!("epoch_native_credential_shape");
        }
        Ok(Self {
            bytes,
            local: PhantomData,
        })
    }

    pub(super) fn authorization(&self) -> Result<HeaderValue> {
        let mut value = Zeroizing::new(Vec::with_capacity(7 + self.bytes.len()));
        value.extend_from_slice(b"Bearer ");
        value.extend_from_slice(&self.bytes);
        let header = HeaderValue::from_bytes(&value)
            .map_err(|_| anyhow::anyhow!("epoch_native_credential_shape"));
        value.zeroize();
        let mut header = header?;
        header.set_sensitive(true);
        Ok(header)
    }

    /// Fixed trusted-native profile paths. Reading a projection alone does not
    /// authenticate it or bind the caller process to the token's Pod.
    pub(super) fn kubernetes_api(acquisition: &mut NativeAcquisition) -> Result<Self> {
        Self::projection(
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            acquisition,
        )
    }

    pub(super) fn subject(acquisition: &mut NativeAcquisition) -> Result<Self> {
        Self::projection("/var/run/secrets/day2-native/subject-token", acquisition)
    }

    fn projection(path: &str, acquisition: &mut NativeAcquisition) -> Result<Self> {
        let result = (|| {
            acquisition.remaining()?;
            let mut bytes = Zeroizing::new(Vec::new());
            let file = std::fs::File::from(rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?);
            ensure!(
                file.metadata()?.is_file(),
                "epoch_native_projection_not_regular"
            );
            file.take(8193).read_to_end(&mut bytes)?;
            acquisition.remaining()?;
            Self::from_bytes(std::mem::take(&mut *bytes))
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    pub(super) fn metadata_source(acquisition: &mut NativeAcquisition) -> Result<Self> {
        let mut profile =
            super::self_check_profile::enter(super::self_check_profile::Category::ProviderHttp);
        let mut work = None;
        let result = (|| {
            acquisition.remaining()?;
            let client = Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .build()?;
            let request = client.get("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token")
                .header("Metadata-Flavor","Google").timeout(acquisition.remaining()?);
            work = Some(admission_work::begin(Work::MetadataAdmission));
            let response = request
                .send()
                .map_err(|_| anyhow::anyhow!("epoch_native_metadata_unavailable"))?;
            acquisition.remaining()?;
            check_response_status(response.status(), "epoch_native_metadata_status_or_bound")?;
            if !response
                .headers()
                .get("Metadata-Flavor")
                .is_some_and(|value| value == "Google")
            {
                return Err(anyhow::anyhow!("epoch_native_metadata_status_or_bound")
                    .context(super::transport::ResponseRefusal::MetadataFlavor));
            }
            check_response_length(
                response.content_length(),
                12_288,
                "epoch_native_metadata_status_or_bound",
            )?;
            let mut bytes = Zeroizing::new(Vec::new());
            let read = response
                .take(12_289)
                .read_to_end(&mut bytes)
                .map_err(|_| anyhow::anyhow!("epoch_native_metadata_unavailable"));
            if let Some(work) = &mut work {
                work.bytes(Bytes::ResponseBody, bytes.len() as u64);
            }
            read?;
            profile.finish();
            acquisition.remaining()?;
            ensure!(bytes.len() <= 12_288, "epoch_native_metadata_bound");
            Self::metadata_reply(&bytes)
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        if let Some(mut work) = work {
            work.finish(result.is_ok());
        }
        result
            .map_err(|error| PreparationFailure::at(PreparationStep::CounterMetadataSource, error))
    }

    /// Successful authenticated mint for the immutable target is retained by
    /// the native owning caller; expireTime is DATA, not qualified host UTC.
    pub(super) fn mint_target(
        source: &Self,
        selected: &EpochIam,
        http: &NativeHttp,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let body = br#"{"scope":["https://www.googleapis.com/auth/datastore"],"lifetime":"300s"}"#;
        let mut bytes = Zeroizing::new(
            http.request(
                Route::GoogleMint(selected),
                &source.authorization()?,
                Some(body),
                acquisition,
            )
            .map_err(|error| PreparationFailure::at(PreparationStep::CounterIamMint, error))?,
        );
        let result = Self::mint_reply(&bytes);
        bytes.zeroize();
        if result.is_err() {
            acquisition.refuse();
        }
        result.map_err(|error| PreparationFailure::at(PreparationStep::CounterIamMint, error))
    }

    /// Consume the actual minted token after the full caller's identity and
    /// recipient joins. The fixed authenticated v2 tokeninfo response supplies
    /// remaining seconds, not an invented UTC/BOOTTIME mapping or the requested
    /// mint lifetime. The caller retains the resulting secret in its real
    /// connection; neither parser DATA nor this material constructs that owner.
    pub(super) fn admit_counter(
        self,
        selected: &EpochIam,
        acquisition: &mut NativeAcquisition,
    ) -> Result<CounterMaterial> {
        let mut work = None;
        let result = (|| {
            let before = acquisition.sample()?.elapsed;
            let mut profile =
                super::self_check_profile::enter(super::self_check_profile::Category::ProviderHttp);
            // The documented endpoint requires a query parameter. Keep its
            // transient secret URL inside this closed transport and discard
            // every reqwest/URL/body error without formatting or chaining it.
            let mut address = url::Url::parse("https://www.googleapis.com/oauth2/v2/tokeninfo")
                .map_err(|_| anyhow::anyhow!("epoch_counter_tokeninfo_address"))?;
            address
                .query_pairs_mut()
                .append_pair("access_token", self.subject_text()?)
                .append_pair("fields", "audience,issued_to,expires_in,scope");
            let client = Client::builder()
                .https_only(true)
                .no_proxy()
                .referer(false)
                .connection_verbose(false)
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(2))
                .build()
                .map_err(|_| anyhow::anyhow!("epoch_counter_tokeninfo_transport"))?;
            let remaining = acquisition.remaining()?.min(Duration::from_secs(5));
            let request = client
                .post(address)
                .header(reqwest::header::CACHE_CONTROL, "no-store")
                .timeout(remaining);
            work = Some(admission_work::begin(Work::CredentialAdmission));
            let response = request
                .send()
                .map_err(|_| anyhow::anyhow!("epoch_counter_tokeninfo_unavailable"))?;
            acquisition.remaining()?;
            check_counter_response_status(response.status())?;
            check_counter_response_length(response.content_length())?;
            let mut bytes = Zeroizing::new(Vec::new());
            let read = response
                .take(16_385)
                .read_to_end(&mut bytes)
                .map_err(|_| anyhow::anyhow!("epoch_counter_tokeninfo_unavailable"));
            if let Some(work) = &mut work {
                work.bytes(Bytes::ResponseBody, bytes.len() as u64);
            }
            read?;
            profile.finish();
            acquisition.remaining()?;
            let seconds = counter_token_remaining(&bytes, selected)?;
            // Charge all setup/transport time from BEFORE introspection and a
            // whole second for integer quantization. Equality still refuses.
            let deadline = counter_deadline(before, seconds)?;
            let latest = acquisition.sample()?.elapsed;
            ensure!(latest < deadline, "epoch_counter_credential_expired");
            Ok(CounterMaterial {
                material: self,
                deadline,
                latest,
                valid: true,
            })
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        if let Some(mut work) = work {
            work.finish(result.is_ok());
        }
        result.map_err(|error| PreparationFailure::at(PreparationStep::CounterTokenInfo, error))
    }

    fn metadata_reply(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 12_288, "epoch_native_metadata_bound");
        let mut value: MetadataReply = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("epoch_native_metadata_shape"))?;
        ensure!(
            value.token_type == "Bearer" && value.expires_in > 0 && value.expires_in <= 3600,
            "epoch_native_metadata_shape"
        );
        Self::from_bytes(std::mem::take(&mut value.access_token).into_bytes())
    }

    fn mint_reply(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 65_536, "epoch_native_mint_reply_bound");
        let mut value: MintReply = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("epoch_native_mint_reply_shape"))?;
        let expiry = time::OffsetDateTime::parse(
            &value.expire_time,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| anyhow::anyhow!("epoch_native_mint_expiry_shape"))?;
        ensure!(
            expiry.offset() == time::UtcOffset::UTC,
            "epoch_native_mint_expiry_shape"
        );
        Self::from_bytes(std::mem::take(&mut value.access_token).into_bytes())
    }

    pub(super) fn subject_text(&self) -> Result<&str> {
        std::str::from_utf8(&self.bytes)
            .map_err(|_| anyhow::anyhow!("epoch_native_credential_shape"))
    }
}

impl Drop for CredentialMaterial {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataReply {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

impl Drop for MetadataReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintReply {
    access_token: String,
    expire_time: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CounterTokenInfo {
    audience: String,
    issued_to: String,
    expires_in: i32,
    scope: String,
}

fn counter_token_remaining(bytes: &[u8], selected: &EpochIam) -> Result<u32> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 16_384,
        "epoch_counter_tokeninfo_bound"
    );
    // A derived struct can also accept an array through a Value deserializer.
    // Admit only an object, with duplicate rejection in the bounded decoder.
    let object: serde_json::Map<String, serde_json::Value> =
        crate::json::decode(bytes).map_err(|_| anyhow::anyhow!("epoch_counter_tokeninfo_shape"))?;
    let info: CounterTokenInfo = serde_json::from_value(serde_json::Value::Object(object))
        .map_err(|_| anyhow::anyhow!("epoch_counter_tokeninfo_shape"))?;
    let EpochIam::GkeWorkloadIdentityV1 {
        service_account_uid,
        ..
    } = selected;
    ensure!(
        info.audience == service_account_uid.as_str()
            && info.issued_to == service_account_uid.as_str()
            && info.scope == "https://www.googleapis.com/auth/datastore"
            && (2..=300).contains(&info.expires_in),
        "epoch_counter_tokeninfo_binding_or_expiry"
    );
    Ok(u32::try_from(info.expires_in)?)
}

// Arithmetic DATA only. The sole production caller supplies its actual
// pre-introspection continuous sample and the exact authenticated response.
fn counter_deadline(before: Duration, remaining_seconds: u32) -> Result<Duration> {
    ensure!(
        (2..=300).contains(&remaining_seconds),
        "epoch_counter_tokeninfo_expiry"
    );
    before
        .checked_add(Duration::from_secs(u64::from(remaining_seconds - 1)))
        .ok_or_else(|| anyhow::anyhow!("epoch_counter_tokeninfo_clock_overflow"))
}

impl Drop for MintReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::transport::ResponseRefusal as CounterResponseRefusal;
    use day2_capabilities::Digest;

    #[test]
    fn counter_response_metadata_preserves_status_and_length_acceptance() {
        for code in 100..=599 {
            let status = StatusCode::from_u16(code).unwrap();
            for length in [None, Some(0), Some(16_384), Some(16_385), Some(u64::MAX)] {
                let actual = check_counter_response_status(status)
                    .and_then(|()| check_counter_response_length(length));
                assert_eq!(
                    actual.is_ok(),
                    status.is_success() && length.is_none_or(|bytes| bytes <= 16_384)
                );
                if let Err(error) = actual {
                    assert_eq!(
                        error.downcast_ref::<&'static str>(),
                        Some(&"epoch_counter_tokeninfo_status_or_bound")
                    );
                    let observed = *error.downcast_ref::<CounterResponseRefusal>().unwrap();
                    if status.is_success() {
                        assert_eq!(observed, CounterResponseRefusal::DeclaredLengthBound);
                    } else {
                        assert_ne!(observed, CounterResponseRefusal::DeclaredLengthBound);
                    }
                    assert_eq!(error.to_string(), "response metadata refused");
                }
            }
        }
        for (code, expected) in [
            (400, CounterResponseRefusal::BadRequest),
            (401, CounterResponseRefusal::Unauthorized),
            (403, CounterResponseRefusal::Forbidden),
            (404, CounterResponseRefusal::NotFound),
            (405, CounterResponseRefusal::MethodNotAllowed),
            (408, CounterResponseRefusal::RequestTimeout),
            (429, CounterResponseRefusal::RateLimited),
            (500, CounterResponseRefusal::ServerError),
            (599, CounterResponseRefusal::ServerError),
            (302, CounterResponseRefusal::OtherStatus),
            (418, CounterResponseRefusal::OtherStatus),
        ] {
            let error =
                check_counter_response_status(StatusCode::from_u16(code).unwrap()).unwrap_err();
            assert_eq!(
                error.downcast_ref::<CounterResponseRefusal>(),
                Some(&expected)
            );
        }
    }

    fn counter_response_guards_precede_body_read(source: &str) -> bool {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Calls(Vec<String>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                syn::visit::visit_expr_call(self, call);
                if let syn::Expr::Path(path) = &*call.func {
                    if let Some(name) = path.path.get_ident() {
                        self.0.push(name.to_string());
                    }
                }
            }
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                syn::visit::visit_expr_method_call(self, call);
                self.0.push(call.method.to_string());
            }
        }
        let file = syn::parse_file(source).unwrap();
        let body=file.items.iter().find_map(|item| {
            let syn::Item::Impl(item)=item else { return None; };
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.is_ident("CredentialMaterial")) { return None; }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident=="admit_counter" => Some(&function.block),
                _ => None,
            })
        }).unwrap();
        let mut calls = Calls::default();
        calls.visit_block(body);
        let actual = body
            .stmts
            .iter()
            .find_map(|statement| {
                let syn::Stmt::Local(local) = statement else {
                    return None;
                };
                if !matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="result") {
                    return None;
                }
                let syn::Expr::Call(call) = &*local.init.as_ref()?.expr else {
                    return None;
                };
                let syn::Expr::Paren(parenthesized) = &*call.func else {
                    return None;
                };
                let syn::Expr::Closure(closure) = &*parenthesized.expr else {
                    return None;
                };
                let syn::Expr::Block(block) = &*closure.body else {
                    return None;
                };
                Some(&block.block)
            })
            .unwrap();
        let checked = |name: &str, receiver_method: &str| {
            actual.stmts.iter().position(|statement| {
                let syn::Stmt::Expr(syn::Expr::Try(attempt),Some(_))=statement else { return false; };
                let syn::Expr::Call(call)=&*attempt.expr else { return false; };
                matches!(&*call.func,syn::Expr::Path(path) if path.path.is_ident(name))
                    && call.args.len()==1
                    && matches!(&call.args[0],syn::Expr::MethodCall(method)
                        if method.method==receiver_method && method.args.is_empty()
                            && matches!(&*method.receiver,syn::Expr::Path(path) if path.path.is_ident("response")))
            })
        };
        let read = actual.stmts.iter().position(|statement| {
            let syn::Stmt::Local(local)=statement else { return false; };
            if !matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="read") { return false; }
            matches!(local.init.as_ref().map(|init|&*init.expr),Some(syn::Expr::MethodCall(mapped))
                if mapped.method=="map_err"
                    && matches!(&*mapped.receiver,syn::Expr::MethodCall(read)
                        if read.method=="read_to_end"
                            && matches!(&*read.receiver,syn::Expr::MethodCall(take)
                                if take.method=="take"
                                    && matches!(&*take.receiver,syn::Expr::Path(path) if path.path.is_ident("response")))))
        });
        let selected = calls
            .0
            .iter()
            .filter(|name| {
                matches!(
                    name.as_str(),
                    "send"
                        | "status"
                        | "check_counter_response_status"
                        | "content_length"
                        | "check_counter_response_length"
                        | "take"
                        | "read_to_end"
                )
            })
            .map(String::as_str)
            .collect::<Vec<_>>();
        matches!((checked("check_counter_response_status","status"),
            checked("check_counter_response_length","content_length"),read),
            (Some(status),Some(length),Some(read)) if status<length && length<read)
            && selected
                == [
                    "send",
                    "status",
                    "check_counter_response_status",
                    "content_length",
                    "check_counter_response_length",
                    "take",
                    "read_to_end",
                ]
    }

    #[test]
    fn actual_counter_transport_keeps_status_then_length_before_secret_body() {
        let source = include_str!("credential_material.rs");
        assert!(counter_response_guards_precede_body_read(source));
        for label in [
            "check_counter_response_status",
            "check_counter_response_length",
        ] {
            let changed = source.replacen(
                &format!("{label}(response."),
                "unchecked_metadata(response.",
                1,
            );
            assert_ne!(source, changed);
            assert!(!counter_response_guards_precede_body_read(&changed));
            let call = if label == "check_counter_response_status" {
                "check_counter_response_status(response.status())?;"
            } else {
                "check_counter_response_length(response.content_length())?;"
            };
            for ignored in [
                call.replace("?;", ";"),
                format!("let _ = {};", call.trim_end_matches("?;")),
                format!("if false {{ {call} }}"),
            ] {
                let changed = source.replacen(call, &ignored, 1);
                assert_ne!(source, changed);
                assert!(!counter_response_guards_precede_body_read(&changed));
            }
        }
        let changed = source.replacen(
            "check_counter_response_status(response.status())?;",
            "check_counter_response_length(response.content_length())?;",
            1,
        );
        assert!(!counter_response_guards_precede_body_read(&changed));
    }

    fn selected_counter_account() -> EpochIam {
        EpochIam::GkeWorkloadIdentityV1 {
            service_account: "counter@selected-project.iam.gserviceaccount.com".to_owned(),
            service_account_uid: "100000000000000000007".to_owned().try_into().unwrap(),
        }
    }

    #[test]
    fn counter_token_introspection_requires_exact_recipient_scope_and_remaining_lifetime() {
        // Provider response DATA only; none constructs an admitted connection.
        let selected = selected_counter_account();
        let good = serde_json::json!({
            "audience":"100000000000000000007",
            "issued_to":"100000000000000000007",
            "expires_in":300,
            "scope":"https://www.googleapis.com/auth/datastore"
        });
        assert_eq!(
            counter_token_remaining(&serde_json::to_vec(&good).unwrap(), &selected).unwrap(),
            300
        );
        for (key, value) in [
            ("audience", serde_json::json!("100000000000000000008")),
            ("issued_to", serde_json::json!("100000000000000000008")),
            (
                "scope",
                serde_json::json!("https://www.googleapis.com/auth/cloud-platform"),
            ),
            (
                "scope",
                serde_json::json!("https://www.googleapis.com/auth/datastore extra"),
            ),
            ("expires_in", serde_json::json!(0)),
            ("expires_in", serde_json::json!(1)),
            ("expires_in", serde_json::json!(-1)),
            ("expires_in", serde_json::json!(301)),
            ("expires_in", serde_json::json!("300")),
            ("expires_in", serde_json::json!(null)),
            ("extra", serde_json::json!("controlled-secret")),
        ] {
            let mut changed = good.clone();
            changed[key] = value;
            let error = counter_token_remaining(&serde_json::to_vec(&changed).unwrap(), &selected)
                .unwrap_err();
            assert!(!format!("{error:#}").contains("controlled-secret"));
        }
        for key in ["audience", "issued_to", "scope", "expires_in"] {
            let mut changed = good.clone();
            changed.as_object_mut().unwrap().remove(key);
            assert!(
                counter_token_remaining(&serde_json::to_vec(&changed).unwrap(), &selected).is_err()
            );
        }
        for bad in [
            br#"{"audience":"100000000000000000007","issued_to":"100000000000000000007","expires_in":300,"expires_in":299,"scope":"https://www.googleapis.com/auth/datastore"}"#.as_slice(),
            b"[]", b"controlled-secret",
            br#"["100000000000000000007","100000000000000000007",300,"https://www.googleapis.com/auth/datastore"]"#,
        ] {
            let error = counter_token_remaining(bad, &selected).unwrap_err();
            assert!(!format!("{error:#}").contains("controlled-secret"));
        }
        assert!(counter_token_remaining(&vec![b' '; 16_385], &selected).is_err());
    }

    #[test]
    fn counter_expiry_charges_transport_and_quantization_without_mapping_utc() {
        assert_eq!(
            counter_deadline(Duration::from_secs(10), 300).unwrap(),
            Duration::from_secs(309)
        );
        assert_eq!(
            counter_deadline(Duration::from_secs(10), 2).unwrap(),
            Duration::from_secs(11)
        );
        for seconds in [0, 1, 301, u32::MAX] {
            assert!(counter_deadline(Duration::from_secs(10), seconds).is_err());
        }
        assert!(counter_deadline(Duration::MAX, 2).is_err());
    }

    #[test]
    fn readmission_pacing_is_non_authorizing_and_never_moves_the_actual_expiry() {
        // Lower material/clock DATA only; no idle native admission is forged.
        for (latest, now, expected) in [
            (100, 100, 255),
            (100, 350, 5),
            (100, 355, 0),
            (355, 356, 0),
            (355, 401, 0),
        ] {
            let material = CounterMaterial {
                material: CredentialMaterial::from_bytes(b"controlled-secret".to_vec()).unwrap(),
                deadline: Duration::from_secs(400),
                latest: Duration::from_secs(latest),
                valid: true,
            };
            for _ in 0..3 {
                assert_eq!(
                    material.readmission_delay(Duration::from_secs(now)),
                    Duration::from_secs(expected)
                );
                assert_eq!(material.deadline, Duration::from_secs(400));
                assert_eq!(material.latest, Duration::from_secs(latest));
            }
        }
        let mut material = CounterMaterial {
            material: CredentialMaterial::from_bytes(b"controlled-secret".to_vec()).unwrap(),
            deadline: Duration::from_secs(400),
            latest: Duration::from_secs(355),
            valid: true,
        };
        assert_eq!(
            material.readmission_delay(Duration::from_secs(355)),
            Duration::ZERO
        );
        let mut expired = NativeAcquisition::fixture(
            Digest::new(b"expired admission attempt"),
            std::process::id(),
            Duration::from_secs(400),
            Duration::from_secs(5),
        );
        assert!(material.check(&mut expired, 5).is_err());
        assert!(expired.remaining().is_err());
        assert!(!material.valid);
    }

    #[test]
    fn counter_material_narrows_each_original_request_and_expiry_refuses_permanently() {
        // Only a lower secret/clock adapter fixture. It supplies no enrolled
        // owner, native connection, current counter or positive writer proof.
        let mut material = CounterMaterial {
            material: CredentialMaterial::from_bytes(b"controlled-secret".to_vec()).unwrap(),
            deadline: Duration::from_secs(12),
            latest: Duration::from_secs(9),
            valid: true,
        };
        let mut first = NativeAcquisition::fixture(
            day2_capabilities::Digest::new(b"request-one"),
            std::process::id(),
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        assert!(
            material
                .authorization(&mut first, 5)
                .unwrap()
                .is_sensitive()
        );
        assert_eq!(
            first.interval_data().unwrap(),
            (Duration::from_secs(10), Duration::from_secs(12))
        );
        let mut equal = NativeAcquisition::fixture(
            day2_capabilities::Digest::new(b"request-two"),
            std::process::id(),
            Duration::from_secs(12),
            Duration::from_secs(5),
        );
        assert!(material.authorization(&mut equal, 5).is_err());
        assert!(first.sample().is_ok());
        // Another independently live original cannot restore expired material.
        assert!(material.authorization(&mut first, 5).is_err());
        assert!(first.sample().is_err());
    }

    #[test]
    fn counter_material_keeps_one_expiry_across_distinct_originals_and_refuses_rewind() {
        // Lower secret/clock adapter only. Positive native admission and the
        // same enrolled/physical owner remain mandatory at the production port.
        let mut material = CounterMaterial {
            material: CredentialMaterial::from_bytes(b"controlled-secret".to_vec()).unwrap(),
            deadline: Duration::from_secs(20),
            latest: Duration::from_secs(9),
            valid: true,
        };
        let request = |name: &[u8], origin| {
            NativeAcquisition::fixture(
                Digest::new(name),
                std::process::id(),
                Duration::from_secs(origin),
                Duration::from_secs(5),
            )
        };
        let mut first = request(b"first-request", 10);
        material.authorization(&mut first, 5).unwrap();
        assert_eq!(
            first.interval_data().unwrap(),
            (Duration::from_secs(10), Duration::from_secs(15))
        );
        let mut second = request(b"second-request", 18);
        material.authorization(&mut second, 5).unwrap();
        assert_eq!(
            second.interval_data().unwrap(),
            (Duration::from_secs(18), Duration::from_secs(20))
        );
        assert_eq!(material.deadline, Duration::from_secs(20));
        let mut rewound = request(b"third-request", 17);
        assert!(material.authorization(&mut rewound, 5).is_err());
        assert!(rewound.sample().is_err());
        assert!(material.authorization(&mut second, 5).is_err());
        assert!(second.sample().is_err());
    }

    #[test]
    fn counter_expiry_shortens_the_same_actual_stage_view_without_moving_its_origin() {
        // Lower clock adapter only. The production seam additionally requires
        // the same genuine enrolled owner and exact Current purpose.
        let mut stage = NativeAcquisition::fixture(
            Digest::new(b"original-request"),
            std::process::id(),
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        let mut read = stage.narrow(5, Duration::from_secs(15)).unwrap();
        let mut material = CounterMaterial {
            material: CredentialMaterial::from_bytes(b"controlled-secret".to_vec()).unwrap(),
            deadline: Duration::from_secs(12),
            latest: Duration::from_secs(9),
            valid: true,
        };
        material.authorization(&mut read, 5).unwrap();
        stage.exchange_current_views(&mut read).unwrap();
        for view in [&mut stage, &mut read] {
            assert_eq!(
                view.interval_data().unwrap(),
                (Duration::from_secs(10), Duration::from_secs(12))
            );
        }
        let mut foreign = NativeAcquisition::fixture(
            Digest::new(b"another-request"),
            std::process::id(),
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        assert!(stage.exchange_current_views(&mut foreign).is_err());
        assert!(stage.sample().is_err());
        assert!(read.sample().is_err());
        assert!(foreign.sample().is_err());
    }

    #[test]
    fn material_and_headers_reject_injection_and_do_not_format_the_secret() {
        for bytes in [
            Vec::new(),
            b"a\r\nb".to_vec(),
            b"a b".to_vec(),
            vec![b'a'; 8193],
            vec![0xff],
        ] {
            let error = CredentialMaterial::from_bytes(bytes)
                .err()
                .unwrap()
                .to_string();
            assert_eq!(error, "epoch_native_credential_shape");
        }
        let material = CredentialMaterial::from_bytes(b"controlled-secret".to_vec()).unwrap();
        let header = material.authorization().unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains("controlled-secret"));
    }

    #[test]
    fn malformed_duplicate_or_unexpected_secret_replies_return_only_codes() {
        let good =
            br#"{"access_token":"controlled-secret","token_type":"Bearer","expires_in":300}"#;
        assert!(CredentialMaterial::metadata_reply(good).is_ok());
        for bad in [
            br#"{"access_token":"controlled-secret","token_type":"Other","expires_in":300}"#.as_slice(),
            br#"{"access_token":"controlled-secret","token_type":"Bearer","expires_in":0}"#,
            br#"{"access_token":"controlled-secret","access_token":"second","token_type":"Bearer","expires_in":300}"#,
            br#"{"access_token":"controlled-secret","token_type":"Bearer","expires_in":300,"extra":"secret"}"#,
            b"controlled-secret"
        ] {
            let error=CredentialMaterial::metadata_reply(bad).err().unwrap().to_string();
            assert!(error.starts_with("epoch_native_metadata_"));
            assert!(!error.contains("controlled-secret"));
        }
        let minted = br#"{"accessToken":"controlled-secret","expireTime":"2026-10-14T00:05:00Z"}"#;
        assert!(CredentialMaterial::mint_reply(minted).is_ok());
        assert!(
            CredentialMaterial::mint_reply(
                br#"{"accessToken":"controlled-secret","expireTime":"2026-10-14T00:05:00+01:00"}"#
            )
            .is_err()
        );
        assert!(
            CredentialMaterial::mint_reply(
                br#"{"accessToken":"controlled-secret","expireTime":"not-time"}"#
            )
            .is_err()
        );
        // The accepted timestamp is historical syntax only, never a UTC clock.
    }
}
