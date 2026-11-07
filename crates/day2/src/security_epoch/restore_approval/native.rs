//! Closed producer input for native restore consumption. Deliberately
//! uninhabited: there is no genuine producer, wire/scalar constructor, fixture
//! promotion or accepting fallback. The eventual origin must own the actual
//! verified approval, current authority/clock and outside-archive consume owner.
use super::ApprovalRequest;
use anyhow::Result;
use day2_capabilities::Digest;
use std::{marker::PhantomData, rc::Rc};

// No production OR test variant. DATA cannot supply this origin. Adding the
// genuine source is a separate reviewed producer join, not a DTO conversion.
enum NativeOrigin {}

// The actual source owns terminal cleanup. Keep its destructor nongeneric so
// the existing proof scanner pins it without an exception or weaker rule.
struct NativeSource {
    origin: NativeOrigin,
}

impl NativeSource {
    fn refuse(&mut self) {
        match self.origin {}
    }
}

impl Drop for NativeSource {
    fn drop(&mut self) {
        self.refuse();
    }
}

/// The lifetime is reserved for the genuine retained source. This marker is
/// not authentication; the empty origin makes safe construction impossible.
pub(crate) struct NativeRestoreApproval<'source> {
    origin: NativeSource,
    source: PhantomData<(&'source mut (), Rc<()>)>,
}

/// Owns the consumed input, including its original source lifetime. Moving the
/// typed owner into the fencing Approval avoids lending a replaceable token or
/// reconstructing a new original from a consumption receipt.
pub(crate) struct ConsumedRestoreApproval<'source> {
    approval: NativeRestoreApproval<'source>,
}

/// Observation DATA only. The domain/origin/deadline must remain fixed from the
/// actual restore original in its qualified common clock domain; bounds are
/// nanoseconds in that domain.
/// The producer also checks the signed approval's unchanged one-hour absolute
/// validity with its genuine qualified clock/floor. Neither bound is renewed.
pub(crate) struct ApprovalObservation {
    domain: Digest,
    origin_ns: u64,
    deadline_ns: u64,
    lower_ns: u64,
    upper_ns: u64,
}

impl<'source> NativeRestoreApproval<'source> {
    /// Future implementation must compare the COMPLETE expected request, bind
    /// the exact operation, arm before the durable single-use CAS and return
    /// only after a known committed result and actual same-original postcheck.
    /// Unknown completion must consume/refuse, never retry or reload a receipt
    /// into this type. No transaction may span signing/provider/peer IO.
    pub(crate) fn consume(
        self,
        _expected: &ApprovalRequest,
        _operation: &Digest,
    ) -> Result<ConsumedRestoreApproval<'source>> {
        match self.origin.origin {}
    }

    /// Local terminal refusal only, including after expiry; no IO, clock sample
    /// or authority acquisition. Drop must never regrant an available input.
    pub(crate) fn refuse(&mut self) {
        self.origin.refuse();
    }
}

impl ConsumedRestoreApproval<'_> {
    /// Future genuine implementation checks the SAME held origin, request,
    /// current authority/owners, original and fixed approval expiry. Observing
    /// any refusal permanently poisons the retained source; clock/input repair
    /// cannot resurrect it. Caller-supplied clock samples are never accepted.
    pub(crate) fn check(&mut self) -> Result<ApprovalObservation> {
        match self.approval.origin.origin {}
    }

    pub(crate) fn refuse(&mut self) {
        self.approval.refuse();
    }
}

impl ApprovalObservation {
    pub(crate) fn interval_data(&self) -> (&Digest, u64, u64) {
        (&self.domain, self.origin_ns, self.deadline_ns)
    }

    pub(crate) fn observation_data(&self) -> (u64, u64) {
        (self.lower_ns, self.upper_ns)
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($owner:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$owner as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(NativeRestoreApproval<'static>, Clone);
    assert_not_impl!(NativeRestoreApproval<'static>, Copy);
    assert_not_impl!(NativeRestoreApproval<'static>, Default);
    assert_not_impl!(NativeRestoreApproval<'static>, std::fmt::Debug);
    assert_not_impl!(NativeRestoreApproval<'static>, Send);
    assert_not_impl!(NativeRestoreApproval<'static>, Sync);
    assert_not_impl!(NativeRestoreApproval<'static>, serde::Serialize);
    assert_not_impl!(NativeRestoreApproval<'static>, serde::Deserialize<'static>);
    assert_not_impl!(ConsumedRestoreApproval<'static>, Clone);
    assert_not_impl!(ConsumedRestoreApproval<'static>, Copy);
    assert_not_impl!(ConsumedRestoreApproval<'static>, Default);
    assert_not_impl!(ConsumedRestoreApproval<'static>, std::fmt::Debug);
    assert_not_impl!(ConsumedRestoreApproval<'static>, Send);
    assert_not_impl!(ConsumedRestoreApproval<'static>, Sync);
    assert_not_impl!(ConsumedRestoreApproval<'static>, serde::Serialize);
    assert_not_impl!(
        ConsumedRestoreApproval<'static>,
        serde::Deserialize<'static>
    );
};

#[cfg(test)]
mod tests {
    use super::*;
    use syn::{ImplItem, Item, Type};

    fn closed(source: &str) -> Result<bool> {
        let file = syn::parse_file(source)?;
        let origins: Vec<_> = file
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Enum(value) if value.ident == "NativeOrigin" => Some(value),
                _ => None,
            })
            .collect();
        if origins.len() != 1 || !origins[0].variants.is_empty() {
            return Ok(false);
        }
        let mut native_source = false;
        let mut input = false;
        let mut consumed = false;
        let mut consume = false;
        for item in &file.items {
            if let Item::Struct(value) = item {
                if value.ident == "NativeSource" {
                    native_source = value.fields.len() == 1 && value.fields.iter().all(|field| {
                        matches!(field.vis, syn::Visibility::Inherited)
                            && field.ident.as_ref().is_some_and(|id| id == "origin")
                            && matches!(&field.ty, Type::Path(p) if p.path.is_ident("NativeOrigin"))
                    });
                }
                if matches!(
                    value.ident.to_string().as_str(),
                    "NativeRestoreApproval" | "ConsumedRestoreApproval"
                ) {
                    if value
                        .fields
                        .iter()
                        .any(|field| !matches!(field.vis, syn::Visibility::Inherited))
                    {
                        return Ok(false);
                    }
                    if value.ident == "NativeRestoreApproval" {
                        input=value.fields.iter().any(|field|
                            field.ident.as_ref().is_some_and(|id| id=="origin")
                            && matches!(&field.ty,Type::Path(p) if p.path.is_ident("NativeSource")));
                    } else {
                        consumed=value.fields.len()==1 && value.fields.iter().all(|field|
                            matches!(&field.ty,Type::Path(p) if p.path.segments.last().is_some_and(|p|p.ident=="NativeRestoreApproval")));
                    }
                }
            }
            if let Item::Impl(value) = item {
                let Type::Path(owner) = &*value.self_ty else {
                    continue;
                };
                if !owner
                    .path
                    .segments
                    .last()
                    .is_some_and(|p| p.ident == "NativeRestoreApproval")
                {
                    continue;
                }
                if let Some((_, implemented, _)) = &value.trait_ {
                    if implemented.is_ident("Drop") {
                        continue;
                    }
                    return Ok(false);
                }
                for method in &value.items {
                    let ImplItem::Fn(method) = method else {
                        return Ok(false);
                    };
                    if method.sig.ident == "consume" {
                        let Some(syn::FnArg::Receiver(receiver)) = method.sig.inputs.first() else {
                            return Ok(false);
                        };
                        consume = receiver.reference.is_none()
                            && receiver.colon_token.is_none()
                            && method.sig.inputs.len() == 3;
                    } else if method.sig.ident != "refuse" {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(native_source && input && consumed && consume)
    }

    #[test]
    fn native_input_has_no_data_model_or_default_origin_and_consumes_the_owned_source() -> Result<()>
    {
        let source = include_str!("native.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .unwrap();
        assert!(closed(source)?);
        for (from, to) in [
            (
                "enum NativeOrigin {}",
                "enum NativeOrigin { Data(ApprovalRequest) }",
            ),
            (
                "enum NativeOrigin {}",
                "enum NativeOrigin { #[cfg(test)] UnqualifiedModel }",
            ),
            ("        self,", "        &mut self,"),
            (
                "    origin: NativeSource,",
                "    pub(crate) origin: NativeSource,",
            ),
            (
                "    approval: NativeRestoreApproval<'source>,",
                "    approval: &'source NativeRestoreApproval<'source>,",
            ),
            (
                "    pub(crate) fn consume(",
                "    pub(crate) fn from_data() -> Self { unreachable!() }\n    pub(crate) fn consume(",
            ),
        ] {
            assert_eq!(source.matches(from).count(), 1, "mutation target");
            assert!(!closed(&source.replace(from, to))?);
        }
        Ok(())
    }
}
