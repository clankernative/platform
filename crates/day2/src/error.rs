//! Behavioral failures have stable codes; diagnostic context is never a classifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Category {
    Authentication,
    Forbidden,
    Conflict,
    InvalidInput,
    NotFound,
    Method,
    ContentType,
    Timeout,
    Internal,
}

macro_rules! failures {
    ($($name:ident => ($code:literal, $category:ident)),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum Failure { $($name),+ }

        impl Failure {
            pub(crate) fn code(self) -> &'static str {
                match self { $(Self::$name => $code),+ }
            }

            pub(crate) fn category(self) -> Category {
                match self { $(Self::$name => Category::$category),+ }
            }

            /// Decode a stable worker/journal code, never an error's diagnostic text.
            pub(crate) fn from_code(code: &str) -> Option<Self> {
                match code { $($code => Some(Self::$name)),+, _ => None }
            }
        }
    };
}

failures! {
    SignInRequired => ("sign_in_required", Authentication),
    // The front door's signed assertion was missing, malformed, forged, expired,
    // or addressed to another application. One code for all of them: a caller
    // probing the edge learns that the assertion failed, not which check did.
    InvalidIdentityAssertion => ("invalid_identity_assertion", Authentication),
    // The keys that sign assertions could not be fetched. Nothing is verified
    // without them, so this fails closed rather than trusting a header.
    IdentityKeysUnavailable => ("identity_keys_unavailable", Internal),
    // An address that was bound to one account now arrives with another — the
    // signature of a reassigned mailbox. Refused until an operator decides.
    PrincipalSubjectChanged => ("principal_subject_changed", Forbidden),
    // A service account at the human front door. Machine callers carry the
    // delegation protocol; without it there is no person to attribute work to.
    MachineCallerRequiresDelegation => ("machine_caller_requires_delegation", Forbidden),
    Forbidden => ("forbidden", Forbidden),
    RequiredAllRowsUnavailable => ("required_all_rows_unavailable", Forbidden),
    InvalidHost => ("invalid_host", Forbidden),
    InvalidOrigin => ("invalid_origin", Forbidden),
    InvalidCsrf => ("invalid_csrf", Forbidden),
    InvalidTicket => ("invalid_ticket", Forbidden),
    TicketScopeMismatch => ("ticket_scope_mismatch", Forbidden),
    ReceiptPolicyChanged => ("receipt_policy_changed", Forbidden),
    ReceiptAuthorityUnavailable => ("receipt_authority_unavailable", Forbidden),
    InvalidLoginLink => ("invalid_login_link", Forbidden),
    CapabilityForbidden => ("capability_forbidden", Forbidden),
    ResourceForbidden => ("resource_forbidden", Forbidden),
    ResourceAuthorityExpired => ("resource_authority_expired", Forbidden),
    ResourceLimitExceeded => ("resource_limit_exceeded", Forbidden),
    BudgetExhausted => ("budget_exhausted", Forbidden),
    BudgetUnavailable => ("budget_unavailable", Conflict),
    Conflict => ("conflict", Conflict),
    UniqueConstraintConflict => ("unique_constraint_conflict", Conflict),
    AmbiguousSelection => ("ambiguous_selection", Conflict),
    CollectionLimitExceeded => ("collection_limit_exceeded", Conflict),
    StaleVersion => ("stale_version", Conflict),
    VersionConflict => ("version_conflict", Conflict),
    PreparationConflict => ("preparation_conflict", Conflict),
    IdempotencyKeyConflict => ("idempotency_key_conflict", Conflict),
    TicketExpired => ("ticket_expired", Conflict),
    ArtifactBindingChanged => ("artifact_binding_changed", Conflict),
    AuthorityPolicyChanged => ("authority_policy_changed", Conflict),
    PreparationAuthorityChanged => ("preparation_authority_changed", Forbidden),
    EffectAuthorityChanged => ("effect_authority_changed", Forbidden),
    ContinuationAuthorityChanged => ("continuation_authority_changed", Forbidden),
    InstallationChanged => ("installation_changed", Conflict),
    BrandingBindingChanged => ("branding_binding_changed", Conflict),
    NotFound => ("not_found", NotFound),
    UnknownPage => ("unknown_page", NotFound),
    UnknownFields => ("unknown_fields", InvalidInput),
    DuplicateOrExcessFields => ("duplicate_or_excess_fields", InvalidInput),
    InvalidInteger => ("invalid_integer", InvalidInput),
    InvalidCursor => ("invalid_cursor", InvalidInput),
    UriBudget => ("uri_budget", InvalidInput),
    InvalidForm => ("invalid_form", InvalidInput),
    InvalidPageInput => ("invalid_page_input", InvalidInput),
    InvalidFormEncoding => ("invalid_form_encoding", InvalidInput),
    InvalidInput => ("invalid_input", InvalidInput),
    InvalidCollectionBound => ("invalid_collection_bound", InvalidInput),
    InvalidDomainValue => ("invalid_domain_value", InvalidInput),
    InvalidIdempotencyKey => ("invalid_idempotency_key", InvalidInput),
    UnsupportedMethod => ("unsupported_method", Method),
    UnsupportedContentType => ("unsupported_content_type", ContentType),
    WorkerTimeout => ("worker_timeout", Timeout),
    WorkerCrashed => ("worker_crashed", Internal),
    TransactionDeadline => ("transaction_budget_exceeded", Timeout),
    PreparationDeadline => ("preparation_deadline", Timeout),
    ExternalAmbiguous => ("external_outcome_ambiguous", Internal),
    Internal => ("internal_error", Internal),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Failure {}

pub(crate) fn classify(error: &anyhow::Error) -> Failure {
    error
        .downcast_ref::<Failure>()
        .copied()
        .unwrap_or(Failure::Internal)
}

/// Operator diagnostics contain only closed error types and numeric OS/SQLite
/// codes. Never serialize error messages, source context, paths or app frames.
/// This evidence does not change the public failure category or retry policy.
pub(crate) fn diagnostic(error: &anyhow::Error) -> serde_json::Value {
    use serde_json::json;
    let failure = error
        .downcast_ref::<Failure>()
        .map(|failure| failure.code());
    let sqlite = error.downcast_ref::<rusqlite::Error>().map(|error| {
        if let rusqlite::Error::SqliteFailure(code, _) = error {
            json!({"primary":code.extended_code & 0xff,"extended":code.extended_code})
        } else {
            json!({"kind":"non_engine"})
        }
    });
    let io = error
        .downcast_ref::<std::io::Error>()
        .map(|error| json!({"kind":format!("{:?}",error.kind()),"errno":error.raw_os_error()}));
    let json = error
        .downcast_ref::<serde_json::Error>()
        .map(|error| format!("{:?}", error.classify()));
    let worker_exit = error
        .downcast_ref::<crate::worker::ExitEvidence>()
        .map(|exit| json!({"code":exit.code,"signal":exit.signal}));
    json!({"failure":failure,"sqlite":sqlite,"io":io,"json":json,"worker_exit":worker_exit})
}

/// Preserve machine-readable codes when observations acquire diagnostic context.
pub(crate) fn observation_code(error: &anyhow::Error) -> String {
    error
        .downcast_ref::<Failure>()
        .map_or_else(|| error.to_string(), |failure| failure.code().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_diagnostics_retain_codes_without_context_or_payloads() {
        let private = "PRIVATE_TOKEN_PATH_AND_APPLICATION_BODY";
        let sqlite = anyhow::Error::new(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some(private.into()),
        ))
        .context(private);
        assert_eq!(diagnostic(&sqlite)["sqlite"]["primary"], 5);
        assert_eq!(diagnostic(&sqlite)["sqlite"]["extended"], 5);
        let io = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            private,
        ))
        .context(private);
        assert_eq!(diagnostic(&io)["io"]["kind"], "PermissionDenied");
        let parse =
            anyhow::Error::new(serde_json::from_str::<serde_json::Value>(private).unwrap_err());
        assert_eq!(diagnostic(&parse)["json"], "Syntax");
        let worker = anyhow::Error::new(Failure::WorkerCrashed)
            .context(crate::worker::ExitEvidence {
                code: None,
                signal: Some(9),
            })
            .context(private);
        assert_eq!(classify(&worker), Failure::WorkerCrashed);
        assert_eq!(diagnostic(&worker)["worker_exit"]["signal"], 9);
        assert_eq!(diagnostic(&worker)["failure"], "worker_crashed");
        let opaque = anyhow::anyhow!(private).context(private);
        for error in [&sqlite, &io, &parse, &worker, &opaque] {
            assert!(!diagnostic(error).to_string().contains(private));
        }
        assert_eq!(classify(&sqlite), Failure::Internal);
        assert!(
            diagnostic(&opaque)
                .as_object()
                .unwrap()
                .values()
                .all(|value| value.is_null())
        );
    }

    #[test]
    fn diagnostic_text_cannot_forge_or_change_a_failure_category() {
        let error = anyhow::Error::new(Failure::Forbidden)
            .context("read customer")
            .context("request failed");
        assert_eq!(classify(&error), Failure::Forbidden);
        assert_eq!(observation_code(&error), "forbidden");
        assert_eq!(classify(&anyhow::anyhow!("forbidden")), Failure::Internal);
        assert_eq!(Failure::from_code("forbidden"), Some(Failure::Forbidden));
        assert_eq!(Failure::ExternalAmbiguous.category(), Category::Internal);
    }
}
