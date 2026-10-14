//! The native source of the private UI workflow contract. Apps cannot select
//! operations, download locations, tools or installation paths through this port.
//!
//! Native handlers implement the generated contract directly:
//! ```no_run
//! use day2::automation::ui::{JsonReceipt, LockHost, LockInput};
//! struct Native;
//! impl LockHost for Native {
//!     fn lock(&mut self, input: LockInput) -> anyhow::Result<JsonReceipt<day2::ui_lock::Lock>> {
//!         Ok(JsonReceipt(day2::build_dependencies::write_lock(
//!             std::path::Path::new("/platform"), std::path::Path::new(&input.source),
//!         )?))
//!     }
//! }
//! ```
//! Omitting a handler is a compiler error, rather than a default runtime refusal:
//! ```compile_fail,E0046
//! struct Native;
//! impl day2::automation::ui::LockHost for Native {}
//! ```
//! Input and result changes cannot leave a stale native implementation:
//! ```compile_fail,E0053
//! struct Native;
//! impl day2::automation::ui::LockHost for Native {
//!     fn lock(&mut self, input: String) -> anyhow::Result<day2::automation::ui::JsonReceipt<day2::ui_lock::Lock>> {
//!         unimplemented!()
//!     }
//! }
//! ```
//! ```compile_fail,E0308
//! let status = day2::automation::ui::Inspection { installed: "yes".to_owned() };
//! ```
//! ```compile_fail,E0308
//! struct Native;
//! impl day2::automation::ui::LockHost for Native {
//!     fn lock(&mut self, input: day2::automation::ui::LockInput)
//!         -> anyhow::Result<day2::automation::ui::JsonReceipt<day2::ui_lock::Lock>> {
//!         Ok("untyped result".to_owned())
//!     }
//! }
//! ```
pub use super::contract::JsonReceipt;
use crate::{workflow_host, workflow_record};

workflow_record!(Empty {});
workflow_record!(Inspection { installed: bool => "installed" });
workflow_record!(Fetched { fetched: bool => "fetched" });
workflow_record!(Extracted { extracted: bool => "extracted" });
workflow_record!(Verified { verified: bool => "verified" });
workflow_record!(Published { published: bool => "published" });
workflow_record!(LockInput { source: String => "source" });
workflow_record!(PackageIdentity {
    name: String => "name",
    version: String => "version",
    digest: String => "digest",
});
workflow_record!(ExecutableIdentity {
    path: String => "path",
    bytes: u64 => "bytes",
    digest: String => "digest",
});
workflow_record!(PresentationWorker {
    abi: u32 => "abi",
    contracts_sha256: String => "contractsSha256",
    executable: ExecutableIdentity => "executable",
});
workflow_record!(DependencyReceipt {
    provider: String => "provider",
    release: String => "release",
    target: String => "target",
    catalog_digest: String => "catalogDigest",
    manifest_digest: String => "manifestDigest",
    provider_pin_digest: String => "providerPinDigest",
    archive_digest: String => "archiveDigest",
    presentation_worker: PresentationWorker => "presentationWorker",
    input_count: u64 => "inputCount",
    package: PackageIdentity => "package",
});

workflow_host!(InstallHost, "install", install_schema, dispatch_install {
    inspect("ui-dependency-inspect", Empty) -> Inspection,
    fetch("ui-dependency-fetch", Empty) -> Fetched,
    extract("ui-dependency-extract", Empty) -> Extracted,
    verify("ui-dependency-verify", Empty) -> Verified,
    publish("ui-dependency-publish", Empty) -> Published,
    receipt("ui-dependency-receipt", Empty) -> JsonReceipt<DependencyReceipt>,
});

workflow_host!(LockHost, "lock", lock_schema, dispatch_lock {
    lock("ui-lock", LockInput) -> JsonReceipt<crate::ui_lock::Lock>,
});

pub fn roc_sources() -> Vec<(&'static str, String)> {
    super::contract::roc_sources(&[install_schema(), lock_schema()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::automation::Request;
    use anyhow::Result;
    use serde_json::json;

    struct Native {
        calls: usize,
    }

    impl LockHost for Native {
        fn lock(&mut self, input: LockInput) -> Result<JsonReceipt<crate::ui_lock::Lock>> {
            assert_eq!(input.source, "app/é");
            self.calls += 1;
            Ok(JsonReceipt(crate::ui_lock::Lock {
                schema_version: 2,
                provider: "clanker-ui.native".into(),
                package: crate::ui_lock::LockedPackage {
                    name: "@clanker/vanilla".into(),
                    version: "fixture".into(),
                    digest: crate::digest(b"fixture"),
                    inputs: vec![],
                },
            }))
        }
    }

    fn request(action: &str, input: &str) -> Request {
        Request {
            protocol: 1,
            action: action.into(),
            input: input.into(),
        }
    }

    #[test]
    fn lock_dispatch_decodes_before_effect_and_serializes_the_native_domain_receipt() -> Result<()>
    {
        let mut native = Native { calls: 0 };
        for input in [
            r#"{"source":42}"#,
            r#"{"soucre":"app"}"#,
            r#"{"source":"app","extra":true}"#,
            r#"{"source":"a","source":"b"}"#,
            "[]",
        ] {
            assert!(dispatch_lock(&mut native, &request("ui-lock", input)).is_err());
        }
        let mut incompatible = request("ui-lock", r#"{"source":"app/é"}"#);
        incompatible.protocol = 2;
        assert!(dispatch_lock(&mut native, &incompatible).is_err());
        assert!(
            dispatch_lock(&mut native, &request("ui-lcok", "{}"))
                .unwrap()
                .is_none()
        );
        assert_eq!(native.calls, 0);
        let result =
            dispatch_lock(&mut native, &request("ui-lock", r#"{"source":"app/é"}"#))?.unwrap();
        let receipt: crate::ui_lock::Lock =
            crate::json::decode(result["json"].as_str().unwrap().as_bytes())?;
        assert_eq!(receipt.schema_version, 2);
        assert_eq!(receipt.package.name, "@clanker/vanilla");
        assert_eq!(native.calls, 1);
        Ok(())
    }

    #[test]
    fn native_records_reject_wrong_and_unknown_fields() {
        assert_eq!(
            serde_json::to_value(Inspection { installed: false }).unwrap(),
            json!({"installed":false})
        );
        assert!(crate::json::decode::<Inspection>(br#"{"installed":"false"}"#).is_err());
        assert!(crate::json::decode::<Inspection>(br#"{"installed":false,"extra":true}"#).is_err());
        assert!(crate::json::decode::<Empty>(br#"{"source":"app"}"#).is_err());
        assert!(super::super::contract::decode::<Empty>(&request("empty", "[]")).is_err());
    }

    #[test]
    fn checked_in_roc_contract_and_transport_are_current() {
        for (name, generated) in roc_sources() {
            let (_, checked_in) = crate::automation::SOURCES
                .iter()
                .find(|(path, _)| *path == name)
                .unwrap();
            assert_eq!(
                *checked_in,
                generated.as_bytes(),
                "stale generated source: {name}"
            );
        }
    }
}
