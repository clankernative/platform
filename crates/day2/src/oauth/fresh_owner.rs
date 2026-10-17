//! Durable allocation DATA beside the actual owning app's Pending. The shell
//! has no database or storage locator. These rows and RPC replies cannot create
//! a live Google bundle, current enrollment, original lifetime or fresh-human proof.

use super::fresh_auth::FreshIntent;
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

const MAX_REQUEST: usize = 16 * 1024;
const MAX_OWNERS: i64 = 4096;

/// Closed public commitment DATA for one original two-phase Google bundle. It
/// contains no provider URL, code, token, private nonce/verifier or proof.
/// The actual Google owner constructs it from its selected profile and original
/// process-local two-phase bundle; a restored row cannot recreate that ownership.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GoogleBundleData {
    original: Digest,
    profile: Digest,
    bundle: Digest,
}

impl GoogleBundleData {
    pub(super) fn from_native_parts(original: Digest, profile: Digest, bundle: Digest) -> Self {
        Self {
            original,
            profile,
            bundle,
        }
    }
}

/// A closed selector for the receiver's real Pending. This is not a serialized
/// FreshIntent: the receiver constructs that only from its own current runtime.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PurposeData {
    OAuthApproval,
    CredentialIntent,
    OAuthConnect,
    OAuthDisconnect,
}

impl PurposeData {
    fn from_intent(intent: &FreshIntent) -> Self {
        match intent.purpose() {
            super::fresh_auth::FreshPurpose::OAuthApproval => Self::OAuthApproval,
            super::fresh_auth::FreshPurpose::CredentialIntent => Self::CredentialIntent,
            super::fresh_auth::FreshPurpose::OAuthConnect => Self::OAuthConnect,
            super::fresh_auth::FreshPurpose::OAuthDisconnect => Self::OAuthDisconnect,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum OperationData {
    Claim {},
    Publish { request: String },
}

impl<'de> Deserialize<'de> for OperationData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // A struct variant closes fields, but serde also accepts sequence
        // representations for internally tagged enums. Admit only an actual
        // map on raw and Value paths, preserving duplicate fields for the
        // existing tagged/deny_unknown_fields visitor rather than normalizing.
        #[derive(Deserialize)]
        #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Claim {},
            Publish { request: String },
        }

        struct ObjectOnly;
        impl<'de> serde::de::Visitor<'de> for ObjectOnly {
            type Value = OperationData;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("one closed fresh-owner operation object")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                match Wire::deserialize(serde::de::value::MapAccessDeserializer::new(map))? {
                    Wire::Claim {} => Ok(OperationData::Claim {}),
                    Wire::Publish { request } => Ok(OperationData::Publish { request }),
                }
            }
        }
        deserializer.deserialize_map(ObjectOnly)
    }
}

/// Authenticated app/shell transport DATA. No database, origin, key, account,
/// serialized intent, private verifier state or standalone consume is accepted.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CallData {
    pub(crate) purpose: PurposeData,
    pub(crate) attempt: String,
    original: Digest,
    owner: Digest,
    operation: OperationData,
}

impl CallData {
    pub(super) fn claim(intent: &FreshIntent, owner: Digest) -> Result<Self> {
        Ok(Self {
            purpose: PurposeData::from_intent(intent),
            attempt: intent.attempt().into(),
            original: intent.commitment()?,
            owner,
            operation: OperationData::Claim {},
        })
    }

    pub(super) fn publication(
        intent: &FreshIntent,
        owner: Digest,
        request: String,
    ) -> Result<Self> {
        ensure!(
            request.len() <= MAX_REQUEST,
            "native fresh public options capacity"
        );
        let mut call = Self::claim(intent, owner)?;
        call.operation = OperationData::Publish { request };
        Ok(call)
    }

    fn digest(&self) -> Result<Digest> {
        Digest::of(&("native-fresh-owner-call-v1", self))
    }

    pub(super) fn require_intent(&self, intent: &FreshIntent) -> Result<()> {
        ensure!(
            self.attempt == intent.attempt()
                && self.purpose == PurposeData::from_intent(intent)
                && self.original == intent.commitment()?,
            "native fresh original pending changed"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum OutcomeData {
    Allocation { state: AllocationData },
    Published { request: Digest },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReplyData {
    call: Digest,
    original: Digest,
    expires_at: i64,
    pub(super) outcome: OutcomeData,
}

impl ReplyData {
    pub(super) fn require_call(&self, call: &CallData, intent: &FreshIntent) -> Result<()> {
        call.require_intent(intent)?;
        ensure!(
            self.call == call.digest()?
                && self.original == intent.commitment()?
                && self.expires_at == intent.deadline(),
            "native fresh owner reply changed"
        );
        match (&call.operation, &self.outcome) {
            (OperationData::Claim {}, OutcomeData::Allocation { .. }) => {}
            (OperationData::Publish { request }, OutcomeData::Published { request: digest }) => {
                ensure!(
                    *digest == Digest::new(request.as_bytes()),
                    "native fresh publication reply changed"
                );
            }
            _ => anyhow::bail!("native fresh owner operation changed"),
        }
        Ok(())
    }
}

/// The actual owning host has resolved its current Pending and authority in
/// this writer. It commits this DATA change before returning the RPC reply.
/// There is deliberately no public consume RPC or proof factory here.
pub(crate) fn apply_in_current_app_transaction(
    db: &Connection,
    intent: &FreshIntent,
    call: &CallData,
    now: i64,
) -> Result<ReplyData> {
    call.require_intent(intent)?;
    let outcome = match &call.operation {
        OperationData::Claim {} => OutcomeData::Allocation {
            state: claim(db, intent, &call.owner, now)?,
        },
        OperationData::Publish { request } => OutcomeData::Published {
            request: publish(db, intent, &call.owner, request.as_bytes(), now)?,
        },
    };
    Ok(ReplyData {
        call: call.digest()?,
        original: intent.commitment()?,
        expires_at: intent.deadline(),
        outcome,
    })
}

const SCHEMA: &str = r#"
        CREATE TABLE IF NOT EXISTS native_fresh_schema_version(version INTEGER PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS native_fresh_owners (
            original TEXT PRIMARY KEY NOT NULL CHECK(length(original)=71 AND substr(original,1,7)='sha256:'
                AND substr(original,8) NOT GLOB '*[^0-9a-f]*'),
            attempt TEXT NOT NULL CHECK(length(attempt) BETWEEN 1 AND 256),
            purpose TEXT NOT NULL CHECK(purpose IN ('OAuthApproval','CredentialIntent','OAuthConnect','OAuthDisconnect')),
            human TEXT NOT NULL CHECK(length(human) BETWEEN 1 AND 320),
            subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 256),
            context TEXT NOT NULL CHECK(length(context) BETWEEN 1 AND 32768 AND json_valid(context)
                AND COALESCE(json_type(context)='object'
                    AND json_extract(context,'$.attempt')=attempt
                    AND json_extract(context,'$.human')=human
                    AND json_extract(context,'$.subject')=subject
                    AND json_extract(context,'$.created_at')=created_at
                    AND json_type(context,'$.challenge')='text'
                    AND length(json_extract(context,'$.challenge'))=71
                    AND CASE purpose
                        WHEN 'OAuthApproval' THEN json_extract(context,'$.context.OAuth.expires_at')
                        WHEN 'CredentialIntent' THEN json_extract(context,'$.context.Credential.expires_at')
                        WHEN 'OAuthConnect' THEN CASE WHEN json_extract(context,'$.context.Management.action')='connect'
                            THEN json_extract(context,'$.context.Management.expires_at') END
                        WHEN 'OAuthDisconnect' THEN CASE WHEN json_extract(context,'$.context.Management.action')='disconnect'
                            THEN json_extract(context,'$.context.Management.expires_at') END
                        END = expires_at,0)),
            owner TEXT NOT NULL CHECK(length(owner)=71 AND substr(owner,1,7)='sha256:'
                AND substr(owner,8) NOT GLOB '*[^0-9a-f]*'),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
            stage TEXT NOT NULL CHECK(stage IN ('allocated','offered','consumed','refused')),
            request TEXT,
            request_digest TEXT,
            result_digest TEXT,
            CHECK(request IS NULL OR (length(request) BETWEEN 1 AND 16384 AND json_valid(request)
                AND COALESCE(json_type(request)='object'
                    AND json_remove(request,'$.original','$.profile','$.bundle')='{}'
                    AND json_extract(request,'$.original')=original
                    AND json_type(request,'$.profile')='text'
                    AND length(json_extract(request,'$.profile'))=71
                    AND substr(json_extract(request,'$.profile'),1,7)='sha256:'
                    AND substr(json_extract(request,'$.profile'),8) NOT GLOB '*[^0-9a-f]*'
                    AND json_type(request,'$.bundle')='text'
                    AND length(json_extract(request,'$.bundle'))=71
                    AND substr(json_extract(request,'$.bundle'),1,7)='sha256:'
                    AND substr(json_extract(request,'$.bundle'),8) NOT GLOB '*[^0-9a-f]*',0))),
            CHECK(request_digest IS NULL OR (length(request_digest)=71 AND substr(request_digest,1,7)='sha256:'
                AND substr(request_digest,8) NOT GLOB '*[^0-9a-f]*')),
            CHECK(result_digest IS NULL OR (length(result_digest)=71 AND substr(result_digest,1,7)='sha256:'
                AND substr(result_digest,8) NOT GLOB '*[^0-9a-f]*')),
            CHECK((stage='allocated' AND request IS NULL AND request_digest IS NULL AND result_digest IS NULL)
               OR (stage='offered' AND request IS NOT NULL AND request_digest IS NOT NULL AND result_digest IS NULL)
               OR (stage='consumed' AND request IS NOT NULL AND request_digest IS NOT NULL AND result_digest IS NOT NULL)
               OR (stage='refused' AND result_digest IS NULL
                    AND ((request IS NULL AND request_digest IS NULL)
                      OR (request IS NOT NULL AND request_digest IS NOT NULL)))),
            UNIQUE(attempt,purpose)
        ) STRICT;
        CREATE TRIGGER IF NOT EXISTS native_fresh_owner_original_immutable
        BEFORE UPDATE OF original,attempt,purpose,human,subject,context,owner,created_at,expires_at ON native_fresh_owners
        BEGIN SELECT RAISE(ABORT,'native fresh original immutable'); END;
        CREATE TRIGGER IF NOT EXISTS native_fresh_owner_no_delete BEFORE DELETE ON native_fresh_owners
        BEGIN SELECT RAISE(ABORT,'native fresh owner tombstone required'); END;
        CREATE TRIGGER IF NOT EXISTS native_fresh_owner_forward_only BEFORE UPDATE OF stage ON native_fresh_owners
        WHEN NOT ((OLD.stage='allocated' AND NEW.stage IN ('offered','refused'))
               OR (OLD.stage='offered' AND NEW.stage IN ('consumed','refused')))
        BEGIN SELECT RAISE(ABORT,'native fresh stage regression'); END;
        CREATE TRIGGER IF NOT EXISTS native_fresh_owner_publication_immutable
        BEFORE UPDATE OF request,request_digest ON native_fresh_owners WHEN OLD.stage != 'allocated'
        BEGIN SELECT RAISE(ABORT,'native fresh publication immutable'); END;
        CREATE TRIGGER IF NOT EXISTS native_fresh_owner_result_immutable
        BEFORE UPDATE OF result_digest ON native_fresh_owners WHEN OLD.stage != 'offered'
        BEGIN SELECT RAISE(ABORT,'native fresh result immutable'); END;
    "#;

#[cfg(test)]
type SchemaRow = (String, String, String, Option<String>);

#[cfg(test)]
fn schema_rows(db: &Connection) -> Result<Vec<SchemaRow>> {
    let mut statement = db.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_master
         WHERE tbl_name='native_fresh_owners' OR name GLOB 'native_fresh_*'
         ORDER BY type,name",
    )?;
    Ok(statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    // Use the same cumulative bounded admission and exact-layout validation as
    // all other identity units. Existing unknown/restored units are not repaired.
    super::schema::install_current(db, "native_fresh_schema_version", 1, SCHEMA,
        &[super::schema::Invariant { table: "native_fresh_owners", predicate:
            "length(original)=71 AND substr(original,1,7)='sha256:' AND substr(original,8) NOT GLOB '*[^0-9a-f]*'
             AND length(attempt) BETWEEN 1 AND 256
             AND purpose IN ('OAuthApproval','CredentialIntent','OAuthConnect','OAuthDisconnect')
             AND length(human) BETWEEN 1 AND 320 AND length(subject) BETWEEN 1 AND 256
             AND length(context) BETWEEN 1 AND 32768 AND json_valid(context) AND json_type(context)='object'
             AND json_extract(context,'$.attempt')=attempt AND json_extract(context,'$.human')=human
             AND json_extract(context,'$.subject')=subject AND json_extract(context,'$.created_at')=created_at
             AND json_type(context,'$.challenge')='text' AND length(json_extract(context,'$.challenge'))=71
             AND CASE purpose
                 WHEN 'OAuthApproval' THEN json_extract(context,'$.context.OAuth.expires_at')
                 WHEN 'CredentialIntent' THEN json_extract(context,'$.context.Credential.expires_at')
                 WHEN 'OAuthConnect' THEN CASE WHEN json_extract(context,'$.context.Management.action')='connect'
                     THEN json_extract(context,'$.context.Management.expires_at') END
                 WHEN 'OAuthDisconnect' THEN CASE WHEN json_extract(context,'$.context.Management.action')='disconnect'
                     THEN json_extract(context,'$.context.Management.expires_at') END
                 END = expires_at
             AND length(owner)=71 AND substr(owner,1,7)='sha256:' AND substr(owner,8) NOT GLOB '*[^0-9a-f]*'
             AND created_at>=0 AND expires_at>created_at
             AND (request IS NULL OR (length(request) BETWEEN 1 AND 16384 AND json_valid(request)
                  AND (SELECT count(*) FROM json_each(request))=3
                  AND json_type(request)='object' AND json_remove(request,'$.original','$.profile','$.bundle')='{}'
                  AND json_extract(request,'$.original')=original
                  AND json_type(request,'$.profile')='text' AND length(json_extract(request,'$.profile'))=71
                  AND substr(json_extract(request,'$.profile'),1,7)='sha256:'
                  AND substr(json_extract(request,'$.profile'),8) NOT GLOB '*[^0-9a-f]*'
                  AND json_type(request,'$.bundle')='text' AND length(json_extract(request,'$.bundle'))=71
                  AND substr(json_extract(request,'$.bundle'),1,7)='sha256:'
                  AND substr(json_extract(request,'$.bundle'),8) NOT GLOB '*[^0-9a-f]*'))
             AND (request_digest IS NULL OR (length(request_digest)=71 AND substr(request_digest,1,7)='sha256:'
                  AND substr(request_digest,8) NOT GLOB '*[^0-9a-f]*'))
             AND (result_digest IS NULL OR (length(result_digest)=71 AND substr(result_digest,1,7)='sha256:'
                  AND substr(result_digest,8) NOT GLOB '*[^0-9a-f]*'))
             AND ((stage='allocated' AND request IS NULL AND request_digest IS NULL AND result_digest IS NULL)
               OR (stage='offered' AND request IS NOT NULL AND request_digest IS NOT NULL AND result_digest IS NULL)
               OR (stage='consumed' AND request IS NOT NULL AND request_digest IS NOT NULL AND result_digest IS NOT NULL)
               OR (stage='refused' AND result_digest IS NULL
                    AND ((request IS NULL AND request_digest IS NULL)
                      OR (request IS NOT NULL AND request_digest IS NOT NULL))))" }])
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum AllocationData {
    Allocated,
    ExistingOwner,
    OtherOwner,
    ConsumedHistory { result: Digest },
    Refused,
}

/// The caller resolves the actual current Pending in the SAME app-owned
/// transaction before calling this. No browser chooses a database or owner.
/// A repeated/lost request reconciles only this original row, never a new nonce.
pub(super) fn claim(
    db: &Connection,
    intent: &FreshIntent,
    owner: &Digest,
    now: i64,
) -> Result<AllocationData> {
    ensure!(
        !db.is_autocommit(),
        "native fresh original app transaction required"
    );
    let deadline = intent.deadline();
    ensure!(
        now >= intent.created_at() && now < deadline,
        "original fresh pending expired"
    );
    let original = intent.commitment()?;
    let context = serde_json::to_string(intent)?;
    ensure!(
        context.len() <= 32768,
        "native fresh original context budget"
    );
    let existing: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM native_fresh_owners WHERE original=?1)",
        [original.as_str()],
        |row| row.get(0),
    )?;
    if !existing {
        let count: i64 = db.query_row("SELECT count(*) FROM native_fresh_owners", [], |row| {
            row.get(0)
        })?;
        ensure!(count < MAX_OWNERS, "native fresh original owner capacity");
    }
    let changed = db.execute(
        "INSERT INTO native_fresh_owners(original,attempt,purpose,human,subject,context,owner,created_at,expires_at,stage)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'allocated') ON CONFLICT DO NOTHING",
        params![original.as_str(),intent.attempt(),serde_json::to_string(&intent.purpose())?.trim_matches('"'),
            intent.human(),intent.subject(),context,owner.as_str(),intent.created_at(),deadline],
    )?;
    if changed == 1 {
        return Ok(AllocationData::Allocated);
    }
    let row: Option<(String, String, String, Option<String>)> = db
        .query_row(
            "SELECT context,owner,stage,result_digest FROM native_fresh_owners WHERE original=?1",
            [original.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let (saved, saved_owner, stage, result) =
        row.context("native fresh attempt purpose already bound")?;
    ensure!(saved == context, "native fresh original context changed");
    if saved_owner != owner.as_str() {
        return Ok(AllocationData::OtherOwner);
    }
    if stage == "consumed" {
        return Ok(AllocationData::ConsumedHistory {
            result: Digest::try_from(result.context("native fresh result missing")?)?,
        });
    }
    if stage == "refused" {
        return Ok(AllocationData::Refused);
    }
    Ok(AllocationData::ExistingOwner)
}

/// Commit publication only after the shell retains the one matching two-phase
/// bundle in its original process. Commitments are DATA; no private state crosses.
pub(super) fn publish(
    db: &Connection,
    intent: &FreshIntent,
    owner: &Digest,
    request: &[u8],
    now: i64,
) -> Result<Digest> {
    ensure!(
        !db.is_autocommit(),
        "native fresh original app transaction required"
    );
    ensure!(
        request.len() <= MAX_REQUEST,
        "native fresh public options capacity"
    );
    let publication: GoogleBundleData = crate::json::decode(request)?;
    ensure!(
        publication.original == intent.commitment()?,
        "Google publication original changed"
    );
    let deadline = intent.deadline();
    ensure!(
        now >= intent.created_at() && now < deadline,
        "original fresh pending expired"
    );
    let digest = Digest::new(request);
    let changed = db.execute(
        "UPDATE native_fresh_owners SET stage='offered',request=?3,request_digest=?4
         WHERE original=?1 AND owner=?2 AND context=?5 AND stage='allocated' AND expires_at>?6",
        params![
            intent.commitment()?.as_str(),
            owner.as_str(),
            std::str::from_utf8(request)?,
            digest.as_str(),
            serde_json::to_string(intent)?,
            now
        ],
    )?;
    if changed != 1 {
        let saved: Option<(String, String)> = db
            .query_row(
                "SELECT request_digest,request FROM native_fresh_owners
             WHERE original=?1 AND owner=?2 AND context=?3 AND stage='offered' AND expires_at>?4",
                params![
                    intent.commitment()?.as_str(),
                    owner.as_str(),
                    serde_json::to_string(intent)?,
                    now
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        ensure!(
            saved == Some((digest.as_str().into(), std::str::from_utf8(request)?.into())),
            "native fresh publication cannot renew or change"
        );
    }
    Ok(digest)
}

/// This is only one statement of the final app transaction. Its caller must
/// re-resolve the actual original Pending/current authority and perform the
/// current enrollment/key/counter revision CAS in that same native writer.
/// No standalone RPC or restored row can turn this DATA transition into proof.
pub(super) fn consume_in_current_app_transaction(
    db: &Connection,
    intent: &FreshIntent,
    owner: &Digest,
    request: &Digest,
    result: &Digest,
    now: i64,
) -> Result<()> {
    ensure!(
        !db.is_autocommit(),
        "native fresh final app transaction required"
    );
    ensure!(
        now >= intent.created_at() && now < intent.deadline(),
        "original fresh pending expired"
    );
    ensure!(db.execute(
        "UPDATE native_fresh_owners SET stage='consumed',result_digest=?4
         WHERE original=?1 AND owner=?2 AND request_digest=?3 AND context=?5 AND stage='offered' AND expires_at>?6",
        params![intent.commitment()?.as_str(),owner.as_str(),request.as_str(),result.as_str(),serde_json::to_string(intent)?,now],
    )? == 1, "native fresh result already consumed or changed");
    Ok(())
}

/// Exact-owner terminal history only. The authenticated receiver supplies the
/// original retained intent and enforces its NEW request observation budget.
/// This does not renew the expired operation or reconstruct a native proof.
pub(super) fn terminal_history(
    db: &Connection,
    intent: &FreshIntent,
    owner: &Digest,
) -> Result<Option<Digest>> {
    let value: Option<String> = db
        .query_row(
            "SELECT result_digest FROM native_fresh_owners
         WHERE original=?1 AND owner=?2 AND context=?3 AND stage='consumed'",
            params![
                intent.commitment()?.as_str(),
                owner.as_str(),
                serde_json::to_string(intent)?
            ],
            |row| row.get(0),
        )
        .optional()?;
    value.map(Digest::try_from).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iap;
    use rusqlite::TransactionBehavior;

    fn intent() -> Result<FreshIntent> {
        FreshIntent::fixture_oauth(
            &iap::Verified {
                email: "alice@example.com".into(),
                subject: "google:alice".into(),
            },
            "original",
            &Digest::new(b"original complete pending challenge"),
            "https://security.example.com/",
            0,
            300,
        )
    }

    fn options() -> Vec<u8> {
        serde_json::to_vec(&GoogleBundleData {
            original: intent().unwrap().commitment().unwrap(),
            profile: Digest::new(b"selected Google profile fixture DATA"),
            bundle: Digest::new(b"one original Google two-tuple bundle fixture DATA"),
        })
        .unwrap()
    }

    #[test]
    fn claim_operation_has_one_closed_object_wire_in_raw_and_value_decoders() -> Result<()> {
        let claim = CallData::claim(&intent()?, Digest::new(b"closed claim owner"))?;
        let valid = serde_json::to_value(&claim)?;
        assert_eq!(valid["operation"], serde_json::json!({"operation":"claim"}));
        let decoded: CallData = crate::json::decode(&serde_json::to_vec(&valid)?)?;
        assert_eq!(serde_json::to_value(decoded)?, valid);
        let decoded: CallData = serde_json::from_value(valid.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, valid);
        for operation in [
            serde_json::json!({"operation":"claim","database":"/tmp/ignored-is-not-closed"}),
            serde_json::json!({"operation":"claim","actor":"another@example.com"}),
            serde_json::json!(["claim"]),
            serde_json::json!(["claim", {}]),
        ] {
            let mut changed = valid.clone();
            changed["operation"] = operation;
            assert!(crate::json::decode::<CallData>(&serde_json::to_vec(&changed)?).is_err());
            assert!(serde_json::from_value::<CallData>(changed).is_err());
        }
        let duplicate = serde_json::to_string(&valid)?.replace(
            "\"operation\":\"claim\"",
            "\"operation\":\"claim\",\"operation\":\"claim\"",
        );
        assert!(crate::json::decode::<CallData>(duplicate.as_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn lost_claim_and_second_shell_cannot_replace_the_original_allocation() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        install(&db)?;
        let intent = intent()?;
        let first = Digest::new(b"first actual shell incarnation");
        let other = Digest::new(b"different actual shell incarnation");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(matches!(
            claim(&tx, &intent, &first, 1)?,
            AllocationData::Allocated
        ));
        tx.commit()?;
        // Response loss: the same owner gets history, not another allocation.
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(matches!(
            claim(&tx, &intent, &first, 2)?,
            AllocationData::ExistingOwner
        ));
        assert!(matches!(
            claim(&tx, &intent, &other, 2)?,
            AllocationData::OtherOwner
        ));
        tx.commit()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM native_fresh_owners", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        assert!(claim(&db, &intent, &first, 2).is_err());
        Ok(())
    }

    #[test]
    fn original_and_stage_claims_are_enforced_by_actual_sqlite() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        install(&db)?;
        let intent = intent()?;
        let owner = Digest::new(b"one original owner");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        claim(&tx, &intent, &owner, 1)?;
        tx.commit()?;
        for sql in [
            "UPDATE native_fresh_owners SET owner='sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'",
            "UPDATE native_fresh_owners SET expires_at=900",
            "UPDATE native_fresh_owners SET stage='consumed'",
            "DELETE FROM native_fresh_owners",
        ] {
            assert!(db.execute(sql, []).is_err(), "{sql}");
        }
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request = publish(&tx, &intent, &owner, &options(), 2)?;
        tx.commit()?;
        assert!(
            db.execute(
                "UPDATE native_fresh_owners SET stage='allocated',request=NULL,request_digest=NULL",
                []
            )
            .is_err()
        );
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_eq!(publish(&tx, &intent, &owner, &options(), 3)?, request);
        let mut changed = options();
        changed.push(b' ');
        assert!(publish(&tx, &intent, &owner, &changed, 3).is_err());
        tx.commit()?;
        Ok(())
    }

    #[test]
    fn one_result_terminal_history_is_not_a_post_expiry_regrant() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        install(&db)?;
        let intent = intent()?;
        let owner = Digest::new(b"original owner");
        let other = Digest::new(b"new process cannot adopt old owner");
        let result = Digest::new(b"actual verified result commitment DATA");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        claim(&tx, &intent, &owner, 1)?;
        let request = publish(&tx, &intent, &owner, &options(), 2)?;
        consume_in_current_app_transaction(&tx, &intent, &owner, &request, &result, 3)?;
        assert!(
            consume_in_current_app_transaction(&tx, &intent, &owner, &request, &result, 3).is_err()
        );
        tx.commit()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(claim(&tx, &intent, &owner, 300).is_err());
        tx.commit()?;
        assert_eq!(terminal_history(&db, &intent, &owner)?, Some(result));
        assert_eq!(terminal_history(&db, &intent, &other)?, None);
        Ok(())
    }

    #[test]
    fn publication_wire_and_actual_sqlite_refuse_hidden_or_unbound_fields() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        install(&db)?;
        let intent = intent()?;
        let owner = Digest::new(b"one Google owner");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        claim(&tx, &intent, &owner, 1)?;
        tx.commit()?;
        let valid = String::from_utf8(options())?;
        let mut extra: serde_json::Value = crate::json::decode(valid.as_bytes())?;
        extra["url"] = serde_json::json!("https://browser-selected.example/");
        let mut null: serde_json::Value = crate::json::decode(valid.as_bytes())?;
        null["profile"] = serde_json::Value::Null;
        let mut foreign: serde_json::Value = crate::json::decode(valid.as_bytes())?;
        foreign["original"] = serde_json::json!(Digest::new(b"different original pending"));
        let duplicate = format!(
            "{},\"profile\":\"{}\"}}",
            valid.strip_suffix('}').unwrap(),
            Digest::new(b"second hidden profile").as_str()
        );
        for request in [
            serde_json::to_string(&extra)?,
            serde_json::to_string(&null)?,
            serde_json::to_string(&foreign)?,
            duplicate,
        ] {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert!(publish(&tx, &intent, &owner, request.as_bytes(), 2).is_err());
            tx.commit()?;
            // Independently exercise the durable schema; bypassing the Rust
            // decoder cannot persist a hidden field or another original.
            assert!(db.execute(
                "UPDATE native_fresh_owners SET stage='offered',request=?1,request_digest=?2 WHERE original=?3",
                params![request, Digest::new(request.as_bytes()).as_str(), intent.commitment()?.as_str()],
            ).is_err());
            let stage: String =
                db.query_row("SELECT stage FROM native_fresh_owners", [], |row| {
                    row.get(0)
                })?;
            assert_eq!(stage, "allocated");
        }
        Ok(())
    }

    #[test]
    fn unknown_existing_schema_refuses_without_repair() -> Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE native_fresh_owners(untrusted TEXT); INSERT INTO native_fresh_owners VALUES('preserve');")?;
        let before = schema_rows(&db)?;
        assert!(install(&db).is_err());
        assert_eq!(schema_rows(&db)?, before);
        assert_eq!(
            db.query_row("SELECT untrusted FROM native_fresh_owners", [], |row| {
                row.get::<_, String>(0)
            })?,
            "preserve"
        );
        Ok(())
    }
}
