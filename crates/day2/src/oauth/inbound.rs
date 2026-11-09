//! Inbound OAuth issuance state. Raw codes and tokens never enter these tables:
//! only purpose-specific hashes, immutable ceilings and redacted receipts do.

use anyhow::{Result, ensure};
use base64::Engine as _;
use day2_capabilities::oauth::{
    ClientChannelContract, GrantCeiling, OAuthClientRedirectRef, OperationAuthorityContract,
    ResourceAudienceRef,
};
use day2_capabilities::{BindingRef, Digest};
use ring::digest::{SHA256, digest};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct CredentialHashes {
    access: AccessTokenHash,
    refresh: RefreshTokenHash,
}

impl CredentialHashes {
    pub fn from_secrets(access: &[u8], refresh: &[u8]) -> Result<Self> {
        ensure!(access != refresh, "access and refresh secrets must differ");
        Ok(Self {
            access: AccessTokenHash::from_secret(access)?,
            refresh: RefreshTokenHash::from_secret(refresh)?,
        })
    }

    pub fn access(&self) -> &AccessTokenHash {
        &self.access
    }

    pub fn refresh(&self) -> &RefreshTokenHash {
        &self.refresh
    }
}

macro_rules! purpose_hash {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name(Digest);

        impl $name {
            pub fn from_secret(secret: &[u8]) -> Result<Self> {
                ensure!(
                    (32..=512).contains(&secret.len()),
                    "invalid OAuth secret length"
                );
                Ok(Self(Digest::of(&($domain, secret))?))
            }

            fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}

purpose_hash!(AuthorizationCodeHash, "oauth-inbound-code-v1");
purpose_hash!(AccessTokenHash, "oauth-inbound-access-v1");
purpose_hash!(RefreshTokenHash, "oauth-inbound-refresh-v1");

pub struct CodeOffer {
    pub code_hash: AuthorizationCodeHash,
    pub grant_id: String,
    pub client: BindingRef,
    pub redirect: OAuthClientRedirectRef,
    pub pkce_challenge: String,
    pub audience: ResourceAudienceRef,
    pub expires_at: i64,
    pub now: i64,
}

pub struct CodeRedemption {
    pub code_hash: AuthorizationCodeHash,
    pub client: BindingRef,
    pub redirect: OAuthClientRedirectRef,
    pub pkce_verifier: String,
    pub audience: ResourceAudienceRef,
    pub hashes: CredentialHashes,
    pub family: String,
    pub receipt: String,
    pub access_expires_at: i64,
    pub now: i64,
}

pub struct RefreshExchange {
    pub old_hash: RefreshTokenHash,
    pub client: BindingRef,
    pub requested_roots: BTreeSet<String>,
    pub hashes: CredentialHashes,
    pub access_expires_at: i64,
    pub now: i64,
}

pub fn install_schema(db: &Connection) -> Result<()> {
    super::schema::admit(db, install_schema_in)
}

fn install_schema_in(db: &Connection) -> Result<()> {
    super::restore::install(db)?;
    let ddl = "PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS oauth_inbound_schema_version (
            version INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS oauth_inbound_grants (
            id TEXT PRIMARY KEY,
            ceiling TEXT NOT NULL,
            digest TEXT NOT NULL,
            epoch INTEGER NOT NULL CHECK(epoch > 0),
            status TEXT NOT NULL CHECK(status IN ('active', 'revoked'))
        );
        CREATE TABLE IF NOT EXISTS oauth_inbound_codes (
            code_hash TEXT PRIMARY KEY,
            grant_id TEXT NOT NULL REFERENCES oauth_inbound_grants(id),
            client TEXT NOT NULL,
            redirect TEXT NOT NULL,
            pkce_challenge TEXT NOT NULL,
            audience TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('ready', 'consumed')),
            receipt TEXT,
            CHECK((state = 'consumed') = (receipt IS NOT NULL))
        );
        CREATE TABLE IF NOT EXISTS oauth_inbound_refresh (
            token_hash TEXT PRIMARY KEY,
            family TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation > 0),
            grant_id TEXT NOT NULL REFERENCES oauth_inbound_grants(id),
            grant_epoch INTEGER NOT NULL,
            roots TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('active', 'consumed', 'revoked')),
            successor TEXT,
            CHECK((state = 'consumed') = (successor IS NOT NULL)),
            UNIQUE(family, generation)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS oauth_one_active_refresh_per_family
            ON oauth_inbound_refresh(family) WHERE state = 'active';
        CREATE TABLE IF NOT EXISTS oauth_inbound_access (
            token_hash TEXT PRIMARY KEY,
            grant_id TEXT NOT NULL REFERENCES oauth_inbound_grants(id),
            grant_epoch INTEGER NOT NULL,
            roots TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );";
    super::schema::install_current(db, "oauth_inbound_schema_version", 2, ddl, &[
        super::schema::Invariant { table: "oauth_inbound_grants", predicate:
            "length(id) > 0 AND length(ceiling) > 0 AND length(digest) > 0 AND epoch > 0 AND status IN ('active', 'revoked')" },
        super::schema::Invariant { table: "oauth_inbound_codes", predicate:
            "length(code_hash) > 0 AND length(grant_id) > 0 AND length(client) > 0 AND length(redirect) > 0 AND
             length(pkce_challenge) = 43 AND length(audience) > 0 AND state IN ('ready', 'consumed') AND
             (state = 'consumed') = (receipt IS NOT NULL) AND (receipt IS NULL OR length(receipt) > 0)" },
        super::schema::Invariant { table: "oauth_inbound_refresh", predicate:
            "length(token_hash) > 0 AND length(family) > 0 AND generation > 0 AND length(grant_id) > 0 AND grant_epoch > 0 AND
             length(roots) > 0 AND state IN ('active', 'consumed', 'revoked') AND
             (state = 'consumed') = (successor IS NOT NULL) AND (successor IS NULL OR (length(successor) > 0 AND successor != token_hash))" },
        super::schema::Invariant { table: "oauth_inbound_access", predicate:
            "length(token_hash) > 0 AND length(grant_id) > 0 AND grant_epoch > 0 AND length(roots) > 0" },
    ])
}

/// The security shell has already obtained exact interactive consent. This
/// store persists that ceiling without a mutable list of operation names.
pub fn record_grant(db: &Connection, id: &str, ceiling: &GrantCeiling, epoch: i64) -> Result<bool> {
    super::restore::require_open(db, super::restore::Kind::Inbound, id)?;
    identifier(id)?;
    ceiling.verify()?;
    ensure!(epoch > 0, "invalid grant epoch");
    Ok(db.execute(
        "INSERT OR IGNORE INTO oauth_inbound_grants VALUES (?1, ?2, ?3, ?4, 'active')",
        params![
            id,
            serde_json::to_string(ceiling)?,
            ceiling.digest.as_str(),
            epoch
        ],
    )? == 1)
}

/// A code binds one client revision, exact redirect, S256 challenge and audience.
/// A registered client alone has no grant: `grant_id` must already be active.
pub fn issue_code(
    db: &mut dyn crate::write_queue::ConnectionOwner,
    offer: CodeOffer,
) -> Result<bool> {
    let CodeOffer {
        code_hash,
        grant_id,
        client,
        redirect,
        pkce_challenge,
        audience,
        expires_at,
        now,
    } = offer;
    identifier(&grant_id)?;
    pkce(&pkce_challenge)?;
    ensure!(
        expires_at
            .checked_sub(now)
            .is_some_and(|ttl| ttl > 0 && ttl <= 600),
        "invalid authorization-code lifetime"
    );
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let ceiling = active_grant(&tx, &grant_id)?;
    if !ceiling.is_some_and(|(ceiling, _)| ceiling.client == client && ceiling.audience == audience)
    {
        return Ok(false);
    }
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO oauth_inbound_codes
         (code_hash, grant_id, client, redirect, pkce_challenge, audience, expires_at, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'ready')",
        params![
            code_hash.as_str(),
            grant_id,
            serde_json::to_string(&client)?,
            serde_json::to_string(&redirect)?,
            pkce_challenge,
            serde_json::to_string(&audience)?,
            expires_at
        ],
    )?;
    tx.commit()?;
    Ok(inserted == 1)
}

/// Redemption consumes the code and creates one credential family and access
/// record in the same transaction as the private custody write. A lost response
/// cannot redeem that code again.
pub fn redeem_code(
    db: &mut dyn crate::write_queue::ConnectionOwner,
    redemption: CodeRedemption,
    custody_write: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    let CodeRedemption {
        code_hash,
        client,
        redirect,
        pkce_verifier,
        audience,
        hashes,
        family,
        receipt,
        access_expires_at,
        now,
    } = redemption;
    identifier(&family)?;
    identifier(&receipt)?;
    let expected_challenge = challenge_for_verifier(&pkce_verifier)?;
    ensure!(
        access_expires_at
            .checked_sub(now)
            .is_some_and(|ttl| ttl > 0 && ttl <= 3600),
        "invalid access-token lifetime"
    );
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(String, String, String, String, String, i64, String)> = tx
        .query_row(
            "SELECT grant_id, client, redirect, pkce_challenge, audience, expires_at, state
         FROM oauth_inbound_codes WHERE code_hash = ?1",
            [code_hash.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((grant_id, stored_client, stored_redirect, challenge, resource, expiry, state)) = row
    else {
        return Ok(false);
    };
    if state != "ready"
        || now >= expiry
        || stored_client != serde_json::to_string(&client)?
        || stored_redirect != serde_json::to_string(&redirect)?
        || challenge != expected_challenge
        || resource != serde_json::to_string(&audience)?
    {
        return Ok(false);
    }
    let Some((ceiling, epoch)) = active_grant(&tx, &grant_id)? else {
        return Ok(false);
    };
    if ceiling.client != client || ceiling.audience != audience {
        return Ok(false);
    }
    let roots = ceiling.roots.keys().cloned().collect::<BTreeSet<_>>();
    custody_write(&tx)?;
    tx.execute(
        "UPDATE oauth_inbound_codes SET state = 'consumed', receipt = ?2
        WHERE code_hash = ?1 AND state = 'ready'",
        params![code_hash.as_str(), receipt],
    )?;
    tx.execute(
        "INSERT INTO oauth_inbound_refresh VALUES (?1, ?2, 1, ?3, ?4, ?5, 'active', NULL)",
        params![
            hashes.refresh.as_str(),
            family,
            grant_id,
            epoch,
            serde_json::to_string(&roots)?
        ],
    )?;
    tx.execute(
        "INSERT INTO oauth_inbound_access VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            hashes.access.as_str(),
            grant_id,
            epoch,
            serde_json::to_string(&roots)?,
            access_expires_at
        ],
    )?;
    tx.commit()?;
    Ok(true)
}

/// A rotating refresh token is consumed once. The requested roots may only
/// narrow the previous token's roots and remain inside the immutable grant.
pub fn refresh(
    db: &mut dyn crate::write_queue::ConnectionOwner,
    exchange: RefreshExchange,
    custody_write: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    let RefreshExchange {
        old_hash,
        client,
        requested_roots,
        hashes,
        access_expires_at,
        now,
    } = exchange;
    ensure!(!requested_roots.is_empty(), "empty refresh root selection");
    ensure!(
        access_expires_at
            .checked_sub(now)
            .is_some_and(|ttl| ttl > 0 && ttl <= 3600),
        "invalid access-token lifetime"
    );
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(String, i64, String, i64, String, String)> = tx
        .query_row(
            "SELECT family, generation, grant_id, grant_epoch, roots, state
         FROM oauth_inbound_refresh WHERE token_hash = ?1",
            [old_hash.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((family, generation, grant_id, grant_epoch, roots_json, state)) = row else {
        return Ok(false);
    };
    let old_roots: BTreeSet<String> = serde_json::from_str(&roots_json)?;
    let Some((ceiling, current_epoch)) = active_grant(&tx, &grant_id)? else {
        return Ok(false);
    };
    if current_epoch != grant_epoch || ceiling.client != client {
        return Ok(false);
    }
    if state == "consumed" {
        // Initial profile policy: a replayed rotating token disables the
        // remaining refresh family. Existing access tokens still expire normally.
        tx.execute(
            "UPDATE oauth_inbound_refresh SET state = 'revoked'
            WHERE family = ?1 AND state = 'active'",
            [&family],
        )?;
        tx.commit()?;
        return Ok(false);
    }
    if state != "active"
        || !requested_roots.is_subset(&old_roots)
        || !requested_roots
            .iter()
            .all(|root| ceiling.roots.contains_key(root))
    {
        return Ok(false);
    }
    let next_generation = generation
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("refresh generation overflow"))?;
    custody_write(&tx)?;
    tx.execute(
        "UPDATE oauth_inbound_refresh SET state = 'consumed', successor = ?2
        WHERE token_hash = ?1 AND state = 'active'",
        params![old_hash.as_str(), hashes.refresh.as_str()],
    )?;
    tx.execute(
        "INSERT INTO oauth_inbound_refresh VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', NULL)",
        params![
            hashes.refresh.as_str(),
            family,
            next_generation,
            grant_id,
            grant_epoch,
            serde_json::to_string(&requested_roots)?
        ],
    )?;
    tx.execute(
        "INSERT INTO oauth_inbound_access VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            hashes.access.as_str(),
            grant_id,
            grant_epoch,
            serde_json::to_string(&requested_roots)?,
            access_expires_at
        ],
    )?;
    tx.commit()?;
    Ok(true)
}

pub fn revoke_grant(
    db: &mut dyn crate::write_queue::ConnectionOwner,
    grant_id: &str,
    expected_epoch: i64,
) -> Result<bool> {
    identifier(grant_id)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE oauth_inbound_grants SET status = 'revoked', epoch = epoch + 1
        WHERE id = ?1 AND epoch = ?2 AND status = 'active'",
        params![grant_id, expected_epoch],
    )?;
    if changed == 1 {
        tx.execute(
            "UPDATE oauth_inbound_refresh SET state = 'revoked'
            WHERE grant_id = ?1 AND state = 'active'",
            [grant_id],
        )?;
    }
    tx.commit()?;
    Ok(changed == 1)
}

/// Bearer verification repeats current channel exposure and the immutable
/// grant ceiling. The caller also applies current subject/resource policy.
pub fn authorize_channel_operation(
    db: &Connection,
    access_hash: &AccessTokenHash,
    client: &BindingRef,
    audience: &ResourceAudienceRef,
    channel: &ClientChannelContract,
    current: &OperationAuthorityContract,
    now: i64,
) -> Result<bool> {
    channel.verify()?;
    if channel.operations.get(&current.operation) != Some(current) {
        return Ok(false);
    }
    authorize_operation(db, access_hash, client, audience, current, now)
}

fn authorize_operation(
    db: &Connection,
    access_hash: &AccessTokenHash,
    client: &BindingRef,
    audience: &ResourceAudienceRef,
    current: &OperationAuthorityContract,
    now: i64,
) -> Result<bool> {
    let row: Option<(String, i64, String, i64)> = db
        .query_row(
            "SELECT grant_id, grant_epoch, roots, expires_at FROM oauth_inbound_access
         WHERE token_hash = ?1",
            [access_hash.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((grant_id, issued_epoch, roots_json, expires_at)) = row else {
        return Ok(false);
    };
    if now >= expires_at {
        return Ok(false);
    }
    let roots: BTreeSet<String> = serde_json::from_str(&roots_json)?;
    if !roots.contains(&current.operation) {
        return Ok(false);
    }
    let Some((ceiling, current_epoch)) = active_grant(db, &grant_id)? else {
        return Ok(false);
    };
    Ok(issued_epoch == current_epoch
        && ceiling.client == *client
        && ceiling.audience == *audience
        && ceiling.allows(current)?)
}

fn active_grant(db: &Connection, id: &str) -> Result<Option<(GrantCeiling, i64)>> {
    super::restore::require_open(db, super::restore::Kind::Inbound, id)?;
    let row: Option<(String, String, i64)> = db
        .query_row(
            "SELECT ceiling, digest, epoch FROM oauth_inbound_grants
         WHERE id = ?1 AND status = 'active'",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    row.map(|(encoded, digest, epoch)| {
        let ceiling: GrantCeiling = serde_json::from_str(&encoded)?;
        ceiling.verify()?;
        ensure!(
            ceiling.digest.as_str() == digest,
            "grant ceiling changed in storage"
        );
        Ok((ceiling, epoch))
    })
    .transpose()
}

fn pkce(challenge: &str) -> Result<()> {
    ensure!(
        challenge.len() == 43
            && challenge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "invalid S256 PKCE challenge"
    );
    Ok(())
}

fn challenge_for_verifier(verifier: &str) -> Result<String> {
    ensure!(
        (43..=128).contains(&verifier.len())
            && verifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)),
        "invalid PKCE verifier"
    );
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(digest(&SHA256, verifier.as_bytes()).as_ref());
    pkce(&challenge)?;
    Ok(challenge)
}

fn identifier(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-:/".contains(&byte)),
        "invalid inbound OAuth identifier"
    );
    Ok(())
}

#[cfg(test)]
pub(in crate::oauth) mod tests {
    use super::*;
    use day2_capabilities::Name;
    use day2_capabilities::oauth::{AuthorityNode, ClientChannelContract, OperationKind};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    fn pin(name: &str) -> BindingRef {
        BindingRef::pin(Name::try_from(name.to_owned()).unwrap(), &name).unwrap()
    }

    fn root(name: &str) -> OperationAuthorityContract {
        OperationAuthorityContract::derive(
            name.into(),
            1,
            Digest::of(&name).unwrap(),
            OperationKind::Query,
            AuthorityNode {
                actions: BTreeSet::new(),
                children: BTreeMap::new(),
            },
        )
        .unwrap()
    }

    pub(in crate::oauth) fn ceiling() -> GrantCeiling {
        let read = root("ghostwright.read");
        let publish = root("ghostwright.publish");
        ClientChannelContract::derive(
            "mcp".into(),
            BTreeMap::from([
                (read.operation.clone(), read),
                (publish.operation.clone(), publish),
            ]),
        )
        .unwrap()
        .grant(
            pin("client"),
            "human_1".into(),
            ResourceAudienceRef(pin("resource")),
            &BTreeSet::from(["ghostwright.read".into(), "ghostwright.publish".into()]),
        )
        .unwrap()
    }

    fn code() -> AuthorizationCodeHash {
        AuthorizationCodeHash::from_secret(&[b'c'; 32]).unwrap()
    }

    fn hashes(generation: u8) -> CredentialHashes {
        CredentialHashes::from_secrets(&[generation; 32], &[generation + 10; 32]).unwrap()
    }

    fn verifier() -> &'static str {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
    }

    fn redemption(
        number: u8,
        client: BindingRef,
        redirect: OAuthClientRedirectRef,
        pkce_verifier: &str,
    ) -> CodeRedemption {
        CodeRedemption {
            code_hash: code(),
            client,
            redirect,
            pkce_verifier: pkce_verifier.into(),
            audience: ResourceAudienceRef(pin("resource")),
            hashes: hashes(number),
            family: format!("family_{number}"),
            receipt: format!("receipt_{number}"),
            access_expires_at: 60,
            now: 2,
        }
    }

    fn exchange(old: u8, next: u8, roots: BTreeSet<String>) -> RefreshExchange {
        RefreshExchange {
            old_hash: hashes(old).refresh,
            client: pin("client"),
            requested_roots: roots,
            hashes: hashes(next),
            access_expires_at: 80,
            now: 4,
        }
    }

    fn prepared() -> crate::oauth::schema::RawAdmissionDatabase {
        let db = crate::oauth::schema::RawAdmissionDatabase::open_in_memory().unwrap();
        install_schema(&db).unwrap();
        assert!(record_grant(&db, "grant_1", &ceiling(), 1).unwrap());
        db
    }

    fn issue(db: &mut dyn crate::write_queue::ConnectionOwner) {
        assert!(
            issue_code(
                db,
                CodeOffer {
                    code_hash: code(),
                    grant_id: "grant_1".into(),
                    client: pin("client"),
                    redirect: OAuthClientRedirectRef(pin("redirect")),
                    pkce_challenge: challenge_for_verifier(verifier()).unwrap(),
                    audience: ResourceAudienceRef(pin("resource")),
                    expires_at: 100,
                    now: 1,
                }
            )
            .unwrap()
        );
    }

    #[test]
    fn restore_cut_refuses_actual_bearer_code_and_refresh_even_after_a_grant_row_rewind()
    -> Result<()> {
        let directory = tempdir()?;
        let path = directory.path().join("app.sqlite");
        let mut db = crate::oauth::restore::tests::database(&path)?;
        assert!(record_grant(&db, "grant_1", &ceiling(), 1)?);
        issue(&mut db);
        assert!(redeem_code(
            &mut db,
            redemption(
                1,
                pin("client"),
                OAuthClientRedirectRef(pin("redirect")),
                verifier()
            ),
            |_| Ok(())
        )?);
        let current = root("ghostwright.read");
        let channel = ClientChannelContract::derive(
            "mcp".into(),
            BTreeMap::from([(current.operation.clone(), current.clone())]),
        )?;
        assert!(authorize_channel_operation(
            &db,
            &hashes(1).access,
            &pin("client"),
            &ResourceAudienceRef(pin("resource")),
            &channel,
            &current,
            3
        )?);
        let called = std::cell::Cell::new(false);
        assert!(
            refresh(
                &mut db,
                exchange(1, 2, BTreeSet::from(["ghostwright.read".into()])),
                |_| {
                    called.set(true);
                    anyhow::bail!("controlled no-commit eligibility cut")
                }
            )
            .is_err()
        );
        assert!(called.get());
        assert!(issue_code(
            &mut db,
            CodeOffer {
                code_hash: AuthorizationCodeHash::from_secret(&[b'd'; 32])?,
                grant_id: "grant_1".into(),
                client: pin("client"),
                redirect: OAuthClientRedirectRef(pin("redirect")),
                pkce_challenge: challenge_for_verifier(verifier())?,
                audience: ResourceAudienceRef(pin("resource")),
                expires_at: 100,
                now: 3
            }
        )?);
        let old_receipt: String = db.query_row(
            "SELECT receipt FROM oauth_inbound_codes WHERE state='consumed'",
            [],
            |r| r.get(0),
        )?;
        crate::oauth::restore::tests::apply_for_storage(&mut db, 94)?;
        // Neither copied row state nor clock rewind can remove the cut.
        db.execute(
            "UPDATE oauth_inbound_grants SET status='active',epoch=1",
            [],
        )?;
        db.execute(
            "UPDATE oauth_inbound_refresh SET state='active' WHERE state='revoked'",
            [],
        )?;
        for _ in 0..2 {
            drop(db);
            db = crate::oauth::schema::RawAdmissionDatabase::open(&path)?;
            assert!(
                authorize_channel_operation(
                    &db,
                    &hashes(1).access,
                    &pin("client"),
                    &ResourceAudienceRef(pin("resource")),
                    &channel,
                    &current,
                    3
                )
                .is_err()
            );
            let mut waiting = redemption(
                3,
                pin("client"),
                OAuthClientRedirectRef(pin("redirect")),
                verifier(),
            );
            waiting.code_hash = AuthorizationCodeHash::from_secret(&[b'd'; 32])?;
            assert!(
                redeem_code(&mut db, waiting, |_| panic!(
                    "restored code reached issuance"
                ))
                .is_err()
            );
            assert!(
                refresh(
                    &mut db,
                    exchange(1, 2, BTreeSet::from(["ghostwright.read".into()])),
                    |_| panic!("restored refresh reached issuance")
                )
                .is_err()
            );
            assert_eq!(
                db.query_row(
                    "SELECT receipt FROM oauth_inbound_codes WHERE state='consumed'",
                    [],
                    |r| r.get::<_, String>(0)
                )?,
                old_receipt
            );
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM oauth_inbound_codes WHERE state='ready'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                1
            );
        }
        Ok(())
    }

    #[test]
    fn code_is_bound_to_client_redirect_pkce_and_resource_then_consumed_once() {
        let mut db = prepared();
        issue(&mut db);
        let issue_once = |db: &mut dyn crate::write_queue::ConnectionOwner,
                          verifier: &str,
                          client: BindingRef,
                          redirect: OAuthClientRedirectRef| {
            redeem_code(db, redemption(1, client, redirect, verifier), |_| Ok(())).unwrap()
        };
        assert!(!issue_once(
            &mut db,
            "wrong-verifier-with-enough-bytes-01234567890123456789",
            pin("client"),
            OAuthClientRedirectRef(pin("redirect"))
        ));
        assert!(!issue_once(
            &mut db,
            verifier(),
            pin("other"),
            OAuthClientRedirectRef(pin("redirect"))
        ));
        assert!(!issue_once(
            &mut db,
            verifier(),
            pin("client"),
            OAuthClientRedirectRef(pin("other"))
        ));
        assert!(issue_once(
            &mut db,
            verifier(),
            pin("client"),
            OAuthClientRedirectRef(pin("redirect"))
        ));
        assert!(!issue_once(
            &mut db,
            verifier(),
            pin("client"),
            OAuthClientRedirectRef(pin("redirect"))
        ));
        assert!(
            authorize_operation(
                &db,
                &hashes(1).access,
                &pin("client"),
                &ResourceAudienceRef(pin("resource")),
                &root("ghostwright.read"),
                3
            )
            .unwrap()
        );
        assert!(
            !authorize_operation(
                &db,
                &hashes(1).access,
                &pin("client"),
                &ResourceAudienceRef(pin("other")),
                &root("ghostwright.read"),
                3
            )
            .unwrap()
        );
        assert!(
            !authorize_operation(
                &db,
                &hashes(1).access,
                &pin("client"),
                &ResourceAudienceRef(pin("resource")),
                &root("ghostwright.read"),
                60
            )
            .unwrap()
        );
    }

    #[test]
    fn removed_channel_member_cannot_use_an_old_access_token() {
        let mut db = prepared();
        issue(&mut db);
        assert!(
            redeem_code(
                &mut db,
                redemption(
                    1,
                    pin("client"),
                    OAuthClientRedirectRef(pin("redirect")),
                    verifier(),
                ),
                |_| Ok(()),
            )
            .unwrap()
        );
        let read = root("ghostwright.read");
        let full = ClientChannelContract::derive(
            "mcp".into(),
            BTreeMap::from([(read.operation.clone(), read.clone())]),
        )
        .unwrap();
        assert!(
            authorize_channel_operation(
                &db,
                &hashes(1).access,
                &pin("client"),
                &ResourceAudienceRef(pin("resource")),
                &full,
                &read,
                3,
            )
            .unwrap()
        );
        let removed = ClientChannelContract::derive(
            "mcp".into(),
            BTreeMap::from([("ghostwright.publish".into(), root("ghostwright.publish"))]),
        )
        .unwrap();
        assert!(
            !authorize_channel_operation(
                &db,
                &hashes(1).access,
                &pin("client"),
                &ResourceAudienceRef(pin("resource")),
                &removed,
                &read,
                3,
            )
            .unwrap()
        );
    }

    #[test]
    fn refresh_only_narrows_and_replay_or_revocation_cannot_reissue() {
        let mut db = prepared();
        issue(&mut db);
        assert!(
            redeem_code(
                &mut db,
                redemption(
                    1,
                    pin("client"),
                    OAuthClientRedirectRef(pin("redirect")),
                    verifier()
                ),
                |_| Ok(())
            )
            .unwrap()
        );
        let roots = BTreeSet::from(["ghostwright.read".into()]);
        assert!(refresh(&mut db, exchange(1, 2, roots.clone()), |_| Ok(())).unwrap());
        assert!(
            !refresh(
                &mut db,
                exchange(
                    2,
                    3,
                    BTreeSet::from(["ghostwright.read".into(), "ghostwright.publish".into(),])
                ),
                |_| Ok(())
            )
            .unwrap()
        );
        assert!(!refresh(&mut db, exchange(1, 3, roots.clone()), |_| Ok(())).unwrap());
        assert!(!refresh(&mut db, exchange(2, 3, roots.clone()), |_| Ok(())).unwrap());
        assert!(
            authorize_operation(
                &db,
                &hashes(2).access,
                &pin("client"),
                &ResourceAudienceRef(pin("resource")),
                &root("ghostwright.read"),
                4
            )
            .unwrap()
        );
        assert!(
            !authorize_operation(
                &db,
                &hashes(2).access,
                &pin("client"),
                &ResourceAudienceRef(pin("resource")),
                &root("ghostwright.publish"),
                4
            )
            .unwrap()
        );
        assert!(revoke_grant(&mut db, "grant_1", 1).unwrap());
        assert!(
            !authorize_operation(
                &db,
                &hashes(2).access,
                &pin("client"),
                &ResourceAudienceRef(pin("resource")),
                &root("ghostwright.read"),
                4
            )
            .unwrap()
        );
        assert!(!refresh(&mut db, exchange(2, 3, roots), |_| Ok(())).unwrap());
    }

    #[test]
    fn custody_failure_rolls_back_one_time_code_consumption() {
        let mut db = prepared();
        issue(&mut db);
        assert!(
            redeem_code(
                &mut db,
                redemption(
                    1,
                    pin("client"),
                    OAuthClientRedirectRef(pin("redirect")),
                    verifier()
                ),
                |_| anyhow::bail!("test custody failure")
            )
            .is_err()
        );
        assert!(
            redeem_code(
                &mut db,
                redemption(
                    1,
                    pin("client"),
                    OAuthClientRedirectRef(pin("redirect")),
                    verifier()
                ),
                |_| Ok(())
            )
            .unwrap()
        );
    }

    #[test]
    fn purpose_hashes_have_distinct_domains() {
        let secret = [b'a'; 32];
        assert!(CredentialHashes::from_secrets(&secret, &secret).is_err());
        assert_ne!(
            AuthorizationCodeHash::from_secret(&secret)
                .unwrap()
                .as_str(),
            AccessTokenHash::from_secret(&secret).unwrap().as_str()
        );
        assert_ne!(
            AccessTokenHash::from_secret(&secret).unwrap().as_str(),
            RefreshTokenHash::from_secret(&secret).unwrap().as_str()
        );
    }

    #[test]
    fn pkce_s256_matches_rfc_7636_appendix_b() {
        assert_eq!(
            challenge_for_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(challenge_for_verifier("too-short").is_err());
        assert!(challenge_for_verifier(&"a".repeat(129)).is_err());
    }

    #[test]
    fn unknown_inbound_schema_version_fails_closed() {
        let db = crate::oauth::schema::RawAdmissionDatabase::open_in_memory().unwrap();
        install_schema(&db).unwrap();
        db.execute("UPDATE oauth_inbound_schema_version SET version = 3", [])
            .unwrap();
        assert!(install_schema(&db).is_err());
    }

    #[test]
    fn two_sqlite_hosts_cannot_redeem_one_code_twice() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("inbound.sqlite");
        let mut initial = crate::oauth::schema::RawAdmissionDatabase::open(&path).unwrap();
        install_schema(&initial).unwrap();
        record_grant(&initial, "grant_1", &ceiling(), 1).unwrap();
        issue(&mut initial);
        drop(initial);
        let barrier = Arc::new(Barrier::new(2));
        let results = std::thread::scope(|scope| {
            let jobs = (1..=2u8)
                .map(|number| {
                    let path = path.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        let mut db =
                            crate::oauth::schema::RawAdmissionDatabase::open(path).unwrap();
                        db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                        db.execute_batch("PRAGMA foreign_keys = ON").unwrap();
                        barrier.wait();
                        redeem_code(
                            &mut db,
                            redemption(
                                number,
                                pin("client"),
                                OAuthClientRedirectRef(pin("redirect")),
                                verifier(),
                            ),
                            |_| Ok(()),
                        )
                        .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            jobs.into_iter()
                .map(|job| job.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.into_iter().filter(|redeemed| *redeemed).count(), 1);
        let db = crate::oauth::schema::RawAdmissionDatabase::open(&path).unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM oauth_inbound_refresh", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            1
        );
    }

    #[test]
    fn grant_revocation_racing_redemption_never_leaves_usable_access() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("revoke.sqlite");
        let mut initial = crate::oauth::schema::RawAdmissionDatabase::open(&path).unwrap();
        install_schema(&initial).unwrap();
        record_grant(&initial, "grant_1", &ceiling(), 1).unwrap();
        issue(&mut initial);
        drop(initial);
        let barrier = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let redeem_barrier = barrier.clone();
            let redeem_path = path.clone();
            let redeem = scope.spawn(move || {
                let mut db = crate::oauth::schema::RawAdmissionDatabase::open(redeem_path).unwrap();
                db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                db.execute_batch("PRAGMA foreign_keys = ON").unwrap();
                redeem_barrier.wait();
                redeem_code(
                    &mut db,
                    redemption(
                        1,
                        pin("client"),
                        OAuthClientRedirectRef(pin("redirect")),
                        verifier(),
                    ),
                    |_| Ok(()),
                )
                .unwrap()
            });
            let revoke = scope.spawn(|| {
                let mut db = crate::oauth::schema::RawAdmissionDatabase::open(&path).unwrap();
                db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                db.execute_batch("PRAGMA foreign_keys = ON").unwrap();
                barrier.wait();
                revoke_grant(&mut db, "grant_1", 1).unwrap()
            });
            let _ = redeem.join().unwrap();
            assert!(revoke.join().unwrap());
        });
        let db = crate::oauth::schema::RawAdmissionDatabase::open(&path).unwrap();
        assert!(
            !authorize_operation(
                &db,
                &hashes(1).access,
                &pin("client"),
                &ResourceAudienceRef(pin("resource")),
                &root("ghostwright.read"),
                3
            )
            .unwrap()
        );
    }
}
