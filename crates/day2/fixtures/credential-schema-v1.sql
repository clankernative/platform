-- The version-1 managed-credential unit exactly as the GoLinks build
-- (platform 1a822436) installs it in every store during Runtime::initialize,
-- whether or not the app declares managed credentials. Statements are copied
-- verbatim from that commit; only the leading "PRAGMA foreign_keys = ON;" of
-- the first batch is omitted.
--
-- crates/day2/src/managed_credentials/store.rs install_schema (unchanged from
-- d5b4328c, where version 1 began, through 0bbe6666):
        CREATE TABLE IF NOT EXISTS day2_credential_schema_version (
            version INTEGER PRIMARY KEY
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_lineages (
            id TEXT PRIMARY KEY,
            namespace TEXT NOT NULL,
            namespace_json TEXT NOT NULL,
            family TEXT NOT NULL,
            family_contract TEXT NOT NULL,
            principal TEXT NOT NULL,
            creator TEXT NOT NULL,
            label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 128),
            recipient TEXT NOT NULL,
            session TEXT NOT NULL,
            grant_json TEXT NOT NULL,
            grant_digest TEXT NOT NULL,
            grant_valid_until INTEGER NOT NULL,
            security_epoch INTEGER NOT NULL CHECK(security_epoch > 0),
            state TEXT NOT NULL CHECK(state IN ('active', 'revoked')),
            head TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision > 0)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_versions (
            id TEXT PRIMARY KEY,
            lineage TEXT NOT NULL REFERENCES day2_credential_lineages(id),
            predecessor TEXT UNIQUE REFERENCES day2_credential_versions(id),
            selector TEXT NOT NULL UNIQUE,
            verifier BLOB NOT NULL CHECK(length(verifier) = 32),
            verifier_key_version TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
            security_epoch INTEGER NOT NULL CHECK(security_epoch > 0),
            grant_digest TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('active', 'superseded', 'revoked'))
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_material (
            version TEXT PRIMARY KEY REFERENCES day2_credential_versions(id),
            identity_json TEXT NOT NULL,
            material_revision INTEGER NOT NULL CHECK(material_revision > 0),
            envelope_revision INTEGER NOT NULL CHECK(envelope_revision > 0),
            encryption_key_version TEXT NOT NULL,
            nonce BLOB NOT NULL CHECK(length(nonce) = 12),
            ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 32 AND 512)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_deliveries (
            version TEXT PRIMARY KEY REFERENCES day2_credential_versions(id),
            recipient TEXT NOT NULL,
            session TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('available', 'closed')),
            closed_reason TEXT NOT NULL DEFAULT ''
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_receipts (
            namespace TEXT NOT NULL,
            invocation TEXT NOT NULL,
            instruction_slot INTEGER NOT NULL CHECK(instruction_slot >= 0),
            family_contract TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('issue', 'rotate', 'revoke')),
            lineage TEXT NOT NULL REFERENCES day2_credential_lineages(id),
            version TEXT REFERENCES day2_credential_versions(id),
            PRIMARY KEY(namespace, invocation, instruction_slot)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_reveals (
            attempt TEXT PRIMARY KEY,
            version TEXT NOT NULL REFERENCES day2_credential_versions(id),
            recipient TEXT NOT NULL,
            session TEXT NOT NULL,
            authorized_at INTEGER NOT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS day2_credential_visible_creator
            ON day2_credential_lineages(namespace, family, creator, id);
        CREATE INDEX IF NOT EXISTS day2_credential_visible_principal
            ON day2_credential_lineages(namespace, family, principal, id);
-- crates/day2/src/managed_credentials/browser.rs install:
        CREATE TABLE IF NOT EXISTS day2_credential_browser (
        invocation TEXT PRIMARY KEY, attempt TEXT NOT NULL UNIQUE, intent TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS day2_credential_browser_expiry ON day2_credential_browser(expires_at);
-- crates/day2/src/managed_credentials/issuance.rs install:
        CREATE TABLE IF NOT EXISTS day2_credential_confirmations (
        invocation TEXT PRIMARY KEY, confirmation TEXT NOT NULL
    ) STRICT;
-- The marker install_schema writes into an absent unit. A version-1 unit
-- holds no other row unless the app issued a managed credential.
INSERT INTO day2_credential_schema_version VALUES (1);
