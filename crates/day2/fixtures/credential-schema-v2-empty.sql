-- Frozen empty credential layout emitted by Platform d67909a872623bc5aaffad61495fb783289ec806.
-- Schema definitions only; no credential material or application rows.

CREATE TABLE day2_credential_browser (
        invocation TEXT PRIMARY KEY, attempt TEXT NOT NULL UNIQUE, intent TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    ) STRICT;

CREATE TABLE day2_credential_confirmations (
        invocation TEXT PRIMARY KEY, confirmation TEXT NOT NULL
    ) STRICT;

CREATE TABLE day2_credential_deliveries (
            version TEXT PRIMARY KEY REFERENCES day2_credential_versions(id),
            recipient TEXT NOT NULL,
            session TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('available', 'closed')),
            closed_reason TEXT NOT NULL DEFAULT ''
        ) STRICT;

CREATE TABLE day2_credential_lineages (
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

CREATE TABLE day2_credential_material (
            version TEXT PRIMARY KEY REFERENCES day2_credential_versions(id),
            identity_json TEXT NOT NULL,
            material_revision INTEGER NOT NULL CHECK(material_revision > 0),
            envelope_revision INTEGER NOT NULL CHECK(envelope_revision > 0),
            encryption_key_version TEXT NOT NULL,
            nonce BLOB NOT NULL CHECK(length(nonce) = 12),
            ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 32 AND 512)
        ) STRICT;

CREATE TABLE day2_credential_origins (
        invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id), evidence TEXT NOT NULL
    ) STRICT;

CREATE TABLE day2_credential_receipts (
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

CREATE TABLE day2_credential_reveals (
            attempt TEXT PRIMARY KEY,
            version TEXT NOT NULL REFERENCES day2_credential_versions(id),
            recipient TEXT NOT NULL,
            session TEXT NOT NULL,
            authorized_at INTEGER NOT NULL
        ) STRICT;

CREATE TABLE day2_credential_revocations (
            namespace TEXT NOT NULL, invocation TEXT NOT NULL, instruction_slot INTEGER NOT NULL,
            request_digest TEXT NOT NULL, outcome TEXT NOT NULL,
            PRIMARY KEY(namespace, invocation, instruction_slot),
            FOREIGN KEY(namespace, invocation, instruction_slot)
                REFERENCES day2_credential_receipts(namespace, invocation, instruction_slot)
        ) STRICT;

CREATE TABLE day2_credential_schema_version (
            version INTEGER PRIMARY KEY
        ) STRICT;

CREATE TABLE day2_credential_versions (
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

CREATE INDEX day2_credential_browser_expiry ON day2_credential_browser(expires_at);

CREATE INDEX day2_credential_visible_creator
            ON day2_credential_lineages(namespace, family, creator, id);

CREATE INDEX day2_credential_visible_principal
            ON day2_credential_lineages(namespace, family, principal, id);

CREATE TRIGGER day2_credential_deliveries_shape_INSERT_v2
                 AFTER INSERT ON day2_credential_deliveries
                 WHEN EXISTS(SELECT 1 FROM day2_credential_deliveries WHERE rowid = NEW.rowid AND NOT COALESCE(((length(CAST(version AS BLOB)) BETWEEN 1 AND 160 AND version NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(recipient AS BLOB)) BETWEEN 1 AND 256 AND trim(recipient,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)) = recipient AND substr(recipient,1,7) != 'domain:' AND substr(recipient,1,18) != 'credential_client:' AND instr(recipient,char(0)) = 0 AND recipient NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND length(CAST(session AS BLOB)) BETWEEN 1 AND 160 AND session NOT GLOB '*[^a-zA-Z0-9._/-]*' AND ((state='available' AND closed_reason='') OR (state='closed' AND closed_reason IN ('acknowledged','expired','session_end','epoch_advance','rotation','revoked')))) AND typeof(version) = 'text' AND typeof(recipient) = 'text' AND typeof(session) = 'text' AND typeof(expires_at) = 'integer' AND typeof(state) = 'text' AND typeof(closed_reason) = 'text'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_deliveries_shape_UPDATE_v2
                 AFTER UPDATE ON day2_credential_deliveries
                 WHEN EXISTS(SELECT 1 FROM day2_credential_deliveries WHERE rowid = NEW.rowid AND NOT COALESCE(((length(CAST(version AS BLOB)) BETWEEN 1 AND 160 AND version NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(recipient AS BLOB)) BETWEEN 1 AND 256 AND trim(recipient,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)) = recipient AND substr(recipient,1,7) != 'domain:' AND substr(recipient,1,18) != 'credential_client:' AND instr(recipient,char(0)) = 0 AND recipient NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND length(CAST(session AS BLOB)) BETWEEN 1 AND 160 AND session NOT GLOB '*[^a-zA-Z0-9._/-]*' AND ((state='available' AND closed_reason='') OR (state='closed' AND closed_reason IN ('acknowledged','expired','session_end','epoch_advance','rotation','revoked')))) AND typeof(version) = 'text' AND typeof(recipient) = 'text' AND typeof(session) = 'text' AND typeof(expires_at) = 'integer' AND typeof(state) = 'text' AND typeof(closed_reason) = 'text'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_lineages_shape_INSERT_v2
                 AFTER INSERT ON day2_credential_lineages
                 WHEN EXISTS(SELECT 1 FROM day2_credential_lineages WHERE rowid = NEW.rowid AND NOT COALESCE(((length(CAST(id AS BLOB)) BETWEEN 1 AND 160 AND id NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(namespace) = 71 AND substr(namespace,1,7) = 'sha256:' AND substr(namespace,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(namespace_json AS BLOB)) BETWEEN 2 AND 1048576 AND json_valid(namespace_json) AND json_type(namespace_json) = 'object' AND length(CAST(family AS BLOB)) BETWEEN 1 AND 160 AND family NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(family_contract) = 71 AND substr(family_contract,1,7) = 'sha256:' AND substr(family_contract,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(principal AS BLOB)) BETWEEN 1 AND 256 AND trim(principal,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)) = principal AND substr(principal,1,7) != 'domain:' AND substr(principal,1,18) != 'credential_client:' AND instr(principal,char(0)) = 0 AND principal NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND length(CAST(creator AS BLOB)) BETWEEN 1 AND 256 AND trim(creator,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)) = creator AND substr(creator,1,7) != 'domain:' AND substr(creator,1,18) != 'credential_client:' AND instr(creator,char(0)) = 0 AND creator NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND length(CAST(recipient AS BLOB)) BETWEEN 1 AND 256 AND trim(recipient,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)) = recipient AND substr(recipient,1,7) != 'domain:' AND substr(recipient,1,18) != 'credential_client:' AND instr(recipient,char(0)) = 0 AND recipient NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND length(CAST(session AS BLOB)) BETWEEN 1 AND 160 AND session NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(grant_json AS BLOB)) BETWEEN 2 AND 1048576 AND json_valid(grant_json) AND json_type(grant_json) = 'object' AND length(grant_digest) = 71 AND substr(grant_digest,1,7) = 'sha256:' AND substr(grant_digest,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(head AS BLOB)) BETWEEN 1 AND 160 AND head NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(label AS BLOB)) BETWEEN 1 AND 128 AND length(trim(label,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288))) > 0 AND instr(label,char(0)) = 0 AND label NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND security_epoch > 0 AND revision > 0 AND state IN ('active','revoked')) AND typeof(id) = 'text' AND typeof(namespace) = 'text' AND typeof(namespace_json) = 'text' AND typeof(family) = 'text' AND typeof(family_contract) = 'text' AND typeof(principal) = 'text' AND typeof(creator) = 'text' AND typeof(label) = 'text' AND typeof(recipient) = 'text' AND typeof(session) = 'text' AND typeof(grant_json) = 'text' AND typeof(grant_digest) = 'text' AND typeof(grant_valid_until) = 'integer' AND typeof(security_epoch) = 'integer' AND typeof(state) = 'text' AND typeof(head) = 'text' AND typeof(revision) = 'integer'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_lineages_shape_UPDATE_v2
                 AFTER UPDATE ON day2_credential_lineages
                 WHEN EXISTS(SELECT 1 FROM day2_credential_lineages WHERE rowid = NEW.rowid AND NOT COALESCE(((length(CAST(id AS BLOB)) BETWEEN 1 AND 160 AND id NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(namespace) = 71 AND substr(namespace,1,7) = 'sha256:' AND substr(namespace,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(namespace_json AS BLOB)) BETWEEN 2 AND 1048576 AND json_valid(namespace_json) AND json_type(namespace_json) = 'object' AND length(CAST(family AS BLOB)) BETWEEN 1 AND 160 AND family NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(family_contract) = 71 AND substr(family_contract,1,7) = 'sha256:' AND substr(family_contract,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(principal AS BLOB)) BETWEEN 1 AND 256 AND trim(principal,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)) = principal AND substr(principal,1,7) != 'domain:' AND substr(principal,1,18) != 'credential_client:' AND instr(principal,char(0)) = 0 AND principal NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND length(CAST(creator AS BLOB)) BETWEEN 1 AND 256 AND trim(creator,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)) = creator AND substr(creator,1,7) != 'domain:' AND substr(creator,1,18) != 'credential_client:' AND instr(creator,char(0)) = 0 AND creator NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND length(CAST(recipient AS BLOB)) BETWEEN 1 AND 256 AND trim(recipient,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)) = recipient AND substr(recipient,1,7) != 'domain:' AND substr(recipient,1,18) != 'credential_client:' AND instr(recipient,char(0)) = 0 AND recipient NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND length(CAST(session AS BLOB)) BETWEEN 1 AND 160 AND session NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(grant_json AS BLOB)) BETWEEN 2 AND 1048576 AND json_valid(grant_json) AND json_type(grant_json) = 'object' AND length(grant_digest) = 71 AND substr(grant_digest,1,7) = 'sha256:' AND substr(grant_digest,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(head AS BLOB)) BETWEEN 1 AND 160 AND head NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(label AS BLOB)) BETWEEN 1 AND 128 AND length(trim(label,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288))) > 0 AND instr(label,char(0)) = 0 AND label NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND security_epoch > 0 AND revision > 0 AND state IN ('active','revoked')) AND typeof(id) = 'text' AND typeof(namespace) = 'text' AND typeof(namespace_json) = 'text' AND typeof(family) = 'text' AND typeof(family_contract) = 'text' AND typeof(principal) = 'text' AND typeof(creator) = 'text' AND typeof(label) = 'text' AND typeof(recipient) = 'text' AND typeof(session) = 'text' AND typeof(grant_json) = 'text' AND typeof(grant_digest) = 'text' AND typeof(grant_valid_until) = 'integer' AND typeof(security_epoch) = 'integer' AND typeof(state) = 'text' AND typeof(head) = 'text' AND typeof(revision) = 'integer'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_material_shape_INSERT_v2
                 AFTER INSERT ON day2_credential_material
                 WHEN EXISTS(SELECT 1 FROM day2_credential_material WHERE rowid = NEW.rowid AND NOT COALESCE(((length(CAST(version AS BLOB)) BETWEEN 1 AND 160 AND version NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(identity_json AS BLOB)) BETWEEN 2 AND 1048576 AND json_valid(identity_json) AND json_type(identity_json) = 'object' AND length(CAST(encryption_key_version AS BLOB)) BETWEEN 1 AND 160 AND encryption_key_version NOT GLOB '*[^a-zA-Z0-9._/-]*' AND material_revision > 0 AND envelope_revision > 0 AND length(nonce)=12 AND length(ciphertext) BETWEEN 32 AND 512) AND typeof(version) = 'text' AND typeof(identity_json) = 'text' AND typeof(material_revision) = 'integer' AND typeof(envelope_revision) = 'integer' AND typeof(encryption_key_version) = 'text' AND typeof(nonce) = 'blob' AND typeof(ciphertext) = 'blob'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_material_shape_UPDATE_v2
                 AFTER UPDATE ON day2_credential_material
                 WHEN EXISTS(SELECT 1 FROM day2_credential_material WHERE rowid = NEW.rowid AND NOT COALESCE(((length(CAST(version AS BLOB)) BETWEEN 1 AND 160 AND version NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(identity_json AS BLOB)) BETWEEN 2 AND 1048576 AND json_valid(identity_json) AND json_type(identity_json) = 'object' AND length(CAST(encryption_key_version AS BLOB)) BETWEEN 1 AND 160 AND encryption_key_version NOT GLOB '*[^a-zA-Z0-9._/-]*' AND material_revision > 0 AND envelope_revision > 0 AND length(nonce)=12 AND length(ciphertext) BETWEEN 32 AND 512) AND typeof(version) = 'text' AND typeof(identity_json) = 'text' AND typeof(material_revision) = 'integer' AND typeof(envelope_revision) = 'integer' AND typeof(encryption_key_version) = 'text' AND typeof(nonce) = 'blob' AND typeof(ciphertext) = 'blob'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_receipts_shape_INSERT_v2
                 AFTER INSERT ON day2_credential_receipts
                 WHEN EXISTS(SELECT 1 FROM day2_credential_receipts WHERE rowid = NEW.rowid AND NOT COALESCE(((length(namespace) = 71 AND substr(namespace,1,7) = 'sha256:' AND substr(namespace,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(invocation AS BLOB)) BETWEEN 1 AND 160 AND invocation NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(family_contract) = 71 AND substr(family_contract,1,7) = 'sha256:' AND substr(family_contract,8) NOT GLOB '*[^0-9a-f]*' AND length(request_digest) = 71 AND substr(request_digest,1,7) = 'sha256:' AND substr(request_digest,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(lineage AS BLOB)) BETWEEN 1 AND 160 AND lineage NOT GLOB '*[^a-zA-Z0-9._/-]*' AND instruction_slot BETWEEN 0 AND 4294967295 AND ((action IN ('issue','rotate') AND version IS NOT NULL AND length(CAST(version AS BLOB)) BETWEEN 1 AND 160 AND version NOT GLOB '*[^a-zA-Z0-9._/-]*') OR (action='revoke' AND version IS NULL))) AND typeof(namespace) = 'text' AND typeof(invocation) = 'text' AND typeof(instruction_slot) = 'integer' AND typeof(family_contract) = 'text' AND typeof(request_digest) = 'text' AND typeof(action) = 'text' AND typeof(lineage) = 'text' AND (version IS NULL OR typeof(version) = 'text')), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_receipts_shape_UPDATE_v2
                 AFTER UPDATE ON day2_credential_receipts
                 WHEN EXISTS(SELECT 1 FROM day2_credential_receipts WHERE rowid = NEW.rowid AND NOT COALESCE(((length(namespace) = 71 AND substr(namespace,1,7) = 'sha256:' AND substr(namespace,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(invocation AS BLOB)) BETWEEN 1 AND 160 AND invocation NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(family_contract) = 71 AND substr(family_contract,1,7) = 'sha256:' AND substr(family_contract,8) NOT GLOB '*[^0-9a-f]*' AND length(request_digest) = 71 AND substr(request_digest,1,7) = 'sha256:' AND substr(request_digest,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(lineage AS BLOB)) BETWEEN 1 AND 160 AND lineage NOT GLOB '*[^a-zA-Z0-9._/-]*' AND instruction_slot BETWEEN 0 AND 4294967295 AND ((action IN ('issue','rotate') AND version IS NOT NULL AND length(CAST(version AS BLOB)) BETWEEN 1 AND 160 AND version NOT GLOB '*[^a-zA-Z0-9._/-]*') OR (action='revoke' AND version IS NULL))) AND typeof(namespace) = 'text' AND typeof(invocation) = 'text' AND typeof(instruction_slot) = 'integer' AND typeof(family_contract) = 'text' AND typeof(request_digest) = 'text' AND typeof(action) = 'text' AND typeof(lineage) = 'text' AND (version IS NULL OR typeof(version) = 'text')), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_reveals_shape_INSERT_v2
                 AFTER INSERT ON day2_credential_reveals
                 WHEN EXISTS(SELECT 1 FROM day2_credential_reveals WHERE rowid = NEW.rowid AND NOT COALESCE(((length(CAST(attempt AS BLOB)) BETWEEN 1 AND 160 AND attempt NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(version AS BLOB)) BETWEEN 1 AND 160 AND version NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(recipient AS BLOB)) BETWEEN 1 AND 256 AND trim(recipient,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)) = recipient AND substr(recipient,1,7) != 'domain:' AND substr(recipient,1,18) != 'credential_client:' AND instr(recipient,char(0)) = 0 AND recipient NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND length(CAST(session AS BLOB)) BETWEEN 1 AND 160 AND session NOT GLOB '*[^a-zA-Z0-9._/-]*') AND typeof(attempt) = 'text' AND typeof(version) = 'text' AND typeof(recipient) = 'text' AND typeof(session) = 'text' AND typeof(authorized_at) = 'integer'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_reveals_shape_UPDATE_v2
                 AFTER UPDATE ON day2_credential_reveals
                 WHEN EXISTS(SELECT 1 FROM day2_credential_reveals WHERE rowid = NEW.rowid AND NOT COALESCE(((length(CAST(attempt AS BLOB)) BETWEEN 1 AND 160 AND attempt NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(version AS BLOB)) BETWEEN 1 AND 160 AND version NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(recipient AS BLOB)) BETWEEN 1 AND 256 AND trim(recipient,char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)) = recipient AND substr(recipient,1,7) != 'domain:' AND substr(recipient,1,18) != 'credential_client:' AND instr(recipient,char(0)) = 0 AND recipient NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*' AND length(CAST(session AS BLOB)) BETWEEN 1 AND 160 AND session NOT GLOB '*[^a-zA-Z0-9._/-]*') AND typeof(attempt) = 'text' AND typeof(version) = 'text' AND typeof(recipient) = 'text' AND typeof(session) = 'text' AND typeof(authorized_at) = 'integer'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_revocations_shape_INSERT_v2
                 AFTER INSERT ON day2_credential_revocations
                 WHEN EXISTS(SELECT 1 FROM day2_credential_revocations WHERE rowid = NEW.rowid AND NOT COALESCE(((length(namespace) = 71 AND substr(namespace,1,7) = 'sha256:' AND substr(namespace,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(invocation AS BLOB)) BETWEEN 1 AND 160 AND invocation NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(request_digest) = 71 AND substr(request_digest,1,7) = 'sha256:' AND substr(request_digest,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(outcome AS BLOB)) BETWEEN 2 AND 1048576 AND json_valid(outcome) AND json_type(outcome) = 'object' AND instruction_slot BETWEEN 0 AND 4294967295) AND typeof(namespace) = 'text' AND typeof(invocation) = 'text' AND typeof(instruction_slot) = 'integer' AND typeof(request_digest) = 'text' AND typeof(outcome) = 'text'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_revocations_shape_UPDATE_v2
                 AFTER UPDATE ON day2_credential_revocations
                 WHEN EXISTS(SELECT 1 FROM day2_credential_revocations WHERE rowid = NEW.rowid AND NOT COALESCE(((length(namespace) = 71 AND substr(namespace,1,7) = 'sha256:' AND substr(namespace,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(invocation AS BLOB)) BETWEEN 1 AND 160 AND invocation NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(request_digest) = 71 AND substr(request_digest,1,7) = 'sha256:' AND substr(request_digest,8) NOT GLOB '*[^0-9a-f]*' AND length(CAST(outcome AS BLOB)) BETWEEN 2 AND 1048576 AND json_valid(outcome) AND json_type(outcome) = 'object' AND instruction_slot BETWEEN 0 AND 4294967295) AND typeof(namespace) = 'text' AND typeof(invocation) = 'text' AND typeof(instruction_slot) = 'integer' AND typeof(request_digest) = 'text' AND typeof(outcome) = 'text'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_versions_shape_INSERT_v2
                 AFTER INSERT ON day2_credential_versions
                 WHEN EXISTS(SELECT 1 FROM day2_credential_versions WHERE rowid = NEW.rowid AND NOT COALESCE(((length(CAST(id AS BLOB)) BETWEEN 1 AND 160 AND id NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(lineage AS BLOB)) BETWEEN 1 AND 160 AND lineage NOT GLOB '*[^a-zA-Z0-9._/-]*' AND (predecessor IS NULL OR (length(CAST(predecessor AS BLOB)) BETWEEN 1 AND 160 AND predecessor NOT GLOB '*[^a-zA-Z0-9._/-]*' AND predecessor != id)) AND length(CAST(selector AS BLOB)) BETWEEN 1 AND 160 AND selector NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(selector)=22 AND selector NOT GLOB '*[^a-zA-Z0-9_-]*' AND substr(selector,22,1) IN ('A','Q','g','w') AND length(CAST(verifier_key_version AS BLOB)) BETWEEN 1 AND 160 AND verifier_key_version NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(grant_digest) = 71 AND substr(grant_digest,1,7) = 'sha256:' AND substr(grant_digest,8) NOT GLOB '*[^0-9a-f]*' AND length(verifier)=32 AND expires_at > issued_at AND security_epoch > 0 AND state IN ('active','superseded','revoked')) AND typeof(id) = 'text' AND typeof(lineage) = 'text' AND (predecessor IS NULL OR typeof(predecessor) = 'text') AND typeof(selector) = 'text' AND typeof(verifier) = 'blob' AND typeof(verifier_key_version) = 'text' AND typeof(issued_at) = 'integer' AND typeof(expires_at) = 'integer' AND typeof(security_epoch) = 'integer' AND typeof(grant_digest) = 'text' AND typeof(state) = 'text'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER day2_credential_versions_shape_UPDATE_v2
                 AFTER UPDATE ON day2_credential_versions
                 WHEN EXISTS(SELECT 1 FROM day2_credential_versions WHERE rowid = NEW.rowid AND NOT COALESCE(((length(CAST(id AS BLOB)) BETWEEN 1 AND 160 AND id NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(CAST(lineage AS BLOB)) BETWEEN 1 AND 160 AND lineage NOT GLOB '*[^a-zA-Z0-9._/-]*' AND (predecessor IS NULL OR (length(CAST(predecessor AS BLOB)) BETWEEN 1 AND 160 AND predecessor NOT GLOB '*[^a-zA-Z0-9._/-]*' AND predecessor != id)) AND length(CAST(selector AS BLOB)) BETWEEN 1 AND 160 AND selector NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(selector)=22 AND selector NOT GLOB '*[^a-zA-Z0-9_-]*' AND substr(selector,22,1) IN ('A','Q','g','w') AND length(CAST(verifier_key_version AS BLOB)) BETWEEN 1 AND 160 AND verifier_key_version NOT GLOB '*[^a-zA-Z0-9._/-]*' AND length(grant_digest) = 71 AND substr(grant_digest,1,7) = 'sha256:' AND substr(grant_digest,8) NOT GLOB '*[^0-9a-f]*' AND length(verifier)=32 AND expires_at > issued_at AND security_epoch > 0 AND state IN ('active','superseded','revoked')) AND typeof(id) = 'text' AND typeof(lineage) = 'text' AND (predecessor IS NULL OR typeof(predecessor) = 'text') AND typeof(selector) = 'text' AND typeof(verifier) = 'blob' AND typeof(verifier_key_version) = 'text' AND typeof(issued_at) = 'integer' AND typeof(expires_at) = 'integer' AND typeof(security_epoch) = 'integer' AND typeof(grant_digest) = 'text' AND typeof(state) = 'text'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

INSERT INTO day2_credential_schema_version VALUES(2);
