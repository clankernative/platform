-- Frozen restore version-1 schema from Platform 8286c1ef.
-- Schema only; an empty unit carries no cut, closure or credential history.

CREATE TABLE oauth_restore_closed(
             kind TEXT NOT NULL, id TEXT NOT NULL,
             cut TEXT NOT NULL REFERENCES oauth_restore_cuts(digest), PRIMARY KEY(kind,id)
         );

CREATE TABLE oauth_restore_cuts(
             digest TEXT PRIMARY KEY, binding TEXT NOT NULL, inventory TEXT NOT NULL
         );

CREATE TABLE oauth_restore_schema_version(version INTEGER PRIMARY KEY);

CREATE TRIGGER oauth_restore_closed_no_delete BEFORE DELETE ON oauth_restore_closed
             BEGIN SELECT RAISE(ABORT,'restore closure retained'); END;

CREATE TRIGGER oauth_restore_closed_no_update BEFORE UPDATE ON oauth_restore_closed
             BEGIN SELECT RAISE(ABORT,'immutable restore closure'); END;

CREATE TRIGGER oauth_restore_closed_shape_INSERT_v1
                 AFTER INSERT ON oauth_restore_closed
                 WHEN EXISTS(SELECT 1 FROM oauth_restore_closed WHERE rowid = NEW.rowid AND NOT COALESCE(((kind IN ('connect','refresh','management','use','use_original','fresh','inbound')
             AND length(id) BETWEEN 1 AND 256 AND length(cut)=71
             AND EXISTS(SELECT 1 FROM oauth_restore_cuts c WHERE c.digest=cut)) AND typeof(kind) = 'text' AND typeof(id) = 'text' AND typeof(cut) = 'text'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER oauth_restore_closed_shape_UPDATE_v1
                 AFTER UPDATE ON oauth_restore_closed
                 WHEN EXISTS(SELECT 1 FROM oauth_restore_closed WHERE rowid = NEW.rowid AND NOT COALESCE(((kind IN ('connect','refresh','management','use','use_original','fresh','inbound')
             AND length(id) BETWEEN 1 AND 256 AND length(cut)=71
             AND EXISTS(SELECT 1 FROM oauth_restore_cuts c WHERE c.digest=cut)) AND typeof(kind) = 'text' AND typeof(id) = 'text' AND typeof(cut) = 'text'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER oauth_restore_cut_no_delete BEFORE DELETE ON oauth_restore_cuts
             BEGIN SELECT RAISE(ABORT,'restore cut retained'); END;

CREATE TRIGGER oauth_restore_cut_no_update BEFORE UPDATE ON oauth_restore_cuts
             BEGIN SELECT RAISE(ABORT,'immutable restore cut'); END;

CREATE TRIGGER oauth_restore_cuts_shape_INSERT_v1
                 AFTER INSERT ON oauth_restore_cuts
                 WHEN EXISTS(SELECT 1 FROM oauth_restore_cuts WHERE rowid = NEW.rowid AND NOT COALESCE(((length(digest)=71 AND substr(digest,1,7)='sha256:' AND substr(digest,8) NOT GLOB '*[^0-9a-f]*'
             AND length(binding) BETWEEN 1 AND 32768 AND json_valid(binding) AND json_type(binding)='object'
             AND length(inventory)=71 AND substr(inventory,1,7)='sha256:' AND substr(inventory,8) NOT GLOB '*[^0-9a-f]*') AND typeof(digest) = 'text' AND typeof(binding) = 'text' AND typeof(inventory) = 'text'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER oauth_restore_cuts_shape_UPDATE_v1
                 AFTER UPDATE ON oauth_restore_cuts
                 WHEN EXISTS(SELECT 1 FROM oauth_restore_cuts WHERE rowid = NEW.rowid AND NOT COALESCE(((length(digest)=71 AND substr(digest,1,7)='sha256:' AND substr(digest,8) NOT GLOB '*[^0-9a-f]*'
             AND length(binding) BETWEEN 1 AND 32768 AND json_valid(binding) AND json_type(binding)='object'
             AND length(inventory)=71 AND substr(inventory,1,7)='sha256:' AND substr(inventory,8) NOT GLOB '*[^0-9a-f]*') AND typeof(digest) = 'text' AND typeof(binding) = 'text' AND typeof(inventory) = 'text'), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

INSERT INTO oauth_restore_schema_version VALUES(1);
