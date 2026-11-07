-- Frozen empty native fresh-owner version-1 unit before action-specific credential intents.
-- Schema only; no captured owners or provider data.

CREATE TABLE native_fresh_owners (
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

CREATE TABLE native_fresh_schema_version(version INTEGER PRIMARY KEY);

CREATE TRIGGER native_fresh_owner_forward_only BEFORE UPDATE OF stage ON native_fresh_owners
        WHEN NOT ((OLD.stage='allocated' AND NEW.stage IN ('offered','refused'))
               OR (OLD.stage='offered' AND NEW.stage IN ('consumed','refused')))
        BEGIN SELECT RAISE(ABORT,'native fresh stage regression'); END;

CREATE TRIGGER native_fresh_owner_no_delete BEFORE DELETE ON native_fresh_owners
        BEGIN SELECT RAISE(ABORT,'native fresh owner tombstone required'); END;

CREATE TRIGGER native_fresh_owner_original_immutable
        BEFORE UPDATE OF original,attempt,purpose,human,subject,context,owner,created_at,expires_at ON native_fresh_owners
        BEGIN SELECT RAISE(ABORT,'native fresh original immutable'); END;

CREATE TRIGGER native_fresh_owner_publication_immutable
        BEFORE UPDATE OF request,request_digest ON native_fresh_owners WHEN OLD.stage != 'allocated'
        BEGIN SELECT RAISE(ABORT,'native fresh publication immutable'); END;

CREATE TRIGGER native_fresh_owner_result_immutable
        BEFORE UPDATE OF result_digest ON native_fresh_owners WHEN OLD.stage != 'offered'
        BEGIN SELECT RAISE(ABORT,'native fresh result immutable'); END;

CREATE TRIGGER native_fresh_owners_shape_INSERT_v1
                 AFTER INSERT ON native_fresh_owners
                 WHEN EXISTS(SELECT 1 FROM native_fresh_owners WHERE rowid = NEW.rowid AND NOT COALESCE(((length(original)=71 AND substr(original,1,7)='sha256:' AND substr(original,8) NOT GLOB '*[^0-9a-f]*'
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
                      OR (request IS NOT NULL AND request_digest IS NOT NULL))))) AND typeof(original) = 'text' AND typeof(attempt) = 'text' AND typeof(purpose) = 'text' AND typeof(human) = 'text' AND typeof(subject) = 'text' AND typeof(context) = 'text' AND typeof(owner) = 'text' AND typeof(created_at) = 'integer' AND typeof(expires_at) = 'integer' AND typeof(stage) = 'text' AND (request IS NULL OR typeof(request) = 'text') AND (request_digest IS NULL OR typeof(request_digest) = 'text') AND (result_digest IS NULL OR typeof(result_digest) = 'text')), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

CREATE TRIGGER native_fresh_owners_shape_UPDATE_v1
                 AFTER UPDATE ON native_fresh_owners
                 WHEN EXISTS(SELECT 1 FROM native_fresh_owners WHERE rowid = NEW.rowid AND NOT COALESCE(((length(original)=71 AND substr(original,1,7)='sha256:' AND substr(original,8) NOT GLOB '*[^0-9a-f]*'
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
                      OR (request IS NOT NULL AND request_digest IS NOT NULL))))) AND typeof(original) = 'text' AND typeof(attempt) = 'text' AND typeof(purpose) = 'text' AND typeof(human) = 'text' AND typeof(subject) = 'text' AND typeof(context) = 'text' AND typeof(owner) = 'text' AND typeof(created_at) = 'integer' AND typeof(expires_at) = 'integer' AND typeof(stage) = 'text' AND (request IS NULL OR typeof(request) = 'text') AND (request_digest IS NULL OR typeof(request_digest) = 'text') AND (result_digest IS NULL OR typeof(result_digest) = 'text')), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END;

INSERT INTO native_fresh_schema_version(version) VALUES(1);
