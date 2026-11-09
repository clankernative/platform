# Owner-authorized business SQLite export

`GET /api/app-sqlite` returns current owner-authorized scope, actor, authority,
admitted artifact and the 16 MiB size bound. `POST /api/app-sqlite` requires the
same human app session, exact Origin, CSRF token, JSON `expected_authority` and a
new `Idempotency-Key`. There is no operator assertion, arbitrary database path,
SQL, table selector or managed-client fallback.

Admission commits a metadata-only audit event before capture. A single runtime
read transaction checks ownership and captures all admitted business model
columns, including soft-deleted rows, into a newly created private SQLite
database. The target is an exclusive mode-0600 temporary file in a mode-0700
directory; only captured model rows reach it. The source connection never
escapes its callback, and output construction/file reads occur outside it. The
target schema comes from the admitted contract, without runtime indexes or
rollups. Explicit column projections and fresh pages exclude framework
sessions, OAuth/credential stores, provider metadata, audit/replay records,
freelist pages and unrelated schema. Source pages are never copied. SQLite
constraints, foreign keys and integrity are checked on the result.

The operation allows at most 100,000 rows and 16 MiB of value bytes/output pages;
SQLite also enforces its target page bound. Failure refuses the whole export.
The final writer transaction rechecks current authority and ownership before
recording preparation and returning bytes. Preparation is not evidence that a
client received them. Restored/disabled owner grants cannot authorize export.

Responses use `application/octet-stream`, `Cache-Control: no-store`, and base64
`X-Day2-Result` metadata binding actor, scope, request, authority and artifact.
The CLI validates that binding and writes a new mode-0600 file exclusively.
This is a debugging export, not a restorable platform backup. Historical backup
selection, restore, arbitrary queries and app import remain separate work.

The access audit is installed at fresh initialization with append-only triggers.
Missing/tampered guards fail closed. There is no automatic schema migration;
recreate disposable canaries and preserve GoLinks persisted links.
