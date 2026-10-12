# Row Authority Through HTTP

This complete conformance fixture proves host-enforced row ownership and stale-edit rejection
through ordinary HTML forms and Datastar responses. It uses links as sample data;
it is not a customer application or a completed GoLinks migration.

`storage/Models.roc` includes required ownership from the first schema. No existing app
database is reset or modified; adding ownership to existing Links data still
requires an explicit backfill and migration design.

The handler in `commands/edit/EditLink.roc` deliberately has no edit authorization or caller-version check.
It reloads the row and writes a new title. The company-owned authority policy in
the HTTP test instance must independently enforce actor ownership or explicit
administrator authority, immutable owner/destination fields, the caller's
expected version, and title constraints inside the transaction.

`ui/pages/` owns the HTML. The host signs hidden target/version fields, adds CSRF
and invocation identity, and handles native POST/redirect and Datastar patches.
No custom browser JavaScript is needed for this fixture; it uses the same pinned
Datastar transport as other apps. This adds no browser isolation guarantee.

A stale edit displays the current stored title and a conflict notice. It does
not silently attach the old draft to a fresh version ticket; explicit draft
comparison and conflict resolution remain separate UI work.

Run through the platform verifier, or set `DAY2_TEST_OWNED_ARTIFACT` to a built
artifact and run `cargo test --locked -p day2 --test day2_integration -- owned_web::`. These are real
HTTP protocol tests, not browser rendering or interaction certification.

The HTTP tests provision isolated instances with the explicit
[`owned-links.json`](../authority-policies/owned-links.json) policy and exercise
`alice`, `bob`, `admin`, and `viewer` through independent authenticated sessions.
For an interactive authoring example, use Reports through
[managed local development](../../ops/LOCAL-DEVELOPMENT.md).
