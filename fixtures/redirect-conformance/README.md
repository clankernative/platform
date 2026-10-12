# Redirect Routes

This complete conformance fixture proves the platform's declared redirect routes
(see [WEB.md](../../docs/WEB.md#redirect-routes)): a GET path that runs one
command and answers `302 Found` with a field of its result. It is shaped like
GoLinks, the first user, but is not a copy of it: `shared/LinkNames.roc` is a
small model of GoLinks' exact-then-wildcard resolution.

- `pages/Redirects.roc` declares `/go/{path..}` and `/{path..}`, both bound to
  `go.visit`, with `url` as the location field, `AnyScheme` destinations and
  `missing_link` as the not-found failure. The prefixed route uses
  `on_not_found` to render the registered `/new` page with a prefilled create
  form; the bare route retains the platform error page as a compatibility check.
- `pages/Routes.roc` declares page routes at `/` and `/about`, which keep
  precedence over the redirect routes even when a link named `about` exists.
- `commands/visit/VisitLink.roc` resolves an active exact name, otherwise the
  active `name/%s` wildcard for all but the last segment, encodes the captured
  segment into the destination and counts the visit.
- `commands/create/CreateLink.roc` deliberately stores any nonempty destination,
  so the tests can prove that the host, not the application, refuses to redirect
  to `javascript:`.

`crates/day2/tests/redirect_routes.rs` serves it behind a test IAP verifier and
checks redirects, wildcard decoding and re-encoding, unknown and deleted links,
refused destinations, page and platform precedence, the command's own authority
grant, the mandatory audit, prefetch and non-navigation refusal, and admission
of malformed declarations. It also checks fallback-query authority, decoded
and escaped form values, unchanged API failures and creation via a signed POST
without JavaScript. Full verification builds the fixture and passes it as
`DAY2_TEST_REDIRECT_ARTIFACT`; to run it alone:

```text
cargo run --locked -q -p xtask -- build fixtures/redirect-conformance
DAY2_TEST_REDIRECT_ARTIFACT=artifacts/<printed digest> cargo test --locked -p day2 --test day2_integration -- redirect_routes::
```
