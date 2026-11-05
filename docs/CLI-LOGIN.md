# Human CLI login bootstrap

The standalone Rust CLI uses the existing Google IAP human identity channel.
It needs company-owned public metadata before starting desktop OAuth. A company
may opt in by selecting `identity.cli_desktop_client` in its canonical
instance document. This complete Google **Desktop app** registration contains
`client_id` and `client_secret`. Google requires the latter during exchange and
refresh even with PKCE, while treating Desktop apps as public clients that
cannot keep registration secrets confidential. The company must explicitly
approve publishing this pair. It proves neither identity nor app authority.
Never supply a confidential Web application secret, service-account key or
user token. See [Google's Desktop OAuth contract](https://developers.google.com/identity/protocols/oauth2/native-app).

For an opted-in edge app, the native host answers only anonymous
`GET /.well-known/day2-cli.json`, with no query or body. The response contains
exactly `schema_version: 1`, that app's `instance_origin`, `installation`,
`environment` and `identity` with `scheme`, `desktop_client`, `hosted_domain`.
The registration contains exactly its bounded `client_id` and `client_secret`;
partial pairs and unknown fields fail admission. The registration value is
16–256 ASCII letters, digits, hyphens or underscores.
It contains no backend audience, readers, writers, resource catalog, provider
connections, user tokens, confidential secrets or artifact paths. It creates no session, sets no cookie,
disables caching and uses the normal exact Host and method-override guards.
HEAD and write methods are refused. Other paths keep their ordinary admission.

The selection is admitted when the edge listener starts and checked again when
serving the metadata. A changed or removed registration, origin, scope, domain or IAP audience
fails closed until the listener restarts with the new reviewed selection.
Absent configuration adds no anonymous route; development sign-in never
publishes this document. This is instance configuration, not app-owned content
or another application operation catalog.

## GKE composition

Set `cli_desktop_client` to the complete object on the selected `app-edge` stack **after** resolving
its ordinary human IAP backend. With the default null value, no CLI resources
or extra contract key are created. Opting in:

- Selects the one client in backend-scoped `google_iap_settings.cli_login`.
  This stack then owns that backend's programmatic-client allowlist. Before
  adopting existing settings, inspect the complete current IAP settings and
  review/import their desired ownership; never erase another client's access
  or other settings accidentally. This does not change project/organization
  defaults, human IAM membership or app authority.
- Creates a `cli-discovery` Service/BackendConfig without IAP and routes only
  the exact discovery path to it. The default backend and all other human
  routes retain IAP. Runtime admission independently refuses those routes
  without signed assertions, including requests reaching the pod directly.
- Publishes the pair as JSON in `CLI_DESKTOP_CLIENT` in the platform contract. `day2-app` takes
  this one selection into `identity.cli_desktop_client`; it has no separate
  workload override or company-specific artifact bytes.

The client registration and consent audience belong to the company. Existing
web OAuth clients for security reauthentication or provider connections have
different roles. Use the company's protected infrastructure plan/review/apply
process to enable the metadata and IAP allowlist. Keep company values out of
the public platform and CLI repositories.

## Qualification boundary

Native HTTP tests cover exact public projection, no session/cookie side effects,
disabled configuration, methods, hosts, queries/bodies, adjacent protected
routes, malformed fields and live metadata replacement. Mocked infrastructure
plans cover default absence, backend-scoped client selection, the exact public
path and runtime contract composition. These tests do not qualify a Google
OAuth registration, Google-managed IAP mode, cloud routing or an OS credential
store. A live company canary must prove browser callback, signed Google desktop
identity, IAP/app authorization, session binding, refresh and logout before
claiming CLI login works for that deployment.
