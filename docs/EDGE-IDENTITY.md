# Edge identity

In production, people reach applications through Google IAP. IAP runs the
Google sign-in and attaches a signed assertion to every request it forwards. The
platform verifies that assertion on every request and takes the person's
identity from it. There is no sign-in page, no login link and no actor argument
at the edge.

This is the only production sign-in the platform has. The development sign-in
link, the printed one-use URL in `LocalServer::bind` and `day2-serve
--development-auth`, stays loopback-only and is refused for any installation
that declares an identity provider.

## What the operator declares

The identity provider belongs to the installation, and each app declares only
its own address:

```json
{
  "installation": "exampleco",
  "environment": "production",
  "identity": { "scheme": "google_iap", "hosted_domain": "example.com" },
  "apps": {
    "go": {
      "edge": {
        "origin": "https://links.example.com",
        "iap_audience": "/projects/123456789/global/backendServices/987654321"
      }
    }
  }
}
```

- **`identity` is declared per installation, not per app.** A company signs in
  with one identity provider and one domain. If each app could choose, each app
  would be choosing who can reach it. Apps have no setting that widens the
  domain or switches the scheme.
- **`hosted_domain` is checked twice.** The assertion's `hd` claim must name it,
  and the address must end in `@` followed by it. The second check catches a
  consumer account that was added to an IAP access list by mistake.
- **`origin` is `https://<host>`, lowercase, with no port or path.** It is the
  exact `Origin` a browser sends and the exact `Host` every request has to name.
- **`iap_audience` is the backend service IAP signs for.** An assertion IAP
  issued for another app is genuine and correctly signed, but it is not for this
  app. So two apps may not share an audience, and two apps may not share an
  origin.
- **An `edge` needs an `identity`.** Without one, the edge would have nothing to
  check requests against and would trust whoever reached it.

The container is started as `day2-serve INSTANCE APP --edge`. Which form a
container may use is set by its instance, not by its arguments:

- `--edge` needs `identity` and this app's `edge`.
- `--development-auth` is refused when `identity` is present.
- Exporting the development compose bundle is refused when `identity` is
  present.

No combination of flags serves an IAP installation without IAP.

## What a request goes through

In order, before any route is chosen:

1. **Exactly one `x-goog-iap-jwt-assertion` header.** A missing header or two of
   them is refused.
2. **ES256 only.** IAP signs with ES256 and publishes only EC keys. `none`,
   HMAC and RSA are all refused.
3. **The signature**, checked with a key from
   `https://www.gstatic.com/iap/verify/public_key-jwk`. Claims are read only
   after the signature has been checked.
4. **Issuer** `https://cloud.google.com/iap`, the **audience** exactly as
   declared, **expiry** with two minutes' skew, and a **subject**.
5. **The address**, trimmed and lowercased. A `*.gserviceaccount.com` address is
   refused with `machine_caller_requires_delegation`, because a service account
   has no person behind it. Machine callers use the delegation protocol.
6. **The hosted domain**, as described above.
7. **The subject binding** (see below).
8. **The app's own policy.** The person must be allowed at least one thing by
   this app, by name or through a `domain:<hosted_domain>` entry (see below).
   Otherwise the request is refused as `forbidden` and no session is created.

When every check passes, the request is from that person. It reaches Roc as
`context.actor()`, acting directly, with authentication `Request`. The audit
record carries the person as both `actor` and `initiator`. On-behalf-of works as
it does anywhere else (see [WEB.md](WEB.md)): the verified person is the
authenticated principal, and the header names the effective one.

Refusals are reported with as much detail as the person can act on and no more:

| Code | Status | Meaning |
| --- | --- | --- |
| `invalid_identity_assertion` | 401 | Missing, malformed, forged, expired, for another app, or outside the domain. These are deliberately not told apart. |
| `machine_caller_requires_delegation` | 403 | A service account came in at the human front door. |
| `principal_subject_changed` | 403 | The address now belongs to a different account (see below). |
| `forbidden` | 403 | A real colleague that this app does not admit. |
| `identity_keys_unavailable` | 503 | Keys could not be fetched and none were cached. |

`/health/live` and `/health/ready` need no assertion, because the load
balancer's health checks do not carry one. Inbound provider deliveries under
`/_ingress/` need no assertion either. They come from a provider, not a person,
and their own signature establishes them (see [INGRESS-PLAN.md](INGRESS-PLAN.md)).
`/login` does not exist at the edge.

## Admitting the whole domain

Because every edge request has had its `hd` claim and its address checked
against `hosted_domain`, an app may admit everyone there without naming them:
`"readers": ["domain:example.com"]`, and the same entry in an operation's
`actors`. The entry must name exactly this installation's `hosted_domain`; an
instance without an identity provider cannot use one at all. It matches only a
lowercase address with a single `@` followed by exactly that domain, never a
subdomain, a lookalike, an `app:`/`svc:` principal or a service account (which
step 5 has already refused). The person is still themselves: the session, the
invocation, row ownership and the audit all carry their verified address, never
the entry. `admins` and delegation rules still name people. See
[AUTHORITY.md](AUTHORITY.md#everyone-at-the-verified-domain).

## Sessions are not sign-in

The edge still issues a session cookie, because CSRF tokens are tied to a
session. The cookie never stands in for the assertion:

- A request with a live session and no assertion is refused.
- A session is reused only if it belongs to the person the assertion names. A
  cookie left in a shared browser by someone else is ignored, and a new session
  is issued.
- The cookie is `__Host-`-prefixed, `Secure`, `HttpOnly` and `SameSite=Strict`.
  Nothing on a sibling subdomain can set it, read it or shadow it.

Signing out deletes the session and redirects to
`/?gcp-iap-mode=CLEAR_LOGIN_COOKIE`. IAP clears its own sign-in when it sees that
path. Dropping only this app's session would sign the person straight back in on
their next request.

## Subject binding

An address is not a person. When someone leaves and their address is later given
to a new hire, IAP signs the new hire's assertions with the old address and a new
Google subject. If the platform admitted people by address alone, the new hire
would inherit the old owner's grants, reader and writer entries, row ownership
and audit trail.

Host schema 9 adds `day2_principals(email, subject, first_seen)`. The first
subject seen for an address is recorded, and every later request must present
that same subject. A different subject is refused with
`principal_subject_changed` until an operator decides the address has changed
hands. The rebind command does not exist yet. Until it does, a rebind is a
manual row change made by an operator who has decided the change is legitimate.

The table is per app, like every other piece of host state. Someone first seen
by GoLinks and later by another app is bound in each app separately.

## Keys

Keys are cached for an hour. A key id the cache does not know triggers a refresh
straight away, so a key rotation does not cause an hour of refusals. Refreshes
happen at most once a minute, however many unknown key ids arrive. Otherwise an
attacker could send a stream of assertions with made-up key ids and turn it into
a stream of requests to Google. If a refresh fails while stale keys are cached,
the stale keys keep verifying, since Google has not retired them yet. If a
refresh fails with no keys cached, every request is refused with
`identity_keys_unavailable` (fail closed).

## Compared with the existing fleet

Company-specific identity migrations belong in the private instance repository.

## Not yet built

- **Machine callers.** The control plane's app-to-app delegation token
  (`X-Internal-Tools-Delegation`) is the next layer. Until it lands, v1 apps and
  the agent gateway cannot call a v2 app. They get
  `machine_caller_requires_delegation`, not a silent pass.
- **The operator rebind command** for `principal_subject_changed`.
- **Other schemes.** `scheme` is an enum so that a second provider would be a
  new variant, not a new set of per-app flags.
