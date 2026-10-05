# Direct app ownership

This is the ownership receiver for the Notifications configuration flow. The
checked `app_ownership.check` export accepts only a business `app_id`. It reads
the inherited `Context.actor()` and returns `{ app_id, allowed }`; callers cannot
choose a human or grant ownership through the import.

`set_owner` manages one unique app/principal assignment. It is deliberately not
exported. An installation must restrict that command to ownership administrators;
ordinary app users receive only `check`. Its business lookup always uses the
inherited principal and exposes no assignment list. The assignment table needs
`rows=all`: its `principal` is the managed subject, not the native row owner.
Marking it `owner_or_admin` would forbid an administrator creating an assignment
for another person under the platform's immutable ownership rules.
Revocation retains the assignment with `active=false`. There is no decision cache.

This ports the direct-user branch of
`InternalToolsControlPlane.Application/Handlers/AppOwnershipAuthorizationService.fs`
at source revision `62f8ab14d8463c4c7bd1d68628b656e0898a9bc0`. Principals here are
canonical host identities rather than user-supplied email strings. Organization
administrator override and Google Group ownership are not implemented or accepted
as assignment types. Add their actual directory-backed policy when required;
missing group membership must never become a positive ownership decision.

The app owns these business rows. The instance owns administrator identities,
operation/row policy and the caller's imported resource grant. The platform owns
authentication, delegation proofs and serving fences.
