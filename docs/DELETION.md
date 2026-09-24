# Deletion

The platform has no hard delete. An application can mark a row deleted and it
can bring it back; nothing an application can say removes a row from the
database. Physical removal is an operator decision expressed as instance
retention policy, never a line of app code.

This is deliberately an unreasonable rule. The alternative — soft delete as a
convention each app re-implements with an `is_deleted` column — fails the same
way every time: one query forgets the filter and deleted rows come back as
live, or one handler issues a real `DELETE` and the record is now a problem for
whoever can read an audit log at 2am. Making deletion a platform state removes
both failures from the space of things an application can do.

## What an application can say

```roc
import pf.Tx
import pf.Selection
import Data

archive = |row| Tx.soft_delete(Data.tickets, row)
unarchive = |row| Tx.restore(Data.tickets, row)

trash = Query.page(Selection.only_deleted(Selection.all(Data.tickets, after, limit)))
```

`Tx.soft_delete` and `Tx.restore` carry no value, so neither can smuggle an
edit past the effect declaration. Both take the observed row and its version,
so both lose to a concurrent write like any other change. Deleting an
already-deleted row fails with `row_already_deleted` and restoring a live one
fails with `row_not_deleted`: a no-op here means the caller is working from a
stale view, and silently bumping the version would hide that.

An operation declares `soft_delete` in its effects. That one declaration also
permits `restore` — an app allowed to delete a row must be able to undo it,
since the reverse asymmetry leaves an app able to break something it cannot
repair.

## What a deleted row does

A deleted row is invisible to every read that does not name it:

| Read | Sees a deleted row |
| --- | --- |
| `Query.get` / `Tx.get` by id | no — `not_found` |
| any selection, page, or `find` | no |
| `Selection.including_deleted` | yes, alongside live rows |
| `Selection.only_deleted` | only deleted rows |
| `Tx.update` | no — restore it first |

Exclusion is the default everywhere, and it is not something an application
does — there is no filter to forget. The worst mistake available is a trash
screen that shows nothing, which is visible and harmless. The reverse default
would put deleted work back in front of people silently.

`Model.Entity` carries no deletion field, and `Row` carries none on the wire.
That is what `only_deleted` is for: a caller building a trash view knows every
row it got back is deleted rather than reading a flag off each one. It also
keeps the field out of every operation's `outputs:` documentation, which is
what a flag on `Entity` would have cost across the fleet.

## Why a row was deleted

There is nowhere on the row to record it, and that is on purpose: a reason
column is a field like any other, editable afterwards by anything that can
update the model. The reason belongs to the act, not the record — it travels as
the deleting command's input, which the audit log keeps with the actor, the
time and the invocation. `Tx.soft_delete` carries no payload for the same
reason `Tx.update` cannot be smuggled through it.

## Storage

Every application table carries `deleted_at INTEGER NOT NULL DEFAULT 0`, a
host-owned column beside `id`, `version` and `created_at`. Zero means live; any
other value is the instant of deletion. Applications cannot declare a field
with that name, read it, or write it — deleting sets it, restoring clears it,
and both bump `version`.

Host schema 5 adds the column to instances created before it existed. The
migration discovers tables from `sqlite_master` rather than from the artifact,
because an instance can hold tables the current schema no longer names, and
uses `ALTER TABLE ADD COLUMN` with a default, which SQLite applies as a
metadata-only change.

## Two invariants

**Uniqueness spans deleted rows.** A unique index is generated without any
reference to `deleted_at`, so a deleted row keeps its unique value. If deletion
released the name, someone else could claim it and the original could never be
restored — deletion would become a way to lose a record by having a second one
take its place. Pinned statically in `schema.rs` (`deletion_invariants`) and
behaviourally in `store.rs`.

**Secrets never live in rows.** Since nothing is ever removed, a secret written
into a row is a secret the platform will keep forever. Schema construction
refuses field names that read as secret material; credentials belong in
resources, which have their own lifecycle. See
[RUNTIME-SECRET-LIFECYCLE.md](RUNTIME-SECRET-LIFECYCLE.md).

## What is an operator's decision

Removal, and only removal, and it is declared in the instance:

```json
"apps": {
  "support": {
    "retention": {
      "tickets": { "after_days": 90, "reason": "closed tickets are kept for a quarter" }
    }
  }
}
```

Empty — the default — means nothing is ever removed. There is no default
window, because a platform with one would be deleting data for operators who
never asked. `after_days` must be at least one: a window of zero is a hard
delete wearing a policy's clothes, so it is refused when the instance loads
rather than honoured. The reason is required, because it is the only part of a
removal that cannot be reconstructed afterwards — the row will be gone, and
what is left is that somebody decided it should be, and why.

Running it is two acts, not one:

```
day2-ops resource-admin-operation --action retention-plan  --app support
day2-ops resource-admin-operation --action retention-sweep --app support --input-file plan.json
```

`retention-plan` reports, per model, how many rows are eligible and the oldest
and newest deletion instants among them. `retention-sweep` is handed that plan
back, recomputes it inside the transaction that does the removing, and refuses
with `retention_plan_changed` if anything differs — a row deleted or restored
in between, or a different clock. An operator removes what they reviewed or
nothing at all. Both require an installation administrator.

Three properties hold whatever the policy says:

- **A row nobody deleted is never eligible.** `deleted_at != 0` is written once
  and used by the plan, the record and the deletion alike, so the count an
  operator reads and the rows destroyed cannot disagree.
- **Every removal is recorded, and the record outlives the row.**
  `day2_retention_removals` keeps the model, the application's own id, when the
  row was created, when it was deleted, under which window and by whom — and no
  field values, because a record of a removal that quoted the row would keep
  the data the removal was for. It is append-only: the entry cannot be edited
  or dropped, which is what stops a removal becoming deniable.
- **Removals reach the audit stream** as `kind='retention'`, beside invocations
  and web requests. An act that destroys data is the last thing that should
  require knowing which table to query.

This is also the one place a unique value is released. A deleted row keeps its
name so it can be restored into it; a removed row does not exist, so the name
is free. That is a consequence of removal being real, and it is the reason the
window exists.

Object retention is not built. The bytes an operator would reclaim are the ones
no live row points at, and finding them needs a list capability the object
store provider does not have yet.

## Objects

The same rule, one layer down. An application cannot destroy bytes in an object
store, and it cannot do it either of the two available ways.

**Deletion.** There is no `delete` in the `ObjectStore` contract. The registry
declares `object_store.delete.v1` as *destroying* — a third mode beside read and
write — and `resources::authorize` refuses every destroying action, so a grant
that names it still cannot be used to reach it. The refusal is in the host, not
only the SDK, so the answer is the same for an artifact built before the rule.
Staging refuses to build an SDK package whose app-exported modules name a
destroying capability, which is what stops one growing back.

**Overwrite.** An upload aimed at an existing key replaces it silently: no
version, no audit entry that reads as a removal, nothing to restore from. So the
application no longer chooses the object. `ObjectStore.grant_upload` takes the
key as a *request*; the host inserts a segment of its own right after the grant
prefix and returns the real key in the authorization. `uploads/evidence.pdf`
becomes `uploads/<32 hex>/evidence.pdf`. Overwriting is not prevented by a check
that races — it stops being expressible.

The segment is derived from the effect's identity, which already encodes the
invocation and the effect's position in it, so a replay produces the same key
and a retry of the same effect targets the same object rather than scattering
copies. Two upload grants in one invocation are two effects, so they get two
objects. An upload grant that cannot say which effect it is refuses rather than
minting a key twice.

The cost is real and deliberate: an application that uploads the wrong file
cannot clean it up, and a new avatar does not reclaim the old one's space. Both
are storage, which an operator's retention policy can reclaim. Neither is data
loss, which it cannot.

Four apps in
[RESOURCE-INTEGRATION-INVENTORY.md](RESOURCE-INTEGRATION-INVENTORY.md) — Gateway,
Insanity, Video Composer and WSB — list object overwrite and delete among the
operations they perform today. They are the test of whether this rule survives
contact with the fleet. The expected answer for each is the same: the row that
points at the object is soft-deleted, the new object is a new key, and the bytes
go when retention says so, not when an app does.

See [RESOURCE-AUTHORITY.md](RESOURCE-AUTHORITY.md) for how grants are scoped.
