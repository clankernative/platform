# Optional Firestore security authority resources

This opt-in root prepares a dedicated Firestore Native database for one app's
shared Credentials security authority. The private instance owns the project,
database name/location, app scope, backend and identities. It is separate from
the [core GKE roots](../../gke/README.md) and initializes no counter or app data.

The root creates:

- One Standard Native database with deletion protection and OpenTofu
  `prevent_destroy`, outside the app's SQLite volume and backup.
- A reader custom role for the existing app GSA: database metadata,
  transactions and document reads.
- A distinct controller GSA with a custom role adding document create/update.
- Two additive project IAM members, conditioned on the exact database name.
- The Firestore API selection, retained if this root stops managing it.

There is no controller workload, KSA binding, token mint/signing grant, secret,
control journal, backup/restore operation or native readiness factory here.
The new GSA's actual effective impersonators must be checked before use.

## Instance selection

Select this root explicitly in the private instance's root mapping and use a
separate GCS backend prefix. Supply all six inputs:

```hcl
project_id  = "example-tools"
location    = "us-central1"
database_id = "calendar-authority"
authority_scope = {
  installation = "example"
  environment  = "staging"
  app          = "calendar"
}
app_reader_service_account    = "calendar-app@example-tools.iam.gserviceaccount.com"
controller_service_account_id = "epoch-controller"
```

These are illustrative values. Prepare and review a saved plan before applying
the instance's actual selection. The mocked tests do not call GCP.

After an authorized apply, `resource_facts` exposes provider metadata including
the system-generated database UID and both immutable GSA IDs. These outputs
are data. The native adapter must authenticate and recheck the actual selected
resource, identity and current acquisition budget before creating a proof.
Do not copy mocked UIDs, an epoch value or a `ready` flag into serving inputs.

The canonical instance still owns `control.security_epochs`: select the app's
reader GSA there, record the actual database UID, and derive the complete key-set
digest and binding revision through the current native instance loader.
Controller policy and execution evidence are distinct from that access selector.
There is one shared counter per selected app authority scope; OAuth does not get
a second counter. Existing records are not adopted by ordinary app startup.

## Permission boundaries

The fixed reader permissions are `datastore.databases.getMetadata`,
`datastore.databases.get` and `datastore.entities.get`. The controller adds
`datastore.entities.create` and `datastore.entities.update`. The root grants no
entity delete/list, database administration, import/export, clone or restore
permission. The API's distinction between metadata reads and transaction
permission is documented in [Firestore IAM](https://docs.cloud.google.com/firestore/native/docs/security/iam).

The [database IAM condition](https://docs.cloud.google.com/firestore/native/docs/manage-databases#configure_per-database_access_permissions)
matches a reusable database **name**, not its immutable UID or a document path.
It is enforced for REST/client access; Google Cloud console access does not
respect database conditions. Other inherited grants can also authorize access.
Effective IAM, impersonation paths and console/operator governance therefore
need separate live qualification. Declaring this reader grant does not prove
that the app has no other write authority.

IAM permits ordinary create/update, without enforcing a conditional write or
an accepted kernel transition. The native controller must enforce exact policy,
separate consuming stage permits, permanent same-request reservation,
conditional multi-record commits and response-loss reconciliation. Transaction
permission itself does not force read-only mode.

Deletion protection prevents database deletion; it does not prevent privileged
record mutation or rollback. Disabling PITR here does not remove Firestore's
historical read window. This root establishes no clock, journal linearizability,
first-holder activation, arbitrary SQLite rollback safety or production readiness.
Those require the separately qualified native producers and explicit fresh
canary activation. Preserve GoLinks' persisted links when redeploying OAuth
canaries.
