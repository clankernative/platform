# Verification setup conformance

This app exercises operation-owned verification preparation using the canonical
application layout. `b_read` declares `prepare_first` followed by
`prepare_second`; `prepare_second` declares `prepare_first`. Each setup is an
ordinary registered command with its own contract and verification callback.

The actor-keyed `ActorState` model is bounded to stages zero through two.
`a_invalidate` resets an actor to stage zero, making the positive read depend on
both setup operations. `b_read` is read-only and only succeeds at stage two.
`configure_failure` is an ordinary public command that changes only the actor's
`fail_second` flag, allowing native tests to configure a declared setup failure
without bypassing the app. `SetupInvariants` independently checks the model's
stage bound. The operation error cases use synthetic unprepared principals so
negative verification cases remain negative rather than being automatically
prepared.

The fixture has no pages, UI, external providers, or live I/O. Its integration
campaign uses the native development verification path and checks that setup
steps are recorded, checked, replayed, and counted separately from ordinary
positive obligations.
