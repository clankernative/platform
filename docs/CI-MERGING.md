# GitHub merge queue

This repository's GitHub instance uses a merge queue for `main`. GitHub constructs
a candidate from current `main` and queued changes, then runs the existing
required Platform CI checks on that candidate. Authors do not need to update a
PR branch just because another PR merged. Actual conflicts still need resolution.
Git host and merge policy remain instance-owned choices.

After a PR satisfies the existing checks and review rules, use **Merge when
ready** / **Add to merge queue** on GitHub. The queue merges successful candidates
using squash commits. Adding a PR to the queue authorizes its automatic merge
when the required candidate checks pass.

`.github/workflows/ci.yml` handles `merge_group: checks_requested` alongside PR,
main push and manual events. Every event runs the same required jobs. Checkout
uses the event's commit, so queue checks validate the generated candidate rather
than the PR head. Workflow concurrency is scoped by `github.ref`, keeping queue,
PR and main runs separate. No verification recipe step is skipped for the queue.

`.github/merge-queue.json` defines an additional `main` ruleset with no bypasses.
It allows one candidate build at a time, requires every candidate to pass, and
merges one PR at a time without a batching wait. The six-hour check response
timeout matches the full verification job's timeout. Existing required checks,
reviews, signature rules, conversation resolution and linear history continue
to apply. `.github/branch-protection.json` keeps
`required_status_checks.strict` false so branches need no manual update.

For initial setup, first land the workflow change on `main` with all required
checks passing; then create the additional ruleset from
`.github/merge-queue.json`. Preserve existing protection and review rulesets.
When updating an existing queue ruleset, use its ID instead of creating a second
one. Confirm the effective `main` rules include the queue and that all required
checks remain configured. Retain the first actual `merge_group` run as evidence
of the candidate checkout and required check results.

The queue automates integration checks; it does not shorten individual jobs.
PR checks, candidate checks and post-merge main checks still run. Starting with
one candidate build limits simultaneous native preparation and runtime work.
Do not treat cache hits or passing PR checks as a substitute for candidate checks.

References: [GitHub merge queue configuration](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue),
[merge group workflow event](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#merge_group).
