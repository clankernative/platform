# Operation Audiences

This source overlay proves that declared operation audiences and a declared row
owner reach an admitted artifact. It replaces four files in a staged copy of
[row-authority-web-conformance](../row-authority-web-conformance/README.md):

- `queries/detail/GetLink.roc` declares `audience: Owners`. It is the only
  operation of the `details` page, so that page serves the app's owners.
- `commands/create/CreateLink.roc` declares `audience: Closed`.
- `commands/edit/EditLink.roc` keeps `audience: Employees` and declares
  `.any_owner(Data.links)`.
- `storage/Models.roc` declares `owned_by: Table.owner({ owner: row.owner })` on
  `Link`. That is authority metadata only: no index, and the schema digest of the
  base fixture is unchanged.

`list` keeps the base fixture's `audience: Employees`.

Full verification builds it as the `audiences` fixture. The `app_contract` test
`admitted_audiences_and_row_owner_reach_the_artifact_and_pages_refuse_mixtures`
reads it through `DAY2_TEST_AUDIENCES_ARTIFACT`. It checks the admitted audiences
owner column and `edit`'s exemption as a positive control, then refuses
in-memory variants of the same contract: a page whose preparation command
declares another audience, a public operation with no audience, a page whose
preparation command is internal, and an internal command that declares one.

The audiences do not change this fixture's authority. Its tests still use the
explicit policies in [authority-policies](../authority-policies/); rendering a
company policy from audiences is separate platform work.
