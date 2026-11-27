# Vendor intake

A member of the configured Google Group can propose a vendor allocation inside an existing department budget and a separate Ramp spending control. A directly authenticated, individually designated reviewer can approve the recorded terms or return the request with a note. The requester sees the status and reason under **My recent requests**. A returned request is final. The requester can submit corrected terms as a new request.

## Run locally

From a platform checkout with the Day2 CLI installed, start a disposable instance with synthetic settings.

```console
./cli/day2 platform local-dev examples/vendor-intake --actor ada@synthetic.example --example synthetic_intake
```

Open the printed login URL and go to `/_prototype/published`. The example uses the simulated Google Directory. Ada belongs to the product-owners group. Grace is its designated reviewer. The local CLI binds one actor to a disposable directory and requires a reset to switch actors. To exercise Ada and Grace on one database, use the HTTP fixture below. The native review queue is at `/review`.

The form accepts USD amounts with at most two decimal places. The command records integer cents, an independent cadence for each amount, the allocation start date, and the source department budget. For example, a one-time $2,400 allocation from the Design budget can have a $200 monthly Ramp limit. The department total changes by $0. The proposed Ramp fund is merchant-restricted and virtual-card-only. Finance resolves the vendor’s Ramp merchant and the fund owner before applying it.

If a contract exists, the requester places it in the displayed folder and supplies a Google Drive file link. The form accepts links copied from Drive and removes sharing parameters. API clients submit the canonical `https://drive.google.com/file/d/<id>/view` shape. To approve such a request, the reviewer must open the file, check its actual folder in Drive, and explicitly confirm that check. The stored confirmation is the reviewer's attestation. The application does not inspect or move files.

## Configure an installation

Before accepting requests, a directly signed-in Day2 app owner calls `vendorintake.configure` once with the installation's private settings. The owner needs an active operation grant. This command requires no provider credentials. The example below illustrates the JSON format with synthetic values.

```json
{
  "product_owners": "product-owners@synthetic.example",
  "reviewer": "grace@synthetic.example",
  "contract_folder": "https://drive.google.com/drive/folders/synthetic_vendor_contracts"
}
```

```console
day2 call vendorintake.configure --input-file private-settings.json --idempotency-key configure-vendor-intake
```

The command confirms identical settings on retry and rejects replacements. Keep the real settings file in the installation's private configuration. A production installation also needs an operator-approved `google_workspace` binding with the `google_workspace.group_member.v1` action on its Google Directory connection, scoped to the intended callers and domain. Membership is observed at submission time using the authenticated actor. The form never chooses the group, reviewer or requester.

The review queue shows each pending submission to the configured reviewer. The native detail form binds the decision to that immutable request number. The command refuses a second decision, a delegated reviewer, missing notes and inconsistent contract confirmation. The application records the financial proposal and the human decision in local storage. Applying a Spend allocation or a Ramp control is a separate step.

## Iterate and publish

An owner opens `/_prototype/published`, edits the HTML and chooses **Save & preview**. The new revision's URL opens exactly those bytes under the viewer's own Day2 authority. The sandbox accepts one no-input read, `day2.call("my_requests")`, and one user-initiated submission, `day2.submit("submit_request", fields)`. The platform asks for confirmation before dispatching the typed command. Reviewing and installation configuration use ordinary Day2 routes outside the authored frame.

From a pinned revision, an owner can use its source download link and take the exported application through ordinary source review, CI and deployment. Both wrappers use the `vendorintake` namespace so its native review form has the same command binding. Use a separate installation for a concurrently running published copy. A newly provisioned copy needs its own private configuration and provider grant. The published wrapper includes the intake, review and configuration operations. Draft authoring routes belong to the prototype installation.

## Verify requester and reviewer access

Run the native campaign with `./cli/day2 platform check examples/vendor-intake 42 4`. Set `ARTIFACT_ID` to the hash printed by the check, then run the HTTP fixture against the admitted artifact.

```console
bazel build //crates/day2:day2_integration
DAY2_TEST_VENDOR_INTAKE_ARTIFACT="$PWD/artifacts/$ARTIFACT_ID" bazel-bin/crates/day2/day2_integration vendor_intake_prototype:: --nocapture
```

The fixture starts separate authenticated requester and reviewer sessions on one disposable database, backed by simulated Google Directory.
