# Ramp vendor funds

`Ramp.create_fund(resource, amount_cents, interval)` issues a non-shareable, virtual-card-only USD fund for one Ramp user and one Ramp merchant. The app receives the fund ID. Finance chooses the owner, merchant, maximum amount and cadence in the resource grant. The `Total` cadence caps cumulative spend on that fund. `Monthly` resets its allowance each month. Ramp models these restrictions on the fund that backs card spending. [Ramp spend controls](https://docs.ramp.com/developer-api/v1/spend-controls)

## Resource and connection

The `ramp` connection pins the business UUID and a revisioned credential reference. Mount a current OAuth bearer with `business:read` and `funds:write`. The installation operates token issuance and rotation. For every create, Day2 reads `GET /developer/v1/business` and checks the returned business UUID before sending the fund request. Production uses the fixed origin `https://api.ramp.com`. [Ramp authorization](https://docs.ramp.com/developer-api/v1/authorization)

The `ramp_fund_policy` resource has a `profile` with `owner_id`, `merchant_id`, `max_amount_cents` and `interval` (`TOTAL` or `MONTHLY`). Use the Ramp merchant UUID recognized by card transactions. The fund schema calls the list `allowed_vendor_ids` and relates it to the Merchants resource. A finance reviewer must resolve the applicant's vendor name to that merchant. Each approved operation needs its ordinary Day2 authority, an attachment permitting `ramp.create_fund.v1` for the actor, and a two-call budget for the identity check and fund creation. The amount is a limit per issued fund. A workflow that permits one approval per intake request must also consume that approval atomically before dispatch. [Ramp Funds API specification](https://docs.ramp.com/openapi/developer-api.json)

## Receipts and uncertainty

Day2 sends one `POST /developer/v1/funds` with Ramp's documented `X-Idempotency-Key`, derived from the durable Day2 effect ID. A successful receipt requires HTTP 201 and the expected active fund, sole member, allowed merchant, virtual-only spend types, currency, amount and cadence. The receipt contains only `fund_id`. [Ramp Funds API](https://docs.ramp.com/developer-api/v1/api/funds)

A lost reply, a server failure or a malformed success can mean Ramp accepted the fund. A second dispatch for the same uncertain effect is blocked. Finance should check Ramp's fund inventory and controls before resolving the request. An unexpected restriction may require suspending a fund in Ramp. Creating another intake or approval starts a separate intent and can create a second fund.

The disposable driver stores seeded businesses, owners, merchants and funds in SQLite. Its deterministic scenarios cover credential business mismatches, resource limits, changed restrictions and a committed fund whose response is lost. Production rollout still needs a correctly scoped token, production merchant mapping and a qualification run against a provider-approved test account.
