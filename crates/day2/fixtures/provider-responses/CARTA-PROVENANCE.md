# Carta wire fixtures

These are **reconstructed** shapes, not provider recordings. They were written
by hand from the response DTOs of the Equity application's production Carta
client (`nexusbird-equity`, `src/Equity.Api/src/Types.fs` and `Carta.fs` at
commit `264b7039ebb25222ccc03897d40c0543b760bc5c`), which deserialized live
responses from `POST /o/access_token/`, `GET /v1alpha1/issuers/{id}/stakeholders`
and `GET /v1alpha1/issuers/{id}/optionGrants`. Field names, nesting, the
`{"value": ...}` wrappers, optionality and the `nextPageToken` envelope follow
those DTOs. Every value is invented: identifiers, names, addresses, dates,
quantities and the access token are examples. Nothing was copied from a
response, and no Carta documentation page was fetched for them.

They are external to this adapter and its simulation, so they can establish
the claim "the pipeline accepts the shape the inspected client relied on". They
cannot establish what Carta actually sends: whether empty arrays, empty strings
or false booleans are omitted, which fields are null, whether a terminal page
repeats or omits its token, or what the playground origin returns. Replace each
file with a redacted playground recording during qualification
(`xtask carta-qualify`), keeping field names, nesting, `null`/absent forms and
token presence exactly as recorded, and update this file with the date, the
environment and the redactions.
