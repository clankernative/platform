# Bounded query and reporting design

Queries must preserve row authority, stable ordering, explicit bounds and complete
verification. A bounded page is not proof that all matching rows were visited.
Aggregations and derived projections need independent reference checks and an
explicit repair contract before being used for authoritative decisions.

See [data queries](DATA-QUERIES.md), [storage indexes](STORAGE-INDEXES.md), and
[the collection fixture](../fixtures/collection-conformance/README.md) for the
implemented public contracts. Company reporting designs and app migration
assessments belong in downstream private repositories.
