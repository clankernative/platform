# Complete collection conformance

Native regression fixture for `Query.collect` and `Tx.collect`. The integration
test supplies independent expected rows, mixed owners and buckets, more than two
pages, real continuation cursors, invalid bounds and overflow. An update before
collection proves that failure rolls back both the row revision and audit changes.

The query is typed as `Query(EntryView.Result)` and the update as `Tx(EntryView.Result)`.
Both deliberately pass a one-row paginated selection with a caller cursor; complete
collection must restart at the beginning with the maximum page size while retaining
the predicate and descending order. Platform capacity errors are not app failures.
The exact ordered field projection uses compact delimited tokens with delimiter-free
fixture values, keeping even 256 rows below the existing output string byte bound.

Build this fixture through the existing app build recipe and set
`DAY2_TEST_COLLECTION_ARTIFACT` for `cargo test --locked -p day2 --test day2_integration -- collection::`.
