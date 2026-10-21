# Reactive Query Search

This is a presentation source overlay, not a separate application. The build stages
the public `examples/reports` app and overlays a read-only `search` query, its
`/search` page and a link to it from the directory. Root registry, nominal models,
commands and codecs are unchanged, so the canonical Reports contract stays fixed
while this artifact exercises platform-owned reactive GET query forms.

- [SearchReports](queries/search/SearchReports.roc) filters one bounded page (the
  first 100 visible reports by ID) by a literal, case-sensitive title substring and
  returns `searched_all` so the page says when more reports exist. It owns its
  contract and verification like every Reports read.
- [search.html](ui/pages/search.html) binds the raw `term` input to the checked
  `search` page with inert `data-query-*` metadata. The platform host owns query
  requests, stale-response cancellation and result-region replacement; the standard
  submit button remains available without progressive behavior.
- [reports-search.json](../authority-policies/reports-search.json) is the Reports
  policy plus an owner-scoped read grant for `reports.search`.

Full verification builds this overlay and exposes it to tests as
`DAY2_TEST_REPORTS_SEARCH_ARTIFACT`; `reports_http` checks native GET rendering,
owner-scoped results and that searching leaves business state unchanged.
