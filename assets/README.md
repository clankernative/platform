# Trusted Browser Assets

Datastar is vendored, not app-authored JavaScript. Version 1.0.1, upstream:
https://github.com/starfederation/datastar/tree/v1.0.1
Bundle: https://cdn.jsdelivr.net/gh/starfederation/datastar@v1.0.1/bundles/datastar.js

Lucide icons are vendored from https://github.com/lucide-icons/lucide/tree/0.468.0 (ISC).
The admitted artifact records every asset's SHA-256. No CDN is contacted at runtime.
Only platform templates may emit Datastar expressions or load these assets.

These are platform chrome only, served under /assets/platform/. App images and
icons live in each app's assets/ directory, not here. Company branding lives in
an independently pinned instance bundle. See docs/WEB.md.

`api-docs.css` and `api-docs.js` are authored platform presentation for the
generated `/docs` reference. They are embedded in the host, require no CDN or
package build, and use the platform's ETag revalidation policy. The docs page
loads only these resources and invokes the same-origin JSON API on user input.
