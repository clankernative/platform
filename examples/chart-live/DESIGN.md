# Chart Live design

Inherits the previously reviewed Native gallery/chart surface; no new brand.
Paper file: 01M3QDD6MPNMW6G6VNPSKBNWNA, page p-1-0, artboard 225-0.
The artboard's earlier SVG is explicitly a layout reference, not execution proof.

- Mood: quiet, operational, exact.
- Palette: white #FFFFFF, ink #17191B, muted #555D63, rules #D7DCDF,
  action/chart accent #A84716. App overrides stay in app-owned styles.
- Type: system sans; 36/24/18/16/14px hierarchy.
- Structure: one query-rendered chart, checked range controls, exact values,
  and ordinary command forms. No fixture-library comparison.
- Responsive: two command columns above 700px, one below; chart and table
  scale/scroll without hiding exact values. Controls have visible focus and
  44px minimum buttons; animation is absent and reduced motion is respected.
- GET ranges and command forms work without JS. Optional enhancement emits
  bounded events; the app owns accepted routes, modal content and commands.
- Editable forms remain outside data-live regions so rejection preserves drafts.

Paper screenshot review: spacing/hierarchy/contrast/text fit passed for the
inherited reference; no layout clipping. Functional/browser qualification is
separate and not established by this design reference.
