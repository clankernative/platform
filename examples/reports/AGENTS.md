# Reports Authoring

Keep application decisions in pure Roc and presentation in ordinary HTML/CSS.
Use generated Data/Inputs/Outputs/Templates handles. Never author generated files.
Follow ../../docs/APP-LAYOUT.md. Keep each operation's request type, handler,
contract and verification together in commands/ or queries/. App.definition
registers complete definitions once. Keep shared state checks in verification/,
optional sample data in examples/, typed routes in pages/ and presentation in ui/.
Register analysis and readiness notifications as internal commands. Request them
through generated Commands handles with a target observed in the same Tx.
Use Handler.prepared for read-only preparation and Handler.effects for external
effects with private transactional completion. Observe cannot write; Effects
cannot access the database. Provider progress belongs to the platform journal,
while report readiness belongs to the app. See ../../docs/COMMAND-RUNTIME.md.
Do not import Temporal, source-control APIs, credentials, or arbitrary I/O.
Run the platform repository root’s `cargo run --locked -p xtask -- verify`.
