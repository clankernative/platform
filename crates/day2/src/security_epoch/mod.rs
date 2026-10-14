//! Private, initial-only external security-epoch protocol.
//!
//! Records, receipts and observations below are historical DATA. None is a
//! current authority, clock, holder or credential-readiness proof. In particular,
//! the live execution-context producer is deliberately absent: ordinary app
//! startup cannot initialize a counter or adopt an existing database here.
mod firestore;
pub(crate) mod journal;
mod kernel;

#[cfg(test)]
mod tests;
