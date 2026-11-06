//! Actual response-right lifetime bookkeeping, never a complete Stop witness.
//! Only the installed native owner registers rights, before request admission.
//! Unknown rights stay outstanding; DATA and Drop cannot make the set empty.
use super::{NativeRole, OWNERS, ResponseIdentity};
use anyhow::{Context, Result, ensure};
use day2_capabilities::security_epoch::AuthorityScope;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

const MAX_OUTSTANDING: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Live,
    Preparing,
    Unknown,
    Complete,
}

struct Record {
    response: ResponseIdentity,
    state: Cell<State>,
}

struct Ledger {
    closed: Cell<bool>,
    records: RefCell<Vec<Rc<Record>>>,
}

/// Owned by the actual installed Owners value, including while it is leased
/// out of the registry. This is NOT native permission or a restorable inventory.
pub(super) struct ResponseRights {
    ledger: Rc<Ledger>,
}

impl ResponseRights {
    pub(super) fn new() -> Self {
        Self {
            ledger: Rc::new(Ledger {
                closed: Cell::new(false),
                records: RefCell::new(Vec::new()),
            }),
        }
    }

    fn register(&self, response: &ResponseIdentity) -> Result<Ticket> {
        ensure!(!self.ledger.closed.get(), "response_rights_owner_closed");
        let mut records = self.ledger.records.try_borrow_mut()?;
        // Only a real known terminal transition can free a slot. Unknown,
        // abandoned and still-preparing records are never pruned or expired.
        records.retain(|record| record.state.get() != State::Complete);
        ensure!(records.len() < MAX_OUTSTANDING, "response_rights_capacity");
        ensure!(
            !records.iter().any(|record| record.response.same(response)),
            "response_rights_duplicate"
        );
        let record = Rc::new(Record {
            response: response.clone(),
            state: Cell::new(State::Live),
        });
        records.push(record.clone());
        Ok(Ticket {
            ledger: self.ledger.clone(),
            record,
        })
    }
}

impl Drop for ResponseRights {
    fn drop(&mut self) {
        self.ledger.closed.set(true);
    }
}

struct Ticket {
    ledger: Rc<Ledger>,
    record: Rc<Record>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if self.record.state.get() != State::Complete {
            self.record.state.set(State::Unknown);
        }
    }
}

/// Routing clones share this exact set through Sink's Rc. No ticket is cloned
/// or moved into Request::finish, a peer ACK, or a per-poll Current completion.
pub(super) struct ResponseTickets {
    tickets: RefCell<Vec<Ticket>>,
}

impl ResponseTickets {
    pub(super) fn new() -> Self {
        Self {
            tickets: RefCell::new(Vec::new()),
        }
    }

    pub(super) fn capture_app(
        &self,
        scope: &AuthorityScope,
        response: &ResponseIdentity,
    ) -> Result<()> {
        let mut tickets = self.tickets.try_borrow_mut()?;
        ensure!(tickets.is_empty(), "response_rights_already_captured");
        OWNERS.with(|owners| {
            let owners = owners.try_borrow()?;
            let owner = owners
                .get(scope.app.as_str())
                .context("native request App missing")?;
            ensure!(
                owner.kind == NativeRole::AppHost && owner.selection.scope() == scope,
                "native request App selection changed"
            );
            tickets.push(owner.response_rights.register(response)?);
            Ok(())
        })
    }

    pub(super) fn capture_shell(&self, response: &ResponseIdentity) -> Result<()> {
        let mut tickets = self.tickets.try_borrow_mut()?;
        ensure!(tickets.is_empty(), "response_rights_already_captured");
        // Shell request capture precedes selection. Conservatively retain a
        // ticket in EVERY actual installed Shell scope before that attempt.
        // A later URL/intent cannot replace this creator's selected gate.
        OWNERS.with(|owners| {
            let owners = owners.try_borrow()?;
            owners.require_unleased()?;
            for owner in owners.values() {
                ensure!(
                    owner.kind == NativeRole::SecurityShell,
                    "response_rights_shell_changed"
                );
                tickets.push(owner.response_rights.register(response)?);
            }
            Ok(())
        })
    }

    pub(super) fn prepare_native(
        &self,
        response: &ResponseIdentity,
        owner: &ResponseRights,
    ) -> Result<Terminal> {
        let tickets = self.tickets.try_borrow()?;
        ensure!(
            tickets.len() == 1 && Rc::ptr_eq(&tickets[0].ledger, &owner.ledger),
            "response_rights_final_owner_changed"
        );
        prepare(&tickets, response)
    }

    pub(super) fn prepare(&self, response: &ResponseIdentity) -> Result<Terminal> {
        prepare(&self.tickets.try_borrow()?, response)
    }

    pub(super) fn refuse(&self) {
        if let Ok(tickets) = self.tickets.try_borrow() {
            for ticket in tickets.iter() {
                if ticket.record.state.get() != State::Complete {
                    ticket.record.state.set(State::Unknown);
                }
            }
        }
        // If borrowed, actual final Ticket Drop still retains Unknown. A
        // refused Sink/role cannot obtain a successful terminal continuation.
    }
}

fn prepare(tickets: &[Ticket], response: &ResponseIdentity) -> Result<Terminal> {
    let mut records = Vec::with_capacity(tickets.len());
    for ticket in tickets {
        ensure!(
            !ticket.ledger.closed.get()
                && ticket.record.response.same(response)
                && ticket.record.state.get() == State::Live,
            "response_rights_terminal_refused"
        );
        ensure!(
            ticket
                .ledger
                .records
                .try_borrow()?
                .iter()
                .any(|record| Rc::ptr_eq(record, &ticket.record)),
            "response_rights_registration_lost"
        );
        records.push((ticket.ledger.clone(), ticket.record.clone()));
    }
    // Every fallible lookup/borrow/allocation above completes BEFORE the
    // actual original is consumed. This phase remains outstanding, not known.
    for (_, record) in &records {
        record.state.set(State::Preparing);
    }
    Ok(Terminal {
        records,
        completed: false,
    })
}

/// Retained across request-owner finish and the fallible result publication.
/// Only fixed actual terminal callers can complete it after known disposition.
pub(super) struct Terminal {
    records: Vec<(Rc<Ledger>, Rc<Record>)>,
    completed: bool,
}

impl Terminal {
    pub(super) fn complete(mut self) {
        // Infallible local bookkeeping only: no RefCell borrow, callback,
        // allocation, I/O, clock, IPC or Result after positive disposition.
        for (ledger, record) in &self.records {
            record.state.set(
                if !ledger.closed.get() && record.state.get() == State::Preparing {
                    State::Complete
                } else {
                    State::Unknown
                },
            );
        }
        self.completed = true;
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if !self.completed {
            for (_, record) in &self.records {
                record.state.set(State::Unknown);
            }
        }
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($owner:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$owner as Ambiguous<_>>::check;
        }};
    }
    macro_rules! closed {
        ($owner:ty) => {
            assert_not_impl!($owner, Clone);
            assert_not_impl!($owner, Copy);
            assert_not_impl!($owner, Default);
            assert_not_impl!($owner, std::fmt::Debug);
            assert_not_impl!($owner, Send);
            assert_not_impl!($owner, Sync);
            assert_not_impl!($owner, serde::Serialize);
            assert_not_impl!($owner, serde::Deserialize<'static>);
        };
    }
    closed!(ResponseRights);
    closed!(ResponseTickets);
    closed!(Terminal);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (ResponseRights, ResponseIdentity, ResponseTickets) {
        let rights = ResponseRights::new();
        let response = ResponseIdentity::new();
        let tickets = ResponseTickets::new();
        tickets
            .tickets
            .borrow_mut()
            .push(rights.register(&response).unwrap());
        (rights, response, tickets)
    }

    fn states(rights: &ResponseRights) -> Vec<State> {
        rights
            .ledger
            .records
            .borrow()
            .iter()
            .map(|record| record.state.get())
            .collect()
    }

    #[test]
    fn rights_survive_peer_known_original_finish_and_rejected_publication() -> Result<()> {
        let (rights, response, tickets) = fixture();
        // These earlier milestones retire nothing. The actual-source control
        // below binds the real request/transport call sites to this lifetime.
        assert!(states(&rights) == [State::Live]);
        let terminal = tickets.prepare_native(&response, &rights)?;
        assert!(states(&rights) == [State::Preparing]);
        // Even after the original is consumed, rejected result publication or
        // cancellation drops this retained continuation and preserves Unknown.
        drop(terminal);
        assert!(states(&rights) == [State::Unknown]);
        assert!(tickets.prepare_native(&response, &rights).is_err());
        drop(tickets);
        assert!(states(&rights) == [State::Unknown]);
        Ok(())
    }

    #[test]
    fn only_exact_terminal_completion_retires_and_duplicate_loser_cannot_erase_winner() -> Result<()>
    {
        let (rights, response, tickets) = fixture();
        assert!(tickets.prepare(&ResponseIdentity::new()).is_err());
        assert!(
            tickets
                .prepare_native(&response, &ResponseRights::new())
                .is_err()
        );
        let winner = tickets.prepare_native(&response, &rights)?;
        assert!(tickets.prepare_native(&response, &rights).is_err());
        assert!(states(&rights) == [State::Preparing]);
        winner.complete();
        assert!(states(&rights) == [State::Complete]);
        tickets.refuse();
        drop(tickets);
        assert!(states(&rights) == [State::Complete]);
        Ok(())
    }

    #[test]
    fn abort_drop_and_owner_loss_cannot_be_repaired_or_pruned_as_completed() -> Result<()> {
        let (rights, response, tickets) = fixture();
        tickets.refuse();
        assert!(tickets.prepare(&response).is_err());
        assert!(states(&rights) == [State::Unknown]);
        let later = rights.register(&ResponseIdentity::new())?;
        assert!(states(&rights) == [State::Unknown, State::Live]);
        drop(later);
        drop(tickets);
        assert!(states(&rights) == [State::Unknown, State::Unknown]);
        let (rights, response, tickets) = fixture();
        let ledger = rights.ledger.clone();
        drop(rights);
        assert!(ledger.closed.get());
        assert!(tickets.prepare(&response).is_err());
        drop(tickets);
        assert!(ledger.records.borrow()[0].state.get() == State::Unknown);
        Ok(())
    }

    #[test]
    fn capacity_frees_only_known_rights_never_unknown_rights() -> Result<()> {
        let rights = ResponseRights::new();
        for _ in 0..MAX_OUTSTANDING {
            drop(rights.register(&ResponseIdentity::new())?);
        }
        assert!(rights.register(&ResponseIdentity::new()).is_err());
        assert!(states(&rights).iter().all(|state| *state == State::Unknown));
        let (rights, response, tickets) = fixture();
        tickets.prepare_native(&response, &rights)?.complete();
        let _later = rights.register(&ResponseIdentity::new())?;
        assert!(states(&rights) == [State::Live]);
        Ok(())
    }

    #[test]
    fn already_prepared_terminal_cannot_erase_abort_or_owner_death() -> Result<()> {
        let (rights, response, tickets) = fixture();
        let terminal = tickets.prepare_native(&response, &rights)?;
        tickets.refuse();
        terminal.complete();
        assert!(states(&rights) == [State::Unknown]);
        let (rights, response, tickets) = fixture();
        let terminal = tickets.prepare_native(&response, &rights)?;
        let ledger = rights.ledger.clone();
        drop(rights);
        terminal.complete();
        assert!(ledger.records.borrow()[0].state.get() == State::Unknown);
        Ok(())
    }

    fn native_terminal_tail(source: &str) -> bool {
        use quote::ToTokens;
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let Some(function) = file.items.iter().find_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            if item.self_ty.to_token_stream().to_string() != "Sink" {
                return None;
            }
            item.items.iter().find_map(|member| match member {
                syn::ImplItem::Fn(function) if function.sig.ident == "drive_response" => {
                    Some(function)
                }
                _ => None,
            })
        }) else {
            return false;
        };
        let expected: syn::Block = syn::parse_quote!({
            let terminal = self
                .response_tickets
                .prepare_native(&self.identity, &owners.response_rights)?;
            request_owner.finish(role.owner())?;
            transport.complete(sequence)?;
            role.known = true;
            lease.known = true;
            self.state.set(SinkState::Complete);
            terminal.complete();
            Ok(())
        });
        let actual = &function.block.stmts;
        let wanted = &expected.stmts;
        actual.len() >= wanted.len()
            && actual[actual.len() - wanted.len()..]
                .iter()
                .zip(wanted)
                .all(|(a, b)| a.to_token_stream().to_string() == b.to_token_stream().to_string())
            && function
                .block
                .to_token_stream()
                .to_string()
                .matches("terminal . complete ()")
                .count()
                == 1
    }

    #[test]
    fn actual_native_response_prechecks_ticket_before_finish_and_retires_after_publication_and_known()
     {
        let source = include_str!("response.rs");
        assert!(native_terminal_tail(source));
        for (old, new) in [
            (
                "transport.complete(sequence)?;",
                "terminal.complete(); transport.complete(sequence)?;",
            ),
            (
                "request_owner.finish(role.owner())?;",
                "terminal.complete(); request_owner.finish(role.owner())?;",
            ),
            (
                "transport.complete(sequence)?;",
                "let _unknown = transport.complete(sequence);",
            ),
            ("lease.known = true;", ""),
            ("terminal.complete();", ""),
            ("terminal.complete();", "terminal.complete()?;"),
        ] {
            let mutant = source.replacen(old, new, 1);
            assert_ne!(source, mutant, "actual final response boundary");
            assert!(!native_terminal_tail(&mutant));
        }
    }

    #[test]
    fn terminal_bookkeeping_contains_no_fallible_borrow_clock_io_or_callback() {
        use quote::ToTokens;
        let source = syn::parse_file(include_str!("response_tickets.rs")).unwrap();
        let body = source
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if item.self_ty.to_token_stream().to_string() != "Terminal" {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == "complete" => Some(&item.block),
                    _ => None,
                })
            })
            .unwrap();
        let expected: syn::Block = syn::parse_quote!({
            for (ledger, record) in &self.records {
                record.state.set(
                    if !ledger.closed.get() && record.state.get() == State::Preparing {
                        State::Complete
                    } else {
                        State::Unknown
                    },
                );
            }
            self.completed = true;
        });
        assert_eq!(
            body.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }

    fn registration_precedes_request(source: &str) -> bool {
        use quote::ToTokens;
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let mut matched = 0;
        for item in file.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            if item.self_ty.to_token_stream().to_string() != "Sink" {
                continue;
            }
            for member in item.items {
                let syn::ImplItem::Fn(function) = member else {
                    continue;
                };
                let expected: syn::Block = match function.sig.ident.to_string().as_str() {
                    "capture_app_request" => syn::parse_quote!({
                        self.response_tickets.capture_app(scope, &self.identity)?;
                        self.request.capture_app(scope)
                    }),
                    "capture_shell_request" => syn::parse_quote!({
                        self.response_tickets.capture_shell(&self.identity)?;
                        self.request.capture_shell()
                    }),
                    _ => continue,
                };
                matched += 1;
                if function.block.to_token_stream().to_string()
                    != expected.to_token_stream().to_string()
                {
                    return false;
                }
            }
        }
        matched == 2
    }

    #[test]
    fn actual_app_and_unselected_shell_register_before_original_capture() {
        let source = include_str!("../native_management.rs");
        assert!(registration_precedes_request(source));
        for (old, new) in [
            (
                "self.response_tickets.capture_app(scope, &self.identity)?;",
                "",
            ),
            ("self.response_tickets.capture_shell(&self.identity)?;", ""),
            (
                "self.response_tickets.capture_app(scope, &self.identity)?;",
                "let _ignored = self.response_tickets.capture_app(scope, &self.identity);",
            ),
            (
                "self.request.capture_app(scope)",
                "self.request.capture_app(scope)?; self.response_tickets.capture_app(scope, &self.identity)",
            ),
        ] {
            let mutant = source.replacen(old, new, 1);
            assert_ne!(source, mutant, "actual request registration");
            assert!(!registration_precedes_request(&mutant));
        }
    }

    fn other_terminal_tail(source: &str, autonomous: bool) -> bool {
        use quote::ToTokens;
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let body = if autonomous {
            file.items.iter().find_map(|item| {
                let syn::Item::Fn(function) = item else {
                    return None;
                };
                if function.sig.ident != "with_app_request" {
                    return None;
                }
                let syn::Stmt::Expr(syn::Expr::Match(branches), _) = function.block.stmts.last()?
                else {
                    return None;
                };
                branches.arms.iter().find_map(|arm| {
                    if arm.pat.to_token_stream().to_string() != "Ok (Ok (value))" {
                        return None;
                    }
                    let syn::Expr::Block(block) = &*arm.body else {
                        return None;
                    };
                    Some(&block.block)
                })
            })
        } else {
            file.items.iter().find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if item.self_ty.to_token_stream().to_string() != "Sink" {
                    return None;
                }
                item.items.iter().find_map(|member| match member {
                    syn::ImplItem::Fn(function) if function.sig.ident == "finish" => {
                        Some(&function.block)
                    }
                    _ => None,
                })
            })
        };
        let Some(body) = body else { return false };
        let expected: syn::Block = if autonomous {
            syn::parse_quote!({
                let terminal = sink.response_tickets.prepare(&sink.identity)?;
                sink.request.finish()?;
                sink.state.set(SinkState::Complete);
                terminal.complete();
                Ok(value)
            })
        } else {
            syn::parse_quote!({
                let terminal = self.response_tickets.prepare(&self.identity)?;
                #[cfg(test)]
                if !fixtures::active() || self.request.has_started()? {
                    self.request.finish()?;
                }
                #[cfg(not(test))]
                self.request.finish()?;
                self.state.set(SinkState::Complete);
                terminal.complete();
                Ok(())
            })
        };
        body.stmts.len() >= expected.stmts.len()
            && body.stmts[body.stmts.len() - expected.stmts.len()..]
                .iter()
                .zip(&expected.stmts)
                .all(|(a, b)| a.to_token_stream().to_string() == b.to_token_stream().to_string())
            && body
                .to_token_stream()
                .to_string()
                .matches("terminal . complete ()")
                .count()
                == 1
    }

    fn terminal_mutant(source: &str, autonomous: bool, old: &str, new: &str) -> String {
        use quote::ToTokens;
        let mut file = syn::parse_file(source).unwrap();
        let mut changed = 0;
        for item in &mut file.items {
            let body = match item {
                syn::Item::Fn(function)
                    if autonomous && function.sig.ident == "with_app_request" =>
                {
                    Some(function.block.as_mut())
                }
                syn::Item::Impl(item)
                    if !autonomous && item.self_ty.to_token_stream().to_string() == "Sink" =>
                {
                    item.items.iter_mut().find_map(|member| match member {
                        syn::ImplItem::Fn(function) if function.sig.ident == "finish" => {
                            Some(&mut function.block)
                        }
                        _ => None,
                    })
                }
                _ => None,
            };
            if let Some(body) = body {
                let before = body.to_token_stream().to_string();
                let after = before.replacen(old, new, 1);
                assert_ne!(before, after, "actual scoped terminal mutation");
                *body = syn::parse_str(&after).unwrap();
                changed += 1;
            }
        }
        assert_eq!(changed, 1);
        file.to_token_stream().to_string()
    }

    #[test]
    fn actual_autonomous_and_ordinary_response_tails_cannot_retire_early_or_omit_completion() {
        let source = include_str!("../native_management.rs");
        for autonomous in [true, false] {
            assert!(other_terminal_tail(source, autonomous));
            let finish = if autonomous {
                "sink . request . finish () ? ;"
            } else {
                "self . request . finish () ? ;"
            };
            for (old, new) in [
                (finish, format!("terminal.complete(); {finish}")),
                ("terminal . complete () ;", String::new()),
                ("terminal . complete () ;", "terminal.complete()?;".into()),
            ] {
                let mutant = terminal_mutant(source, autonomous, old, &new);
                assert!(!other_terminal_tail(&mutant, autonomous));
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Event {
        PeerKnown,
        OriginalFinished,
        Prepare,
        ForeignPrepare,
        Publish,
        LostPublication,
        Abort,
    }

    // Independent expectation: retirement needs the original's completion AND
    // a known final publication, with no prior uncertainty. The oracle never
    // reads production State, registration records or the terminal's fields.
    fn replay(history: &[Event]) -> Result<Vec<bool>> {
        let (rights, response, tickets) = fixture();
        let mut terminal = None;
        let mut original_finished = false;
        let mut prepared = false;
        let mut uncertain = false;
        let mut completed = false;
        let mut observations = Vec::new();
        for event in history {
            match event {
                Event::PeerKnown => {}
                Event::OriginalFinished => {
                    original_finished = true;
                }
                Event::Prepare => {
                    let actual = tickets.prepare_native(&response, &rights);
                    let expected = !prepared && !uncertain && !completed;
                    ensure!(actual.is_ok() == expected, "response_history_prepare");
                    if let Ok(value) = actual {
                        prepared = true;
                        terminal = Some(value);
                    }
                }
                Event::ForeignPrepare => {
                    ensure!(
                        tickets
                            .prepare_native(&response, &ResponseRights::new())
                            .is_err(),
                        "response_history_foreign"
                    );
                }
                Event::Publish if original_finished => {
                    if let Some(value) = terminal.take() {
                        value.complete();
                        if !uncertain {
                            completed = true;
                        }
                    }
                }
                Event::Publish => {}
                Event::LostPublication => {
                    if terminal.take().is_some() {
                        uncertain = true;
                    }
                }
                Event::Abort => {
                    tickets.refuse();
                    if !completed {
                        uncertain = true;
                    }
                }
            }
            let actual = states(&rights) == [State::Complete];
            ensure!(actual == completed, "response_history_terminal");
            observations.push(actual);
        }
        Ok(observations)
    }

    #[test]
    fn generated_response_histories_match_independent_expectations_and_replay_twice() -> Result<()>
    {
        const EVENTS: [Event; 7] = [
            Event::PeerKnown,
            Event::OriginalFinished,
            Event::Prepare,
            Event::ForeignPrepare,
            Event::Publish,
            Event::LostPublication,
            Event::Abort,
        ];
        for seed in 0..256_u64 {
            let mut random = seed + 1;
            let history: Vec<_> = (0..32)
                .map(|_| {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    EVENTS[(random % EVENTS.len() as u64) as usize]
                })
                .collect();
            let first = replay(&history)
                .with_context(|| format!("response history seed {seed}: {history:?}"))?;
            let second = replay(&history)?;
            ensure!(first == second, "response_history_replay_changed");
        }
        Ok(())
    }
}
