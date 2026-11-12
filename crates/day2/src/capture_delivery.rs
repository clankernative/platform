//! Delivery of a validated provider capture into the application's database.
//!
//! A delivery capability collects and validates a complete capture, splits it
//! into pages that each fit one journaled observation and one bounded
//! `Tx.create_many`, and stages those pages in the application's own database.
//! The application reads them back as local observations and persists whatever
//! it keeps in its own models.
//!
//! A staged capture has exactly one holder:
//!
//! - **An invocation** (Workspace Directory). The pages are a buffer: released
//!   when that invocation's preparation ends, and swept once the invocation is
//!   no longer pending or is blocked by an authority change.
//! - **The application** (Carta). A capture too large for one invocation is held
//!   until the application releases it, so a multi-invocation import keeps its
//!   source. There is no platform expiry and no silent pruning: a resource with
//!   too many unreleased captures refuses another until one is released.
//!
//! Either way the pages live in the application's own database, are backed up
//! and restored with it, and nothing chooses their retention but the application.
//! See docs/PROVIDER-CAPTURE-DELIVERY.md.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

/// One less than preparation's 32 observations: the delivery itself is one.
pub const MAX_PAGES: usize = 31;
/// `Tx.create_many`'s batch bound, so one page can become one write step.
pub const MAX_PAGE_ITEMS: usize = 256;
/// A page's result as journaled, JSON escaping included. The remainder of the
/// 64 KiB observation is left for the instruction and the envelope.
pub const MAX_PAGE_JOURNAL_BYTES: usize = 56 * 1024;
/// Every invocation-held delivery in one application database at once.
pub const MAX_BUFFER_BYTES: i64 = 64 * 1024 * 1024;
/// An application-held capture may span many invocations: one page per record
/// at most, under the provider's own record bound.
pub const MAX_HELD_PAGES: usize = 10_000;
/// Unreleased application-held captures per kind and authority.
pub const MAX_HELD_PER_AUTHORITY: i64 = 2;
/// Every application-held capture in one application database at once.
pub const MAX_HELD_BYTES: i64 = 128 * 1024 * 1024;

/// Who a staged capture belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holder<'a> {
    /// Readable only by this invocation, released when its preparation ends.
    Invocation(&'a str),
    /// Readable by any invocation of this application under the same authority,
    /// until the application releases it.
    Application,
}

impl<'a> Holder<'a> {
    /// The stored holder key: the invocation, or empty for the application.
    /// Invocation identities are never empty.
    fn column(self) -> &'a str {
        match self {
            Self::Invocation(invocation) => invocation,
            Self::Application => "",
        }
    }
}

/// Staged pages of one complete capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staged {
    /// Content identity of the capture.
    pub id: String,
    /// Fixed provider/kind label, for example `workspace_directory.hierarchy`.
    pub kind: &'static str,
    /// The exact grant authority the pages are bound to, compared on every read.
    pub authority: String,
    pub item_count: u64,
    /// Each page's complete result bytes, as returned to the application.
    pub pages: Vec<String>,
}

/// The bytes `encoded` occupies once it is embedded in a journaled observation
/// as a JSON string.
pub fn journal_bytes(encoded: &str) -> Result<usize> {
    Ok(serde_json::to_string(encoded)?.len())
}

pub(crate) fn upgrade(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_capture_deliveries (
            holder TEXT NOT NULL,
            id TEXT NOT NULL CHECK(length(id) BETWEEN 1 AND 128),
            kind TEXT NOT NULL,
            authority TEXT NOT NULL,
            item_count INTEGER NOT NULL CHECK(item_count >= 0),
            page_count INTEGER NOT NULL CHECK(page_count BETWEEN 1 AND 10000),
            bytes INTEGER NOT NULL CHECK(bytes >= 0),
            PRIMARY KEY(holder,id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_capture_delivery_pages (
            holder TEXT NOT NULL,
            id TEXT NOT NULL,
            page INTEGER NOT NULL CHECK(page >= 0),
            result TEXT NOT NULL,
            PRIMARY KEY(holder,id,page),
            FOREIGN KEY(holder,id) REFERENCES day2_capture_deliveries(holder,id)
        ) STRICT;
        CREATE TRIGGER IF NOT EXISTS day2_capture_deliveries_no_update
            BEFORE UPDATE ON day2_capture_deliveries BEGIN SELECT RAISE(ABORT,'immutable_delivery'); END;
        CREATE TRIGGER IF NOT EXISTS day2_capture_delivery_pages_no_update
            BEFORE UPDATE ON day2_capture_delivery_pages BEGIN SELECT RAISE(ABORT,'immutable_delivery'); END;",
    )?;
    Ok(())
}

fn installed(connection: &Connection) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='day2_capture_deliveries')",
        [],
        |row| row.get(0),
    )?)
}

/// Whether staging found the capture new or already held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Staging {
    Staged,
    AlreadyHeld,
}

/// Stage `staged` for `holder`.
///
/// An invocation first sweeps deliveries no invocation can read again, and a
/// retried attempt replaces its own identical content. The application keeps a
/// capture it already holds under the same authority (an unchanged recapture),
/// and otherwise refuses to exceed its per-authority count or byte bound rather
/// than discard anything it holds.
pub(crate) fn stage(
    connection: &Connection,
    holder: Holder<'_>,
    staged: &Staged,
) -> Result<Staging> {
    let max_pages = match holder {
        Holder::Invocation(invocation) => {
            ensure!(!invocation.is_empty(), "capture_delivery_invalid");
            MAX_PAGES
        }
        Holder::Application => MAX_HELD_PAGES,
    };
    ensure!(
        !staged.id.is_empty()
            && staged.id.len() <= 128
            && !staged.pages.is_empty()
            && staged.pages.len() <= max_pages,
        "capture_delivery_invalid"
    );
    let mut bytes = 0i64;
    for page in &staged.pages {
        ensure!(
            journal_bytes(page)? <= MAX_PAGE_JOURNAL_BYTES,
            "capture_delivery_page_too_large"
        );
        bytes = bytes
            .checked_add(i64::try_from(page.len())?)
            .context("capture_delivery_capacity")?;
    }
    ensure!(installed(connection)?, "capture_delivery_unavailable");
    let key = holder.column();
    match holder {
        Holder::Invocation(invocation) => {
            sweep(connection)?;
            release_one(connection, invocation, &staged.id)?;
        }
        Holder::Application => {
            let held: Option<(String, String)> = connection
                .query_row(
                    "SELECT kind,authority FROM day2_capture_deliveries WHERE holder='' AND id=?1",
                    [&staged.id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((kind, authority)) = held {
                ensure!(
                    kind == staged.kind && authority == staged.authority,
                    "capture_delivery_conflict"
                );
                return Ok(Staging::AlreadyHeld);
            }
            let unreleased: i64 = connection.query_row(
                "SELECT count(*) FROM day2_capture_deliveries WHERE holder='' AND kind=?1 AND authority=?2",
                params![staged.kind, staged.authority],
                |row| row.get(0),
            )?;
            ensure!(
                unreleased < MAX_HELD_PER_AUTHORITY,
                "capture_delivery_release_required"
            );
        }
    }
    connection.execute(
        "INSERT INTO day2_capture_deliveries VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            key,
            staged.id,
            staged.kind,
            staged.authority,
            i64::try_from(staged.item_count)?,
            i64::try_from(staged.pages.len())?,
            bytes,
        ],
    )?;
    for (index, page) in staged.pages.iter().enumerate() {
        connection.execute(
            "INSERT INTO day2_capture_delivery_pages VALUES(?1,?2,?3,?4)",
            params![key, staged.id, i64::try_from(index)?, page],
        )?;
    }
    let (sql, bound) = match holder {
        Holder::Invocation(_) => (
            "SELECT coalesce(sum(bytes),0) FROM day2_capture_deliveries WHERE holder!=''",
            MAX_BUFFER_BYTES,
        ),
        Holder::Application => (
            "SELECT coalesce(sum(bytes),0) FROM day2_capture_deliveries WHERE holder=''",
            MAX_HELD_BYTES,
        ),
    };
    let total: i64 = connection.query_row(sql, [], |row| row.get(0))?;
    ensure!(total <= bound, "capture_delivery_capacity");
    Ok(Staging::Staged)
}

/// The header of a staged capture, after the holder, kind and authority match.
pub(crate) fn held(
    connection: &Connection,
    holder: Holder<'_>,
    kind: &str,
    authority: &str,
    id: &str,
) -> Result<(u64, u64)> {
    ensure!(installed(connection)?, "capture_delivery_unavailable");
    let header: Option<(String, String, i64, i64)> = connection
        .query_row(
            "SELECT kind,authority,item_count,page_count FROM day2_capture_deliveries WHERE holder=?1 AND id=?2",
            params![holder.column(), id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let (saved_kind, saved_authority, items, pages) =
        header.context("capture_delivery_unavailable")?;
    ensure!(
        saved_kind == kind && saved_authority == authority,
        "capture_delivery_authority_changed"
    );
    Ok((u64::try_from(items)?, u64::try_from(pages)?))
}

/// Read one staged page. An invocation-held page answers only its invocation; an
/// application-held page answers any invocation. Both require the grant's
/// authority to be exactly the one the capture was staged under.
pub(crate) fn page(
    connection: &Connection,
    holder: Holder<'_>,
    kind: &str,
    authority: &str,
    id: &str,
    page: u64,
) -> Result<String> {
    let (_, page_count) = held(connection, holder, kind, authority, id)?;
    ensure!(page < page_count, "capture_delivery_page_invalid");
    connection
        .query_row(
            "SELECT result FROM day2_capture_delivery_pages WHERE holder=?1 AND id=?2 AND page=?3",
            params![holder.column(), id, i64::try_from(page)?],
            |row| row.get(0),
        )
        .optional()?
        .context("capture_delivery_incomplete")
}

/// Release everything `invocation` staged. Called when its preparation ends.
pub(crate) fn release(connection: &Connection, invocation: &str) -> Result<()> {
    if !installed(connection)? || invocation.is_empty() {
        return Ok(());
    }
    connection.execute(
        "DELETE FROM day2_capture_delivery_pages WHERE holder=?1",
        [invocation],
    )?;
    connection.execute(
        "DELETE FROM day2_capture_deliveries WHERE holder=?1",
        [invocation],
    )?;
    Ok(())
}

/// Release one application-held capture. Idempotent: releasing a capture that
/// is no longer held reports `false`. Another authority's capture is refused.
pub(crate) fn release_held(
    connection: &Connection,
    kind: &str,
    authority: &str,
    id: &str,
) -> Result<bool> {
    match held(connection, Holder::Application, kind, authority, id) {
        Ok(_) => {}
        Err(error) if error.to_string() == "capture_delivery_unavailable" => return Ok(false),
        Err(error) => return Err(error),
    }
    release_one(connection, "", id)?;
    Ok(true)
}

fn release_one(connection: &Connection, holder: &str, id: &str) -> Result<()> {
    connection.execute(
        "DELETE FROM day2_capture_delivery_pages WHERE holder=?1 AND id=?2",
        params![holder, id],
    )?;
    connection.execute(
        "DELETE FROM day2_capture_deliveries WHERE holder=?1 AND id=?2",
        params![holder, id],
    )?;
    Ok(())
}

/// Drop invocation-held deliveries no invocation can read again: the invocation
/// finished, was never accepted here, or is permanently blocked by an authority
/// change. Application-held captures are never swept.
fn sweep(connection: &Connection) -> Result<()> {
    let blocks: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='day2_authority_blocks')",
        [],
        |row| row.get(0),
    )?;
    let stale = if blocks {
        "SELECT d.holder FROM day2_capture_deliveries d
         LEFT JOIN day2_invocations i ON i.id=d.holder
         WHERE d.holder!='' AND (i.id IS NULL OR i.status!='pending'
            OR d.holder IN (SELECT invocation FROM day2_authority_blocks))"
    } else {
        "SELECT d.holder FROM day2_capture_deliveries d
         LEFT JOIN day2_invocations i ON i.id=d.holder
         WHERE d.holder!='' AND (i.id IS NULL OR i.status!='pending')"
    };
    connection.execute(
        &format!("DELETE FROM day2_capture_delivery_pages WHERE holder IN ({stale})"),
        [],
    )?;
    connection.execute(
        &format!("DELETE FROM day2_capture_deliveries WHERE holder IN ({stale})"),
        [],
    )?;
    Ok(())
}

/// Whether any recorded observation of this invocation staged an
/// invocation-held delivery, so that ending preparation only writes when there
/// is something to release.
pub(crate) fn staged_by(model: &str) -> bool {
    model == day2_capabilities::registry::Action::WorkspaceDirectoryHierarchyDelivery.capability()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database() -> Result<Connection> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE day2_invocations(id TEXT PRIMARY KEY, status TEXT NOT NULL) STRICT;
             CREATE TABLE day2_authority_blocks(invocation TEXT PRIMARY KEY, reason TEXT NOT NULL) STRICT;
             INSERT INTO day2_invocations VALUES('pending-a','pending'),('pending-b','pending'),('done','success');",
        )?;
        upgrade(&connection)?;
        Ok(connection)
    }

    fn staged(id_seed: &str, pages: &[&str]) -> Staged {
        Staged {
            id: crate::digest(id_seed.as_bytes()),
            kind: "workspace_directory.hierarchy",
            authority: "[\"C1\",\"directory@1\",\"reader@example.test\"]".into(),
            item_count: u64::try_from(pages.len()).unwrap(),
            pages: pages.iter().map(|page| (*page).to_owned()).collect(),
        }
    }

    fn count(connection: &Connection, table: &str) -> Result<i64> {
        Ok(
            connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })?,
        )
    }

    #[test]
    fn pages_are_readable_only_by_the_staging_invocation_and_authority() -> Result<()> {
        let db = database()?;
        let capture = staged("one", &["{\"page\":0}", "{\"page\":1}"]);
        stage(&db, Holder::Invocation("pending-a"), &capture)?;
        let kind = capture.kind;
        let authority = capture.authority.as_str();
        assert_eq!(
            page(
                &db,
                Holder::Invocation("pending-a"),
                kind,
                authority,
                &capture.id,
                1
            )?,
            "{\"page\":1}"
        );
        for (invocation, kind, authority, index, expected) in [
            (
                "pending-b",
                kind,
                authority,
                0,
                "capture_delivery_unavailable",
            ),
            (
                "pending-a",
                "carta.issuer",
                authority,
                0,
                "capture_delivery_authority_changed",
            ),
            (
                "pending-a",
                kind,
                "[\"C1\",\"directory@2\",\"reader@example.test\"]",
                0,
                "capture_delivery_authority_changed",
            ),
            (
                "pending-a",
                kind,
                "[\"C1\",\"directory@1\",\"other@example.test\"]",
                0,
                "capture_delivery_authority_changed",
            ),
            (
                "pending-a",
                kind,
                authority,
                2,
                "capture_delivery_page_invalid",
            ),
            (
                "pending-a",
                kind,
                authority,
                u64::MAX,
                "capture_delivery_page_invalid",
            ),
        ] {
            assert_eq!(
                page(
                    &db,
                    Holder::Invocation(invocation),
                    kind,
                    authority,
                    &capture.id,
                    index
                )
                .unwrap_err()
                .to_string(),
                expected
            );
        }
        assert_eq!(
            page(
                &db,
                Holder::Invocation("pending-a"),
                kind,
                authority,
                &crate::digest(b"other"),
                0
            )
            .unwrap_err()
            .to_string(),
            "capture_delivery_unavailable"
        );
        Ok(())
    }

    #[test]
    fn release_and_sweep_never_leave_a_buffer_past_its_invocation() -> Result<()> {
        let db = database()?;
        let first = staged("first", &["{\"page\":0}"]);
        stage(&db, Holder::Invocation("pending-a"), &first)?;
        // A retried attempt restages identical content without duplicating it.
        stage(&db, Holder::Invocation("pending-a"), &first)?;
        assert_eq!(count(&db, "day2_capture_delivery_pages")?, 1);
        release(&db, "pending-a")?;
        assert_eq!(count(&db, "day2_capture_deliveries")?, 0);
        assert_eq!(count(&db, "day2_capture_delivery_pages")?, 0);

        // Crash leftovers: a finished invocation, an unknown one and a blocked
        // one are all swept by the next staging, which itself survives.
        for invocation in ["pending-a", "pending-b"] {
            stage(
                &db,
                Holder::Invocation(invocation),
                &staged(invocation, &["{}"]),
            )?;
        }
        db.execute(
            "UPDATE day2_invocations SET status='success' WHERE id='pending-a'",
            [],
        )?;
        db.execute(
            "INSERT INTO day2_authority_blocks VALUES('pending-b','authority_policy_changed')",
            [],
        )?;
        db.execute(
            "INSERT INTO day2_invocations VALUES('pending-c','pending')",
            [],
        )?;
        db.execute_batch(
            "INSERT INTO day2_capture_deliveries VALUES('ghost','sha256:0000000000000000000000000000000000000000000000000000000000000000','workspace_directory.hierarchy','[]',0,1,2);
             INSERT INTO day2_capture_delivery_pages VALUES('ghost','sha256:0000000000000000000000000000000000000000000000000000000000000000',0,'{}');",
        )?;
        let survivor = staged("survivor", &["{}"]);
        stage(&db, Holder::Invocation("pending-c"), &survivor)?;
        let invocations: Vec<String> = db
            .prepare("SELECT holder FROM day2_capture_deliveries ORDER BY holder")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        assert_eq!(invocations, vec!["pending-c".to_owned()]);
        assert_eq!(count(&db, "day2_capture_delivery_pages")?, 1);
        Ok(())
    }

    #[test]
    fn staging_fails_closed_on_bounds_and_immutability() -> Result<()> {
        let db = database()?;
        let too_many: Vec<&str> = vec!["{}"; MAX_PAGES + 1];
        assert_eq!(
            stage(
                &db,
                Holder::Invocation("pending-a"),
                &staged("many", &too_many)
            )
            .unwrap_err()
            .to_string(),
            "capture_delivery_invalid"
        );
        assert_eq!(
            stage(&db, Holder::Invocation("pending-a"), &staged("none", &[]))
                .unwrap_err()
                .to_string(),
            "capture_delivery_invalid"
        );
        // Escaping counts: a page of quotes is twice its raw size once journaled.
        let quoted = "\"".repeat(MAX_PAGE_JOURNAL_BYTES / 2);
        assert_eq!(
            stage(
                &db,
                Holder::Invocation("pending-a"),
                &staged("quoted", &[&quoted])
            )
            .unwrap_err()
            .to_string(),
            "capture_delivery_page_too_large"
        );
        stage(&db, Holder::Invocation("pending-a"), &staged("ok", &["{}"]))?;
        assert!(
            db.execute("UPDATE day2_capture_delivery_pages SET result='[]'", [])
                .is_err()
        );
        assert!(
            db.execute("UPDATE day2_capture_deliveries SET authority='[]'", [])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn total_buffered_bytes_are_bounded() -> Result<()> {
        let db = database()?;
        let page = "x".repeat(MAX_PAGE_JOURNAL_BYTES - 2);
        let pages: Vec<&str> = vec![page.as_str(); MAX_PAGES];
        let per_delivery = i64::try_from(page.len() * MAX_PAGES)?;
        let fit = MAX_BUFFER_BYTES / per_delivery;
        for index in 0..fit {
            let invocation = format!("bulk-{index}");
            db.execute(
                "INSERT INTO day2_invocations VALUES(?1,'pending')",
                [&invocation],
            )?;
            stage(
                &db,
                Holder::Invocation(&invocation),
                &staged(&invocation, &pages),
            )?;
        }
        db.execute(
            "INSERT INTO day2_invocations VALUES('overflow','pending')",
            [],
        )?;
        assert_eq!(
            stage(
                &db,
                Holder::Invocation("overflow"),
                &staged("overflow", &pages)
            )
            .unwrap_err()
            .to_string(),
            "capture_delivery_capacity"
        );
        Ok(())
    }

    #[test]
    fn an_uninstalled_database_has_nothing_to_release() -> Result<()> {
        let db = Connection::open_in_memory()?;
        release(&db, "anything")?;
        assert_eq!(
            page(
                &db,
                Holder::Invocation("anything"),
                "workspace_directory.hierarchy",
                "[]",
                "sha256:x",
                0
            )
            .unwrap_err()
            .to_string(),
            "capture_delivery_unavailable"
        );
        Ok(())
    }

    fn held_capture(seed: &str, authority: &str) -> Staged {
        Staged {
            id: format!("carta_{}", &crate::digest(seed.as_bytes())[7..]),
            kind: "carta.issuer",
            authority: authority.into(),
            item_count: 2,
            pages: vec!["{\"page\":0}".into(), "{\"page\":1}".into()],
        }
    }

    #[test]
    fn application_held_captures_outlive_invocations_until_released() -> Result<()> {
        let db = database()?;
        let first = held_capture("first", "issuer-1");
        assert_eq!(stage(&db, Holder::Application, &first)?, Staging::Staged);
        // An unchanged recapture is the capture already held, not another one.
        assert_eq!(
            stage(&db, Holder::Application, &first)?,
            Staging::AlreadyHeld
        );
        // Sweeping invocation buffers never touches what the application holds.
        stage(
            &db,
            Holder::Invocation("pending-a"),
            &staged("buffer", &["{}"]),
        )?;
        db.execute(
            "UPDATE day2_invocations SET status='success' WHERE id='pending-a'",
            [],
        )?;
        stage(
            &db,
            Holder::Invocation("pending-b"),
            &staged("next", &["{}"]),
        )?;
        assert_eq!(
            page(
                &db,
                Holder::Application,
                "carta.issuer",
                "issuer-1",
                &first.id,
                1
            )?,
            "{\"page\":1}"
        );
        // Neither an invocation nor another authority can read it.
        assert_eq!(
            page(
                &db,
                Holder::Invocation("pending-b"),
                "carta.issuer",
                "issuer-1",
                &first.id,
                0
            )
            .unwrap_err()
            .to_string(),
            "capture_delivery_unavailable"
        );
        assert_eq!(
            page(
                &db,
                Holder::Application,
                "carta.issuer",
                "issuer-2",
                &first.id,
                0
            )
            .unwrap_err()
            .to_string(),
            "capture_delivery_authority_changed"
        );
        let mut conflicting = first.clone();
        conflicting.authority = "issuer-2".into();
        assert_eq!(
            stage(&db, Holder::Application, &conflicting)
                .unwrap_err()
                .to_string(),
            "capture_delivery_conflict"
        );

        // A bounded number of unreleased captures; the next is refused, never
        // made room for by discarding one the application still holds.
        let second = held_capture("second", "issuer-1");
        stage(&db, Holder::Application, &second)?;
        let third = held_capture("third", "issuer-1");
        assert_eq!(
            stage(&db, Holder::Application, &third)
                .unwrap_err()
                .to_string(),
            "capture_delivery_release_required"
        );
        // Another authority has its own allowance.
        stage(&db, Holder::Application, &held_capture("other", "issuer-2"))?;
        assert_eq!(
            release_held(&db, "carta.issuer", "issuer-2", &first.id)
                .unwrap_err()
                .to_string(),
            "capture_delivery_authority_changed"
        );
        assert!(release_held(&db, "carta.issuer", "issuer-1", &first.id)?);
        assert!(!release_held(&db, "carta.issuer", "issuer-1", &first.id)?);
        assert_eq!(stage(&db, Holder::Application, &third)?, Staging::Staged);
        assert_eq!(
            page(
                &db,
                Holder::Application,
                "carta.issuer",
                "issuer-1",
                &first.id,
                0
            )
            .unwrap_err()
            .to_string(),
            "capture_delivery_unavailable"
        );
        let held: i64 = db.query_row(
            "SELECT count(*) FROM day2_capture_deliveries WHERE holder=''",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(held, 3);
        Ok(())
    }

    #[test]
    fn application_held_bytes_are_bounded() -> Result<()> {
        let db = database()?;
        let page = "x".repeat(MAX_PAGE_JOURNAL_BYTES - 2);
        let per_capture = 64;
        let mut index = 0;
        loop {
            let capture = Staged {
                id: format!(
                    "carta_{}",
                    &crate::digest(index.to_string().as_bytes())[7..]
                ),
                kind: "carta.issuer",
                authority: format!("issuer-{index}"),
                item_count: per_capture,
                pages: vec![page.clone(); per_capture as usize],
            };
            match stage(&db, Holder::Application, &capture) {
                Ok(_) => index += 1,
                Err(error) => {
                    assert_eq!(error.to_string(), "capture_delivery_capacity");
                    break;
                }
            }
        }
        let fit = MAX_HELD_BYTES / (i64::try_from(page.len())? * 64);
        assert_eq!(index, fit);
        Ok(())
    }
}
