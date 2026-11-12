//! Invocation-scoped delivery of a validated provider capture into the app.
//!
//! A delivery capability collects and validates a complete capture, splits it
//! into pages that each fit one journaled observation and one bounded
//! `Tx.create_many`, and stages those pages in the application's own database.
//! The same invocation then reads the pages back as local observations and
//! persists whatever it keeps in its own models.
//!
//! The staged pages are a buffer, not a store: they belong to exactly one
//! invocation, are released when that invocation's preparation ends, and any
//! left behind by a crash are swept once the invocation is no longer pending or
//! is blocked by an authority change. Nothing here has a platform-chosen expiry
//! or outlives the invocation that collected it; retention of the delivered
//! data is the application's decision in its own tables. See
//! docs/PROVIDER-CAPTURE-DELIVERY.md.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

/// One less than preparation's 32 observations: the delivery itself is one.
pub const MAX_PAGES: usize = 31;
/// `Tx.create_many`'s batch bound, so one page can become one write step.
pub const MAX_PAGE_ITEMS: usize = 256;
/// A page's result as journaled, JSON escaping included. The remainder of the
/// 64 KiB observation is left for the instruction and the envelope.
pub const MAX_PAGE_JOURNAL_BYTES: usize = 56 * 1024;
/// Every delivery staged in one application database at once.
pub const MAX_BUFFER_BYTES: i64 = 64 * 1024 * 1024;

/// Staged pages of one complete capture, ready for one invocation to read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staged {
    /// Content identity of the capture (`sha256:` digest).
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
            invocation TEXT NOT NULL,
            id TEXT NOT NULL CHECK(length(id)=71),
            kind TEXT NOT NULL,
            authority TEXT NOT NULL,
            item_count INTEGER NOT NULL CHECK(item_count >= 0),
            page_count INTEGER NOT NULL CHECK(page_count BETWEEN 1 AND 31),
            PRIMARY KEY(invocation,id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_capture_delivery_pages (
            invocation TEXT NOT NULL,
            id TEXT NOT NULL,
            page INTEGER NOT NULL CHECK(page >= 0),
            result TEXT NOT NULL,
            PRIMARY KEY(invocation,id,page),
            FOREIGN KEY(invocation,id) REFERENCES day2_capture_deliveries(invocation,id)
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

/// Stage `staged` for `invocation`, first sweeping deliveries whose invocation
/// can no longer read them. Restaging the same capture in the same invocation
/// (a retried attempt) replaces it with identical content.
pub(crate) fn stage(connection: &Connection, invocation: &str, staged: &Staged) -> Result<()> {
    ensure!(
        !invocation.is_empty()
            && staged.id.len() == 71
            && staged.id.starts_with("sha256:")
            && !staged.pages.is_empty()
            && staged.pages.len() <= MAX_PAGES,
        "capture_delivery_invalid"
    );
    for page in &staged.pages {
        ensure!(
            journal_bytes(page)? <= MAX_PAGE_JOURNAL_BYTES,
            "capture_delivery_page_too_large"
        );
    }
    ensure!(installed(connection)?, "capture_delivery_unavailable");
    sweep(connection)?;
    release_one(connection, invocation, &staged.id)?;
    connection.execute(
        "INSERT INTO day2_capture_deliveries VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            invocation,
            staged.id,
            staged.kind,
            staged.authority,
            i64::try_from(staged.item_count)?,
            i64::try_from(staged.pages.len())?,
        ],
    )?;
    for (index, page) in staged.pages.iter().enumerate() {
        connection.execute(
            "INSERT INTO day2_capture_delivery_pages VALUES(?1,?2,?3,?4)",
            params![invocation, staged.id, i64::try_from(index)?, page],
        )?;
    }
    let buffered: i64 = connection.query_row(
        "SELECT coalesce(sum(length(CAST(result AS BLOB))),0) FROM day2_capture_delivery_pages",
        [],
        |row| row.get(0),
    )?;
    ensure!(buffered <= MAX_BUFFER_BYTES, "capture_delivery_capacity");
    Ok(())
}

/// Read one staged page. Only the invocation that staged the capture can read
/// it, and only while the grant's authority is exactly the one it was staged
/// under.
pub(crate) fn page(
    connection: &Connection,
    invocation: &str,
    kind: &str,
    authority: &str,
    id: &str,
    page: u64,
) -> Result<String> {
    ensure!(installed(connection)?, "capture_delivery_unavailable");
    let header: Option<(String, String, i64)> = connection
        .query_row(
            "SELECT kind,authority,page_count FROM day2_capture_deliveries WHERE invocation=?1 AND id=?2",
            params![invocation, id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (saved_kind, saved_authority, page_count) =
        header.context("capture_delivery_unavailable")?;
    ensure!(
        saved_kind == kind && saved_authority == authority,
        "capture_delivery_authority_changed"
    );
    let index =
        i64::try_from(page).map_err(|_| anyhow::anyhow!("capture_delivery_page_invalid"))?;
    ensure!(index < page_count, "capture_delivery_page_invalid");
    connection
        .query_row(
            "SELECT result FROM day2_capture_delivery_pages WHERE invocation=?1 AND id=?2 AND page=?3",
            params![invocation, id, index],
            |row| row.get(0),
        )
        .optional()?
        .context("capture_delivery_incomplete")
}

/// Release everything `invocation` staged. Called when its preparation ends.
pub(crate) fn release(connection: &Connection, invocation: &str) -> Result<()> {
    if !installed(connection)? {
        return Ok(());
    }
    connection.execute(
        "DELETE FROM day2_capture_delivery_pages WHERE invocation=?1",
        [invocation],
    )?;
    connection.execute(
        "DELETE FROM day2_capture_deliveries WHERE invocation=?1",
        [invocation],
    )?;
    Ok(())
}

fn release_one(connection: &Connection, invocation: &str, id: &str) -> Result<()> {
    connection.execute(
        "DELETE FROM day2_capture_delivery_pages WHERE invocation=?1 AND id=?2",
        params![invocation, id],
    )?;
    connection.execute(
        "DELETE FROM day2_capture_deliveries WHERE invocation=?1 AND id=?2",
        params![invocation, id],
    )?;
    Ok(())
}

/// Drop deliveries no invocation can read again: the invocation finished, was
/// never accepted here, or is permanently blocked by an authority change.
fn sweep(connection: &Connection) -> Result<()> {
    let blocks: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='day2_authority_blocks')",
        [],
        |row| row.get(0),
    )?;
    let stale = if blocks {
        "SELECT d.invocation FROM day2_capture_deliveries d
         LEFT JOIN day2_invocations i ON i.id=d.invocation
         WHERE i.id IS NULL OR i.status!='pending'
            OR d.invocation IN (SELECT invocation FROM day2_authority_blocks)"
    } else {
        "SELECT d.invocation FROM day2_capture_deliveries d
         LEFT JOIN day2_invocations i ON i.id=d.invocation
         WHERE i.id IS NULL OR i.status!='pending'"
    };
    connection.execute(
        &format!("DELETE FROM day2_capture_delivery_pages WHERE invocation IN ({stale})"),
        [],
    )?;
    connection.execute(
        &format!("DELETE FROM day2_capture_deliveries WHERE invocation IN ({stale})"),
        [],
    )?;
    Ok(())
}

/// Whether any recorded observation of this invocation staged a delivery, so
/// that ending preparation only writes when there is something to release.
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
        stage(&db, "pending-a", &capture)?;
        let kind = capture.kind;
        let authority = capture.authority.as_str();
        assert_eq!(
            page(&db, "pending-a", kind, authority, &capture.id, 1)?,
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
                page(&db, invocation, kind, authority, &capture.id, index)
                    .unwrap_err()
                    .to_string(),
                expected
            );
        }
        assert_eq!(
            page(
                &db,
                "pending-a",
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
        stage(&db, "pending-a", &first)?;
        // A retried attempt restages identical content without duplicating it.
        stage(&db, "pending-a", &first)?;
        assert_eq!(count(&db, "day2_capture_delivery_pages")?, 1);
        release(&db, "pending-a")?;
        assert_eq!(count(&db, "day2_capture_deliveries")?, 0);
        assert_eq!(count(&db, "day2_capture_delivery_pages")?, 0);

        // Crash leftovers: a finished invocation, an unknown one and a blocked
        // one are all swept by the next staging, which itself survives.
        for invocation in ["pending-a", "pending-b"] {
            stage(&db, invocation, &staged(invocation, &["{}"]))?;
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
            "INSERT INTO day2_capture_deliveries VALUES('ghost','sha256:0000000000000000000000000000000000000000000000000000000000000000','workspace_directory.hierarchy','[]',0,1);
             INSERT INTO day2_capture_delivery_pages VALUES('ghost','sha256:0000000000000000000000000000000000000000000000000000000000000000',0,'{}');",
        )?;
        let survivor = staged("survivor", &["{}"]);
        stage(&db, "pending-c", &survivor)?;
        let invocations: Vec<String> = db
            .prepare("SELECT invocation FROM day2_capture_deliveries ORDER BY invocation")?
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
            stage(&db, "pending-a", &staged("many", &too_many))
                .unwrap_err()
                .to_string(),
            "capture_delivery_invalid"
        );
        assert_eq!(
            stage(&db, "pending-a", &staged("none", &[]))
                .unwrap_err()
                .to_string(),
            "capture_delivery_invalid"
        );
        // Escaping counts: a page of quotes is twice its raw size once journaled.
        let quoted = "\"".repeat(MAX_PAGE_JOURNAL_BYTES / 2);
        assert_eq!(
            stage(&db, "pending-a", &staged("quoted", &[&quoted]))
                .unwrap_err()
                .to_string(),
            "capture_delivery_page_too_large"
        );
        stage(&db, "pending-a", &staged("ok", &["{}"]))?;
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
            stage(&db, &invocation, &staged(&invocation, &pages))?;
        }
        db.execute(
            "INSERT INTO day2_invocations VALUES('overflow','pending')",
            [],
        )?;
        assert_eq!(
            stage(&db, "overflow", &staged("overflow", &pages))
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
                "anything",
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
}
