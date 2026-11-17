//! Bounded ordinary-RWO serving observations. Health reads no business SQL on
//! requests and grants no business authority: every real request still enters
//! current native generation, policy and captured-owner guards.
use super::*;
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const FRESH: Duration = Duration::from_secs(5);
const PERIOD: Duration = Duration::from_secs(1);
const MAX_METADATA: i64 = 2 * 1024 * 1024;

#[derive(Clone)]
struct Frame {
    ready: bool,
    candidate: bool,
    generation: Option<String>,
    quiesced: bool,
}

pub(crate) struct Health {
    frame: Mutex<Option<(Instant, Frame)>>,
    source_stopped: AtomicBool,
}

fn observer_connection(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.busy_timeout(Duration::ZERO)?;
    Ok(connection)
}

fn sample(runtime: &Runtime) -> Result<Frame> {
    ensure!(
        runtime.rolling() && !runtime.uses_native_storage(),
        "ordinary_rolling_health_required"
    );
    // Independent metadata reader: a long business unit cannot serialize it
    // behind the business SQL-unit admission queue. WAL readers still use one
    // consistent SQLite transaction, never a desired-file or cached grant.
    let mut db = observer_connection(runtime.db())?;
    let tx = db.transaction()?;
    let bounded: bool = tx.query_row(
        "SELECT length(document)<=?1 FROM day2_authority WHERE singleton=1",
        [MAX_METADATA],
        |row| row.get(0),
    )?;
    ensure!(bounded, "serving_health_metadata_budget");
    let has_release: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_rollout WHERE singleton=1 AND length(release)>?1)",
        [MAX_METADATA],
        |row| row.get(0),
    )?;
    ensure!(!has_release, "serving_health_metadata_budget");
    let (ready, _) = ready_snapshot(runtime, &tx, false)?;
    let (candidate, warm) = ready_snapshot(runtime, &tx, true)?;
    let generation = if crate::runtime_generation::identity(runtime, &tx)?.is_some() {
        Some(crate::runtime_generation::selected(runtime, &tx)?)
    } else {
        None
    };
    let quiesced = crate::runtime_pair::source_quiesced(runtime, &tx)?;
    tx.rollback()?;
    for id in warm {
        retained(runtime, &id)?;
    }
    Ok(Frame {
        ready,
        candidate,
        generation,
        quiesced,
    })
}

fn busy(error: &anyhow::Error) -> bool {
    error.downcast_ref::<rusqlite::Error>().is_some_and(|e| {
        matches!(e,
        rusqlite::Error::SqliteFailure(code, _) if matches!(code.code,
            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked))
    })
}

impl Health {
    pub(crate) fn new(runtime: &Runtime) -> Arc<Self> {
        let health = Arc::new(Self {
            frame: Mutex::new(None),
            source_stopped: AtomicBool::new(false),
        });
        health.publish(sample(runtime), Instant::now());
        health
    }

    fn publish(&self, result: Result<Frame>, now: Instant) {
        let mut current = self.frame.lock().expect("serving health lock");
        match result {
            Ok(frame) => {
                *current = Some((now, frame));
            }
            Err(error) if busy(&error) => {} // Preserve only the still-fresh observation.
            Err(_) => {
                *current = None;
            }
        }
    }

    fn observed(&self, now: Instant) -> Option<Frame> {
        self.frame
            .lock()
            .expect("serving health lock")
            .as_ref()
            .filter(|(at, _)| {
                now.checked_duration_since(*at)
                    .is_some_and(|age| age <= FRESH)
            })
            .map(|(_, frame)| frame.clone())
    }

    pub(crate) fn ready(&self, candidate: bool) -> bool {
        self.observed(Instant::now()).is_some_and(|frame| {
            if candidate {
                frame.candidate
            } else {
                frame.ready
            }
        })
    }

    pub(crate) fn drain(
        &self,
        admitting: bool,
        inflight: usize,
        streams: usize,
    ) -> Option<serde_json::Value> {
        let frame = self.observed(Instant::now())?;
        Some(
            serde_json::json!({"generation":frame.generation,"admitting":admitting,
            "inflight":inflight,"streams":streams,"quiesced":frame.quiesced}),
        )
    }

    pub(crate) fn source_stopped(&self) -> bool {
        self.source_stopped.load(Ordering::Acquire)
    }

    pub(crate) async fn run(
        self: Arc<Self>,
        runtime: Arc<Runtime>,
        admitting: Arc<AtomicBool>,
        source_stop: tokio::sync::watch::Sender<bool>,
        mut stopped: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let mut ticks = tokio::time::interval(PERIOD);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                result=stopped.changed()=> { let _=result; return Ok(()); }
                _=ticks.tick()=> {
                    let runtime=runtime.clone();
                    let health=self.clone();
                    // Exactly one blocking metadata observation at a time. It
                    // remains owned and joined through ordinary server drain.
                    tokio::task::spawn_blocking(move || health.publish(sample(&runtime),Instant::now())).await?;
                    if self.observed(Instant::now()).is_some_and(|frame| frame.quiesced) {
                        self.source_stopped.store(true,Ordering::Release);
                        admitting.store(false,Ordering::Release);
                        let _=source_stop.send(true);
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> Frame {
        Frame {
            ready: true,
            candidate: true,
            generation: Some(crate::digest(b"generation")),
            quiesced: false,
        }
    }

    #[test]
    fn only_busy_preserves_a_bounded_observation_and_no_clock_rewind_rearms_it() {
        let health = Health {
            frame: Mutex::new(None),
            source_stopped: AtomicBool::new(false),
        };
        let now = Instant::now();
        health.publish(Ok(frame()), now);
        let error = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            None,
        );
        health.publish(Err(error.into()), now + Duration::from_secs(1));
        assert!(health.observed(now + FRESH).unwrap().ready);
        assert!(
            health
                .observed(now + FRESH + Duration::from_nanos(1))
                .is_none()
        );
        assert!(health.observed(now - Duration::from_millis(1)).is_none());
        health.publish(
            Err(anyhow::anyhow!("scope invalidated")),
            now + Duration::from_secs(1),
        );
        assert!(health.observed(now + Duration::from_secs(1)).is_none());
        assert!(!health.source_stopped());
    }

    #[test]
    fn failed_refresh_exposes_no_previous_generation_or_app_values() {
        let health = Health {
            frame: Mutex::new(None),
            source_stopped: AtomicBool::new(false),
        };
        health.publish(Ok(frame()), Instant::now());
        assert!(health.drain(false, 0, 0).is_some());
        health.publish(
            Err(anyhow::anyhow!("private fixture value")),
            Instant::now(),
        );
        assert!(health.drain(false, 0, 0).is_none());
        assert!(!health.ready(false));
    }
}
