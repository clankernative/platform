//! Private managed-credential effect boundary. Serving binaries use trusted
//! host clocks and OS cryptographic entropy. Replayable identifiers and secret
//! material use separate ports; no invocation or replay seed derives a secret.
//! Synthetic hooks and async scope installation exist only in test binaries.

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::Duration;

#[cfg(test)]
pub(crate) trait Hooks: Send + Sync {
    fn domain(&self) -> u64;
    fn wall_time(&self) -> Result<i64>;
    fn monotonic(&self) -> Duration;
    fn fill_id(&self, bytes: &mut [u8]) -> Result<()>;
    fn fill_secret(&self, bytes: &mut [u8]) -> Result<()>;
}

#[cfg(test)]
thread_local! {
    static HOOKS: std::cell::RefCell<Option<std::sync::Arc<dyn Hooks>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn scope<T>(hooks: std::sync::Arc<dyn Hooks>, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<std::sync::Arc<dyn Hooks>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            HOOKS.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(HOOKS.with(|slot| slot.replace(Some(hooks))));
    run()
}

/// Capture at the HTTP task boundary, then restore around synchronous dispatch.
/// This is a zero-state value in serving binaries. It composes with the OAuth
/// scheduler without replacing that track's clock, transport or entropy ports.
#[derive(Clone)]
pub(crate) struct Captured {
    oauth: crate::oauth::effects::Captured,
    #[cfg(test)]
    hooks: Option<std::sync::Arc<dyn Hooks>>,
}

pub(crate) fn capture() -> Captured {
    Captured {
        oauth: crate::oauth::effects::capture(),
        #[cfg(test)]
        hooks: HOOKS.with(|slot| slot.borrow().clone()),
    }
}

impl Captured {
    pub(crate) fn run<T>(self, run: impl FnOnce() -> T) -> T {
        self.oauth.run(|| {
            #[cfg(test)]
            if let Some(hooks) = self.hooks {
                return scope(hooks, run);
            }
            run()
        })
    }

    pub(crate) async fn run_async<F: std::future::Future>(self, future: F) -> F::Output {
        #[cfg(test)]
        {
            let mut future = std::pin::pin!(future);
            std::future::poll_fn(|context| self.clone().run(|| future.as_mut().poll(context))).await
        }
        #[cfg(not(test))]
        future.await
    }
}

pub(crate) fn spawn_blocking<F, R>(run: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let captured = capture();
    crate::oauth::effects::spawn_blocking(move || captured.run(run))
}

/// Reuse the existing native HTTP body timer with both scoped replay tracks.
pub(crate) async fn timeout<F: std::future::Future>(
    duration: Duration,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    crate::oauth::effects::timeout(duration, future).await
}

#[cfg(test)]
pub(crate) async fn scope_async<F: std::future::Future>(
    hooks: std::sync::Arc<dyn Hooks>,
    future: F,
) -> F::Output {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|context| scope(hooks.clone(), || future.as_mut().poll(context))).await
}

pub(crate) fn wall_time() -> Result<i64> {
    #[cfg(test)]
    if let Some(result) = HOOKS.with(|slot| slot.borrow().as_ref().map(|hooks| hooks.wall_time())) {
        return result;
    }
    Ok(i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?)
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct Instant {
    inner: InstantSource,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum InstantSource {
    Live(std::time::Instant),
    #[cfg(test)]
    Simulated {
        domain: u64,
        ticks: Duration,
    },
}

#[cfg(test)]
impl Instant {
    pub(crate) fn now() -> Self {
        #[cfg(test)]
        if let Some(inner) = HOOKS.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|hooks| InstantSource::Simulated {
                    domain: hooks.domain(),
                    ticks: hooks.monotonic(),
                })
        }) {
            return Self { inner };
        }
        Self {
            inner: InstantSource::Live(std::time::Instant::now()),
        }
    }

    pub(crate) fn checked_elapsed(self) -> Option<Duration> {
        match (Self::now().inner, self.inner) {
            (InstantSource::Live(now), InstantSource::Live(earlier)) => {
                now.checked_duration_since(earlier)
            }
            #[cfg(test)]
            (
                InstantSource::Simulated { domain, ticks },
                InstantSource::Simulated {
                    domain: other,
                    ticks: earlier,
                },
            ) if domain == other => ticks.checked_sub(earlier),
            #[cfg(test)]
            _ => None,
        }
    }
}

fn fill_id(bytes: &mut [u8]) -> Result<()> {
    #[cfg(test)]
    if let Some(result) =
        HOOKS.with(|slot| slot.borrow().as_ref().map(|hooks| hooks.fill_id(bytes)))
    {
        return result;
    }
    getrandom::fill(bytes).map_err(|_| anyhow::anyhow!("credential identifier entropy unavailable"))
}

/// Private secret bytes, token selectors and AEAD nonces never use the ID port.
pub(crate) fn fill_secret(bytes: &mut [u8]) -> Result<()> {
    #[cfg(test)]
    if let Some(result) =
        HOOKS.with(|slot| slot.borrow().as_ref().map(|hooks| hooks.fill_secret(bytes)))
    {
        return result;
    }
    getrandom::fill(bytes)
        .map_err(|_| anyhow::anyhow!("credential cryptographic entropy unavailable"))
}

pub(crate) fn navigation_id() -> Result<String> {
    let mut bytes = [0; 32];
    fill_id(&mut bytes)?;
    let value = URL_SAFE_NO_PAD.encode(bytes);
    bytes.fill(0);
    Ok(value)
}

pub(crate) fn record_id() -> Result<String> {
    let mut bytes = [0; 16];
    fill_id(&mut bytes)?;
    let value = format!("c_{}", URL_SAFE_NO_PAD.encode(bytes));
    bytes.fill(0);
    Ok(value)
}
