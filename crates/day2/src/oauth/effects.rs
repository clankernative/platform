//! The ambient-effect boundary for OAuth. Production uses the OS clock, crypto
//! entropy and the bounded native HTTP adapters. Tests replace all three together
//! and run the same host code; a scripted transport never opens a socket.
//!
//! Simulation hooks exist only in test binaries. They cannot mint production
//! readiness or install deterministic cryptographic entropy in a serving host.

use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{IntoUrl, blocking, header::HeaderMap};
use serde::Serialize;
use std::{
    io::Read,
    net::SocketAddr,
    ops::{Add, Sub},
    time::Duration,
};

#[cfg(test)]
pub(crate) trait Hooks: Send + Sync {
    fn domain(&self) -> u64;
    fn wall_time(&self) -> Result<i64>;
    fn monotonic(&self) -> Duration;
    fn fill(&self, bytes: &mut [u8]) -> Result<()>;
    fn send(&self, request: blocking::Request) -> Result<Response>;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Instant {
    Live(std::time::Instant),
    #[cfg(test)]
    Simulated {
        domain: u64,
        ticks: Duration,
    },
}

impl Instant {
    pub(super) fn now() -> Self {
        #[cfg(test)]
        if let Some(instant) = HOOKS.with(|slot| {
            slot.borrow().as_ref().map(|hooks| Self::Simulated {
                domain: hooks.domain(),
                ticks: hooks.monotonic(),
            })
        }) {
            return instant;
        }
        Self::Live(std::time::Instant::now())
    }

    pub(super) fn checked_add(self, duration: Duration) -> Option<Self> {
        match self {
            Self::Live(instant) => instant.checked_add(duration).map(Self::Live),
            #[cfg(test)]
            Self::Simulated { domain, ticks } => ticks
                .checked_add(duration)
                .map(|ticks| Self::Simulated { domain, ticks }),
        }
    }

    pub(super) fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        match (self, earlier) {
            (Self::Live(now), Self::Live(earlier)) => now.checked_duration_since(earlier),
            #[cfg(test)]
            (
                Self::Simulated { domain, ticks },
                Self::Simulated {
                    domain: other,
                    ticks: earlier,
                },
            ) if domain == other => ticks.checked_sub(earlier),
            #[cfg(test)]
            _ => None,
        }
    }

    pub(super) fn elapsed(self) -> Duration {
        Self::now()
            .checked_duration_since(self)
            .unwrap_or(Duration::MAX)
    }
}

impl PartialOrd for Instant {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (*self, *other) {
            (Self::Live(a), Self::Live(b)) => a.partial_cmp(&b),
            #[cfg(test)]
            (
                Self::Simulated { domain, ticks },
                Self::Simulated {
                    domain: other,
                    ticks: b,
                },
            ) if domain == other => ticks.partial_cmp(&b),
            #[cfg(test)]
            _ => None,
        }
    }
}

impl Add<Duration> for Instant {
    type Output = Self;

    fn add(self, duration: Duration) -> Self {
        self.checked_add(duration)
            .expect("OAuth monotonic deadline overflow")
    }
}

impl Sub<Duration> for Instant {
    type Output = Self;

    fn sub(self, duration: Duration) -> Self {
        match self {
            Self::Live(instant) => Self::Live(instant - duration),
            #[cfg(test)]
            Self::Simulated { domain, ticks } => Self::Simulated {
                domain,
                ticks: ticks
                    .checked_sub(duration)
                    .expect("OAuth monotonic time underflow"),
            },
        }
    }
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

pub(crate) fn fill(bytes: &mut [u8]) -> Result<()> {
    #[cfg(test)]
    if let Some(result) = HOOKS.with(|slot| slot.borrow().as_ref().map(|hooks| hooks.fill(bytes))) {
        return result;
    }
    getrandom::fill(bytes).map_err(|_| anyhow::anyhow!("OAuth cryptographic entropy unavailable"))
}

pub(super) fn random() -> Result<String> {
    let mut bytes = [0; 32];
    fill(&mut bytes)?;
    let value = URL_SAFE_NO_PAD.encode(bytes);
    bytes.fill(0);
    Ok(value)
}

/// Blocking work inherits the simulation environment instead of silently using
/// live time or sockets on Tokio's blocking pool.
pub(super) fn spawn_blocking<F, R>(run: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    #[cfg(test)]
    let hooks = HOOKS.with(|slot| slot.borrow().clone());
    tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        if let Some(hooks) = hooks {
            return scope(hooks, run);
        }
        run()
    })
}

/// Request-body deadlines use Tokio's clock, which the simulation runtime
/// pauses and advances independently of wall time and provider lease time.
pub(super) async fn timeout<F: std::future::Future>(
    duration: Duration,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout(duration, future).await
}

#[cfg(test)]
pub(super) async fn scope_async<F: std::future::Future>(
    hooks: std::sync::Arc<dyn Hooks>,
    future: F,
) -> F::Output {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|context| scope(hooks.clone(), || future.as_mut().poll(context))).await
}

#[derive(Clone)]
pub(crate) struct Client(blocking::Client);

pub(crate) struct Builder(blocking::ClientBuilder);

impl Client {
    pub(crate) fn builder() -> Builder {
        Builder(blocking::Client::builder().retry(reqwest::retry::never()))
    }

    pub(crate) fn get(&self, url: impl IntoUrl) -> Request {
        Request {
            client: self.0.clone(),
            request: self.0.get(url),
        }
    }

    pub(crate) fn post(&self, url: impl IntoUrl) -> Request {
        Request {
            client: self.0.clone(),
            request: self.0.post(url),
        }
    }
}

impl Builder {
    pub(crate) fn no_proxy(self) -> Self {
        Self(self.0.no_proxy())
    }
    pub(crate) fn redirect(self, policy: reqwest::redirect::Policy) -> Self {
        Self(self.0.redirect(policy))
    }
    pub(crate) fn retry(self, policy: reqwest::retry::Builder) -> Self {
        Self(self.0.retry(policy))
    }
    pub(crate) fn connect_timeout(self, timeout: Duration) -> Self {
        Self(self.0.connect_timeout(timeout))
    }
    pub(crate) fn timeout(self, timeout: Duration) -> Self {
        Self(self.0.timeout(timeout))
    }
    pub(crate) fn build(self) -> Result<Client> {
        Ok(Client(self.0.build()?))
    }
}

pub(crate) struct Request {
    client: blocking::Client,
    request: blocking::RequestBuilder,
}

impl Request {
    pub(crate) fn header<K, V>(mut self, name: K, value: V) -> Self
    where
        reqwest::header::HeaderName: TryFrom<K>,
        <reqwest::header::HeaderName as TryFrom<K>>::Error: Into<axum::http::Error>,
        reqwest::header::HeaderValue: TryFrom<V>,
        <reqwest::header::HeaderValue as TryFrom<V>>::Error: Into<axum::http::Error>,
    {
        self.request = self.request.header(name, value);
        self
    }

    pub(super) fn form<T: Serialize + ?Sized>(mut self, form: &T) -> Self {
        self.request = self.request.form(form);
        self
    }

    pub(super) fn timeout(mut self, timeout: Duration) -> Self {
        self.request = self.request.timeout(timeout);
        self
    }

    pub(crate) fn body(mut self, body: impl Into<blocking::Body>) -> Self {
        self.request = self.request.body(body);
        self
    }

    pub(crate) fn send(self) -> Result<Response> {
        let request = self.request.build()?;
        #[cfg(test)]
        if let Some(hooks) = HOOKS.with(|slot| slot.borrow().clone()) {
            return hooks.send(request);
        }
        Ok(Response::Live(self.client.execute(request)?))
    }
}

pub(crate) enum Response {
    Live(blocking::Response),
    #[cfg(test)]
    Simulated {
        status: reqwest::StatusCode,
        headers: HeaderMap,
        body: std::io::Cursor<Vec<u8>>,
        peer: Option<SocketAddr>,
    },
}

impl Response {
    pub(crate) fn status(&self) -> reqwest::StatusCode {
        match self {
            Self::Live(response) => response.status(),
            #[cfg(test)]
            Self::Simulated { status, .. } => *status,
        }
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        match self {
            Self::Live(response) => response.headers(),
            #[cfg(test)]
            Self::Simulated { headers, .. } => headers,
        }
    }

    pub(crate) fn content_length(&self) -> Option<u64> {
        match self {
            Self::Live(response) => response.content_length(),
            #[cfg(test)]
            Self::Simulated { headers, .. } => headers
                .get("content-length")
                .and_then(|v| v.to_str().ok()?.parse().ok()),
        }
    }

    pub(super) fn remote_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Live(response) => response.remote_addr(),
            #[cfg(test)]
            Self::Simulated { peer, .. } => *peer,
        }
    }

    pub(crate) fn error_for_status(self) -> Result<Self> {
        ensure!(
            !self.status().is_client_error() && !self.status().is_server_error(),
            "OAuth HTTP request rejected"
        );
        Ok(self)
    }

    #[cfg(test)]
    pub(super) fn bytes(mut self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

impl Read for Response {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Live(response) => response.read(bytes),
            #[cfg(test)]
            Self::Simulated { body, .. } => body.read(bytes),
        }
    }
}
