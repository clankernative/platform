//! The selected App/Shell HTTP executor. Tokio supplies readiness, not polling
//! of the service, provider calls, or HTTP connection. A single OS thread polls
//! those futures through socket completion. No response crosses a task queue.
//!
//! One HTTP/1 request per connection prevents pipelining/keepalive from moving
//! a response to another operation. Capacity includes slow response writes and
//! disconnected callers whose synchronous native operation has not returned.
//! Admission and successful physical delivery are distinct outcomes.

use anyhow::{Context, Result, ensure};
use axum::{body::Body, extract::Request, response::Response};
use futures_util::{StreamExt, stream::FuturesUnordered};
use hyper::{rt, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    cell::RefCell,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context as TaskContext, Poll},
    thread::{JoinHandle, ThreadId},
};
use tokio::{net::TcpListener, runtime::Handle};

pub(super) mod response_io;

// Keep the actual thread handles through TLS teardown. A result sent by its
// body is not proof that the owning thread and its thread-local roles exited.
#[derive(Default)]
struct OwnerThreads {
    closed: bool,
    started: bool,
    threads: Vec<JoinHandle<()>>,
}

static OWNER_THREADS: Mutex<OwnerThreads> = Mutex::new(OwnerThreads {
    closed: false,
    started: false,
    threads: Vec::new(),
});

impl OwnerThreads {
    fn spawn(&mut self, run: impl FnOnce() + Send + 'static) -> Result<()> {
        ensure!(!self.closed, "native HTTP executor launch closed");
        let mut live = Vec::new();
        for thread in self.threads.drain(..) {
            if thread.is_finished() {
                let _ = thread.join();
            } else {
                live.push(thread);
            }
        }
        self.threads = live;
        ensure!(self.threads.len() < 128, "native HTTP executor capacity");
        self.threads.push(
            std::thread::Builder::new()
                .name("day2-oauth-owner".into())
                .spawn(run)
                .context("start native HTTP owner")?,
        );
        self.started = true;
        Ok(())
    }

    fn close(&mut self) -> (bool, Vec<JoinHandle<()>>) {
        self.closed = true;
        (self.started, std::mem::take(&mut self.threads))
    }
}

/// Entrypoint-only, after the readiness runtime has stopped. Permanently close
/// launch admission and join the actual retained threads, including their TLS
/// destructors. This creates no role, clock, replacement or retry.
pub(crate) fn close_owner_threads() -> Result<bool> {
    let (started, threads) = OWNER_THREADS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .close();
    join_owner_threads(threads)?;
    Ok(started)
}

fn join_owner_threads(threads: Vec<JoinHandle<()>>) -> Result<()> {
    let mut self_join = false;
    for thread in threads {
        if thread.thread().id() == std::thread::current().id() {
            self_join = true;
        } else {
            // A panicked thread is still joined and all of its TLS has ended.
            let _ = thread.join();
        }
    }
    ensure!(!self_join, "native HTTP owner cannot close itself");
    Ok(())
}

#[cfg(test)]
use std::convert::Infallible;

thread_local! {
    // Only timer creation enters this handle. Keeping an entered Tokio runtime
    // across dispatch would prohibit reqwest's existing blocking adapter.
    static REACTOR: RefCell<Option<Handle>> = const { RefCell::new(None) };
    static LIVE: RefCell<Option<tokio::sync::mpsc::Sender<NativeLiveWork>>> = const { RefCell::new(None) };
}

struct NativeLiveWork {
    work: LiveJob,
    sink: super::native_management::Sink,
    effects: crate::managed_credentials::effects::Captured,
}

enum LiveJob {
    Page(Box<crate::web::live::LiveWork>),
    #[cfg(test)]
    Probe(Arc<tests::Exchange>, tokio::sync::oneshot::Sender<String>),
}

impl NativeLiveWork {
    async fn run(self) {
        self.effects
            .run_async(self.sink.scope(async move {
                match self.work {
                    LiveJob::Page(work) => (*work).run().await,
                    #[cfg(test)]
                    LiveJob::Probe(exchange, response) => {
                        exchange
                            .background
                            .lock()
                            .unwrap()
                            .push(std::thread::current().id());
                        let _ = response.send("live".into());
                    }
                }
            }))
            .await;
    }
}

pub(crate) fn start_live(work: crate::web::live::LiveWork) -> Result<()> {
    let work = NativeLiveWork {
        work: LiveJob::Page(Box::new(work)),
        sink: super::native_management::current_sink()?,
        effects: crate::managed_credentials::effects::capture(),
    };
    LIVE.with(|slot| {
        slot.try_borrow()?
            .as_ref()
            .context("native live executor missing")?
            .try_send(work)
            .map_err(|_| anyhow::anyhow!("native live executor capacity"))
    })
}

/// Tokio's implicit task budget is absent on the local owner executor. A live
/// refresh must yield explicitly even if its interval has accumulated ticks.
pub(crate) async fn cooperate() {
    let mut first = true;
    std::future::poll_fn(|cx| {
        if std::mem::take(&mut first) {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await
}

pub(crate) fn timer<F>(create: impl FnOnce() -> F) -> F {
    REACTOR.with(|slot| {
        let slot = slot.borrow();
        let _entered = slot.as_ref().map(Handle::enter);
        create()
    })
}

/// Poll only reactor readiness here; native dispatch stays outside runtime
/// entry. Tokio interval polling also needs its selected (possibly paused)
/// clock, rather than falling back to an unrelated ambient clock.
pub(crate) async fn readiness<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| timer(|| future.as_mut().poll(cx))).await
}

/// Closed transport composition; never an app-supplied callback/task port.
pub(crate) enum Endpoint {
    Shell(Arc<super::security_shell::SecurityShell>),
    App(Arc<crate::web::Host>),
    Receiver(Arc<super::shell_transport::AppApprovalReceiver>),
    #[cfg(test)]
    Test(Arc<tests::Exchange>),
    #[cfg(test)]
    Prepared(Box<Endpoint>, Box<dyn FnOnce() -> Result<()> + Send>),
}

impl Endpoint {
    fn take_idle_credential_wakes(
        &self,
    ) -> Result<Vec<super::native_management::IdleCredentialWake>> {
        #[cfg(test)]
        if let Self::Test(exchange) = self {
            // Readiness DATA only. Tests still reach the real idle factory;
            // a scripted wake cannot publish a credential or supply an owner.
            return Ok(exchange.idle_wakes.lock().unwrap().drain(..).collect());
        }
        super::native_management::take_idle_credential_wakes()
    }

    async fn pump(&self, stopped: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        match self {
            Self::App(host) => crate::web::native_pump(host.clone(), stopped).await,
            _ => std::future::pending().await,
        }
    }
    fn install(&self) -> Result<()> {
        #[cfg(test)]
        if super::native_management::simulation_installed() {
            return Ok(());
        }
        use crate::security_epoch::native_enrollment::NativeRole;
        let (scopes, role) = match self {
            Self::Shell(shell) => (
                shell.native_selections().to_vec(),
                NativeRole::SecurityShell,
            ),
            Self::App(host) => (crate::web::native_selections(host)?, NativeRole::AppHost),
            Self::Receiver(receiver) => (receiver.native_selections()?, NativeRole::AppHost),
            #[cfg(test)]
            Self::Test(_) => return Ok(()),
            #[cfg(test)]
            Self::Prepared(_, _) => anyhow::bail!("nested native fixture preparation"),
        };
        super::native_management::install(&scopes, role)
    }

    async fn handle(
        &self,
        request: Request,
        admission: Arc<AtomicBool>,
    ) -> crate::web::NativeResponse {
        match self {
            Self::Shell(shell) => crate::web::NativeResponse::application(
                shell.clone().handle_native(request, admission).await,
            ),
            Self::App(host) => crate::web::handle_native(host.clone(), request).await,
            Self::Receiver(receiver) => {
                crate::web::NativeResponse::application(receiver.clone().handle(request).await)
            }
            #[cfg(test)]
            Self::Test(exchange) => {
                crate::web::NativeResponse::application(exchange.handle(request).await)
            }
            #[cfg(test)]
            Self::Prepared(_, _) => panic!("native fixture not prepared"),
        }
    }

    /// Capture on the final executor before body/cookie parsing or operation
    /// entropy/I/O. Headers select no permission; actual suppliers are borrowed.
    fn capture_request<B>(
        &self,
        sink: &super::native_management::Sink,
        request: &axum::http::Request<B>,
    ) -> Result<Option<crate::web::NativeResponse>> {
        if let Self::App(host) = self
            && let Some(response) = crate::web::native_literal_health(host, request)
        {
            sink.capture_literal_health(&response)?;
            return Ok(Some(response));
        }
        #[cfg(test)]
        if super::native_management::simulation_installed() || matches!(self, Self::Test(_)) {
            sink.capture_model_request()?;
            return Ok(None);
        }
        match self {
            Self::Shell(shell) => {
                if shell.native_selections().is_empty() {
                    sink.capture_non_native_request()?;
                } else {
                    sink.capture_shell_request()?;
                }
            }
            // None means the immutable Runtime does not use native storage.
            // A native Runtime with no current owner returns Err, never None.
            Self::App(host) => match crate::web::native_runtime_response_scope(host)? {
                Some(scope) => sink.capture_app_request(&scope)?,
                None => sink.capture_non_native_request()?,
            },
            Self::Receiver(receiver) => match receiver.native_runtime_response_scope()? {
                Some(scope) => sink.capture_app_request(&scope)?,
                None => sink.capture_non_native_request()?,
            },
            #[cfg(test)]
            Self::Test(_) | Self::Prepared(_, _) => {
                anyhow::bail!("native request endpoint unavailable")
            }
        }
        Ok(None)
    }

    fn prepare_response(
        &self,
        sink: &super::native_management::Sink,
        response: &crate::web::NativeResponse,
        finite: bool,
    ) -> Result<()> {
        let scope = match self {
            Self::App(host) => {
                response.app_scope(|| crate::web::native_runtime_response_scope(host))?
            }
            Self::Receiver(receiver) => receiver.native_runtime_response_scope()?,
            Self::Shell(_) => None,
            #[cfg(test)]
            Self::Test(_) => None,
            #[cfg(test)]
            Self::Prepared(_, _) => anyhow::bail!("native fixture preparation not complete"),
        };
        sink.prepare_response(scope, finite)
    }
}

pub(super) async fn serve_receiver(
    receiver: Arc<super::shell_transport::AppApprovalReceiver>,
    listener: TcpListener,
) -> Result<()> {
    serve(
        Endpoint::Receiver(receiver),
        listener,
        32,
        Arc::new(AtomicBool::new(true)),
        std::future::pending(),
    )
    .await
}

/// The only value returned to the launcher is completion DATA. The endpoint is
/// moved to its final thread before it can acquire a native original.
pub(crate) async fn serve(
    endpoint: Endpoint,
    listener: TcpListener,
    capacity: usize,
    admission: Arc<AtomicBool>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    ensure!(
        (1..=256).contains(&capacity),
        "invalid native HTTP capacity"
    );
    launch(
        Launch::Ready {
            endpoint,
            listener,
            capacity,
            admission,
        },
        shutdown,
    )
    .await
}

pub(crate) async fn serve_app(
    startup: crate::deployment::NativeAppStartup,
    admission: Arc<AtomicBool>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    launch(Launch::App(Box::new(startup), admission), shutdown).await
}

enum Launch {
    Ready {
        endpoint: Endpoint,
        listener: TcpListener,
        capacity: usize,
        admission: Arc<AtomicBool>,
    },
    App(Box<crate::deployment::NativeAppStartup>, Arc<AtomicBool>),
}

impl Launch {
    async fn run(self, shutdown: impl Future<Output = ()>) -> Result<()> {
        match self {
            Self::Ready {
                endpoint,
                listener,
                capacity,
                admission,
            } => run(endpoint, listener, capacity, admission, shutdown, false).await,
            Self::App(startup, admission) => {
                let scopes = startup.selections()?;
                super::native_management::install(
                    &scopes,
                    crate::security_epoch::native_enrollment::NativeRole::AppHost,
                )?;
                let (host, listener) = (*startup).prepare(admission.clone())?;
                ensure!(
                    crate::web::native_selections(&host)? == scopes,
                    "native App startup scope changed"
                );
                run(
                    Endpoint::App(host),
                    listener,
                    crate::web::MAX_QUEUED,
                    admission,
                    shutdown,
                    true,
                )
                .await
            }
        }
    }
}

async fn launch(launch: Launch, shutdown: impl Future<Output = ()> + Send + 'static) -> Result<()> {
    let reactor = Handle::try_current().context("native HTTP readiness runtime missing")?;
    let effects = crate::managed_credentials::effects::capture();
    let (completed, completion) = tokio::sync::oneshot::channel();
    // Dropping the launcher's receiver cannot cancel native work or free its
    // capacity. The thread owns every live connection until drain completes.
    OWNER_THREADS
        .lock()
        .map_err(|_| anyhow::anyhow!("native HTTP executor registry refused"))?
        .spawn(move || {
            REACTOR.with(|slot| *slot.borrow_mut() = Some(reactor));
            let result = effects.run(|| futures_executor::block_on(launch.run(shutdown)));
            REACTOR.with(|slot| slot.borrow_mut().take());
            let _ = completed.send(result);
        })?;
    completion.await.context("native HTTP owner terminated")?
}

/// Local readiness only. Each timer is armed once from a fresh projection of
/// the actual material's fixed BOOTTIME due time. Requests never re-arm it.
/// Neither a fired timer nor empty queues can supply native idle permission.
#[derive(Default)]
struct IdleSchedule {
    waiting: Vec<(
        super::native_management::IdleCredentialWake,
        super::effects::ReadinessTimer,
    )>,
    due: Option<super::native_management::IdleCredentialWake>,
    retry: Option<super::effects::ReadinessTimer>,
}

impl IdleSchedule {
    fn extend(
        &mut self,
        wakes: Vec<super::native_management::IdleCredentialWake>,
        anchor: super::effects::ReadinessInstant,
    ) -> Result<()> {
        for wake in wakes {
            ensure!(
                self.due.as_ref().is_none_or(|due| due.scope != wake.scope)
                    && self.waiting.iter().all(|(old, _)| old.scope != wake.scope),
                "native idle credential wake repeated"
            );
            ensure!(
                self.waiting.len() < 128,
                "native idle credential wake capacity"
            );
            let deadline = anchor
                .checked_add(wake.delay)
                .context("native idle credential timer overflow")?;
            let sleep = super::effects::ReadinessTimer::at(deadline);
            self.waiting.push((wake, sleep));
        }
        self.waiting.sort_by_key(|(_, sleep)| sleep.deadline());
        Ok(())
    }

    fn paused(&self) -> bool {
        self.due.is_some()
    }

    fn ready(&self) -> Option<&super::native_management::IdleCredentialWake> {
        self.due.as_ref().filter(|_| self.retry.is_none())
    }

    async fn wait(&mut self) {
        if let Some(retry) = &mut self.retry {
            retry.await;
            self.retry = None;
        } else if let Some((_, sleep)) = self.waiting.first_mut() {
            sleep.await;
            self.due = Some(self.waiting.remove(0).0);
        } else {
            std::future::pending::<()>().await;
        }
    }

    fn defer_busy(&mut self) {
        // Only a pre-clock/pre-I/O actual-owner Busy may defer. This timer
        // changes no credential, original, expiry, due time or admission latch.
        self.retry = Some(super::effects::ReadinessTimer::after(
            std::time::Duration::from_millis(10),
        ));
    }

    fn published(
        &mut self,
        wakes: Vec<super::native_management::IdleCredentialWake>,
        anchor: super::effects::ReadinessInstant,
    ) -> Result<()> {
        self.due.take();
        self.retry.take();
        self.extend(wakes, anchor)
    }
}

async fn run(
    endpoint: Endpoint,
    listener: TcpListener,
    capacity: usize,
    admission: Arc<AtomicBool>,
    shutdown: impl Future<Output = ()>,
    enrolled: bool,
) -> Result<()> {
    let owner = std::thread::current().id();
    // Fixtures create their originals on this final executor too. Only Send
    // metadata may return to the test driver; native owners never move.
    #[cfg(test)]
    let endpoint = match endpoint {
        Endpoint::Prepared(endpoint, prepare) => {
            prepare()?;
            *endpoint
        }
        endpoint => endpoint,
    };
    if !enrolled {
        endpoint.install()?;
    }
    let (live_sender, mut live_receiver) = tokio::sync::mpsc::channel(32);
    LIVE.with(|slot| slot.replace(Some(live_sender)));
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            super::native_management::clear();
            LIVE.with(|slot| slot.borrow_mut().take());
        }
    }
    let _clear = Clear;
    let endpoint = &endpoint;
    let (pump_stop, pump_stopped) = tokio::sync::watch::channel(false);
    let mut pump = std::pin::pin!(endpoint.pump(pump_stopped));
    let mut pump_finished = !matches!(endpoint, Endpoint::App(_));
    let mut connections = FuturesUnordered::new();
    let mut live = FuturesUnordered::new();
    let mut shutdown = std::pin::pin!(shutdown);
    let mut draining = false;
    let mut idle = IdleSchedule::default();
    // Capture BEFORE taking the fresh BOOTTIME-derived delays. Collection or
    // postprocessing cannot push a timer later by starting its duration again.
    let anchor = super::effects::ReadinessInstant::now();
    if let Err(error) = endpoint
        .take_idle_credential_wakes()
        .and_then(|wakes| idle.extend(wakes, anchor))
    {
        admission.store(false, Ordering::Release);
        return Err(error);
    }
    loop {
        if draining && connections.is_empty() && live.is_empty() && pump_finished {
            return Ok(());
        }
        if !draining
            && admission.load(Ordering::Acquire)
            && connections.is_empty()
            && live.is_empty()
            && live_receiver.is_empty()
            && let Some(wake) = idle.ready()
        {
            let result = super::native_management::readmit_idle_credential(wake);
            match result {
                Ok(super::native_management::IdleReadmission::Busy) => idle.defer_busy(),
                Ok(super::native_management::IdleReadmission::Published) => {
                    let anchor = super::effects::ReadinessInstant::now();
                    if let Err(error) = endpoint
                        .take_idle_credential_wakes()
                        .and_then(|wakes| idle.published(wakes, anchor))
                    {
                        admission.store(false, Ordering::Release);
                        return Err(error);
                    }
                }
                Err(error) => {
                    admission.store(false, Ordering::Release);
                    return Err(error);
                }
            }
        }
        let idle_paused = idle.paused();
        let idle_retry = idle.retry.is_some();
        tokio::select! {
            biased;
            _ = &mut shutdown, if !draining => {
                draining = true;
                admission.store(false, Ordering::Release);
                let _ = pump_stop.send(true);
                live_receiver.close();
                while live_receiver.try_recv().is_ok() {} // Not-started work owns no external send.
            }
            _ = idle.wait(), if !draining && admission.load(Ordering::Acquire) && (!idle_paused || idle_retry) => {
                #[cfg(test)]
                if let Endpoint::Test(exchange) = endpoint {
                    exchange.idle_paused.notify_one();
                }
            }
            result = &mut pump, if !pump_finished && (!idle_paused || draining || !admission.load(Ordering::Acquire)) => {
                result?;
                pump_finished = true;
                ensure!(!admission.load(Ordering::Acquire), "native App pump completed with admission open");
                // Admission stop drains background work; explicit shutdown
                // drains the listener. Keep idle health/refusal responses
                // available between those distinct lifecycle events.
                live_receiver.close();
                while live_receiver.try_recv().is_ok() {}
            }
            work = live_receiver.recv(), if !draining && !live_receiver.is_closed() => {
                if let Some(work) = work { live.push(work.run()); }
            }
            _ = live.next(), if !live.is_empty() => {}
            _ = connections.next(), if !connections.is_empty() => {}
            accepted = futures_util::future::poll_fn(|cx| timer(|| listener.poll_accept(cx))), if !draining && !idle_paused && connections.len() < capacity => {
                let (stream, _) = accepted?;
                let sink = super::native_management::Sink::new();
                let driver = std::rc::Rc::new(RefCell::new(None));
                let connection_io = OwnerIo { inner: std::rc::Rc::new(RefCell::new(TokioIo::new(stream))), owner, sink: sink.clone(), driver: driver.clone(),
                    #[cfg(test)]
                    exchange: match endpoint { Endpoint::Test(exchange) => Some(exchange.clone()), _ => None },
                };
                let admitted = admission.clone();
                connections.push(async move {
                    struct Completion {
                        sink: super::native_management::Sink,
                        known: bool,
                    }
                    impl Drop for Completion {
                        fn drop(&mut self) {
                            if !self.known { self.sink.abort(); }
                        }
                    }
                    let mut completion = Completion { sink: sink.clone(), known: false };
                    let service_driver = driver.clone();
                    let service_inner = connection_io.inner.clone();
                    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                        let admitted = admitted.clone();
                        let sink = sink.clone();
                        let driver_slot = service_driver.clone();
                        let inner = service_inner.clone();
                        let captured = endpoint.capture_request(&sink, &request);
                        async move {
                            if matches!(captured, Ok(None))
                                && let Endpoint::App(host) = endpoint
                                && crate::web::native_host_candidate(host, &request)
                            {
                                let result = host.prepared_host_effects().run_async(sink.scope(async {
                                    let prepared = crate::web::prepare_host_request(host.clone(), request.map(Body::new)).await?;
                                    let scope = crate::web::native_runtime_response_scope(host)?.context("native host response scope absent")?;
                                    sink.begin_host_request(&scope)?;
                                    let driver = response_io::Driver::for_host(inner, sink.clone(), host.clone(), prepared);
                                    {
                                        let mut slot = driver_slot.try_borrow_mut()?;
                                        ensure!(slot.is_none(), "native host driver already installed");
                                        *slot = Some(driver.clone());
                                    }
                                    // Install BEFORE polling SQL. There is no fake
                                    // socket command and no first-write dependency.
                                    Ok::<_, anyhow::Error>(std::future::poll_fn(|cx| driver.poll_host_reply(cx)).await?)
                                })).await;
                                return result.map_err(|_| {
                                    sink.abort();
                                    io::Error::other("native host request authority unavailable")
                                });
                            }
                            let response = match captured {
                                Ok(Some(literal)) => literal,
                                Ok(None) => sink.scope(endpoint.handle(request.map(Body::new), admitted)).await,
                                Err(_) => {
                                    sink.abort();
                                    return Err(io::Error::other("native request authority unavailable"));
                                }
                            };
                            let finite = finite_app_body_candidate(response.response());
                            if endpoint.prepare_response(&sink, &response, finite).is_err() {
                                sink.abort();
                                return Err(io::Error::other("native response authority unavailable"));
                            }
                            match sink.scope(prepare_finite_app_body(response.into_response(), &sink)).await {
                                Ok(response) => Ok::<_, io::Error>(response),
                                Err(_) => {
                                    sink.abort();
                                    Err(io::Error::other("native finite response preparation unavailable"))
                                }
                            }
                        }
                    });
                    // A failed write means delivery is unknown/failed. Never
                    // replay the handler or turn it into a successful receipt.
                    let connection = http1::Builder::new().keep_alive(false)
                        .timer(OwnerTimer)
                        .header_read_timeout(std::time::Duration::from_secs(3))
                        .serve_connection(connection_io, service);
                    #[cfg(test)]
                    let original_not_before = super::effects::ReadinessInstant::now().checked_add(std::time::Duration::from_secs(30)).expect("test transport deadline overflow");
                    let bounded = timer(|| tokio::time::timeout(std::time::Duration::from_secs(30), connection));
                    #[cfg(test)]
                    if let Endpoint::Test(exchange) = endpoint {
                        exchange.connection_deadlines.lock().unwrap().push(original_not_before);
                    }
                    if let Ok(Ok(())) = bounded.await {
                        // Known local transport completion only. This is not
                        // evidence that a browser/human received the bytes.
                        // Hyper may already have dropped OwnerIo. The retained
                        // handle finishes THIS driver, never a replacement.
                        let held = driver.borrow().clone();
                        completion.known = match held {
                            Some(driver) => driver.finish().await.is_ok(),
                            None => completion.sink.finish().is_ok(),
                        };
                    }
                    let held = driver.borrow().clone();
                    if let Some(driver) = held {
                        if !completion.known { driver.abort(); }
                        // No native owner remains borrowed during DATA export.
                        // Missing output is never a known delivery receipt.
                        driver.report();
                    }
                });
            }
        }
    }
}

/// This wraps the socket, not just Body::poll_frame: response headers, buffered
/// body writes, flush and shutdown all run on the native owning OS thread.
struct OwnerIo<T> {
    inner: std::rc::Rc<RefCell<T>>,
    owner: ThreadId,
    sink: super::native_management::Sink,
    driver: std::rc::Rc<RefCell<Option<response_io::Driver>>>,
    #[cfg(test)]
    exchange: Option<Arc<tests::Exchange>>,
}

#[derive(Clone, Copy)]
struct OwnerTimer;

impl rt::Timer for OwnerTimer {
    fn sleep(&self, duration: std::time::Duration) -> Pin<Box<dyn rt::Sleep>> {
        timer(|| rt::Timer::sleep(&hyper_util::rt::TokioTimer::new(), duration))
    }

    fn sleep_until(&self, deadline: std::time::Instant) -> Pin<Box<dyn rt::Sleep>> {
        timer(|| rt::Timer::sleep_until(&hyper_util::rt::TokioTimer::new(), deadline))
    }
}

impl<T> OwnerIo<T> {
    fn check(&self) -> io::Result<()> {
        if std::thread::current().id() != self.owner {
            return Err(io::Error::other("native HTTP executor changed"));
        }
        Ok(())
    }
}

impl<T: rt::Write + Unpin + 'static> OwnerIo<T> {
    fn response_driver(&self) -> Option<response_io::Driver> {
        if let Some(driver) = self.driver.borrow().as_ref() {
            return Some(driver.clone());
        }
        if !self.sink.uses_retained_app_io() {
            return None;
        }
        Some(
            self.driver
                .borrow_mut()
                .get_or_insert_with(|| {
                    response_io::Driver::new(self.inner.clone(), self.sink.clone())
                })
                .clone(),
        )
    }
}

impl<T: rt::Read + Unpin> rt::Read for OwnerIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut *self.inner.borrow_mut()).poll_read(cx, buf)
    }
}

impl<T: rt::Write + Unpin + 'static> rt::Write for OwnerIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        #[cfg(test)]
        if let Some(exchange) = &self.exchange {
            exchange
                .writes
                .lock()
                .unwrap()
                .push(std::thread::current().id());
        }
        let this = self.get_mut();
        if let Some(driver) = this.response_driver() {
            return driver.poll_write(cx, bytes);
        }
        this.sink
            .poll_io(|| Pin::new(&mut *this.inner.borrow_mut()).poll_write(cx, bytes))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        let this = self.get_mut();
        if let Some(driver) = this.response_driver() {
            return driver.poll_flush(cx);
        }
        this.sink
            .poll_io(|| Pin::new(&mut *this.inner.borrow_mut()).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        let this = self.get_mut();
        if let Some(driver) = this.response_driver() {
            return driver.poll_shutdown(cx);
        }
        this.sink
            .poll_io(|| Pin::new(&mut *this.inner.borrow_mut()).poll_shutdown(cx))
    }
}

/// Only a bounded, fully prepared App body enters a retained delivery scope.
/// Unknown-length/live bodies retain their existing admission choreography: do
/// not lease an owner that their producer still needs to render the next frame.
pub(in crate::oauth) async fn prepare_finite_app_body(
    response: Response,
    sink: &super::native_management::Sink,
) -> Result<Response> {
    use hyper::body::Body as _;
    const MAX_BODY: usize = 64 * 1024;
    const MAX_FRAMES: usize = 64;
    if !sink.can_retain_app_response()? {
        return Ok(response);
    }
    let Some(exact) = response
        .body()
        .size_hint()
        .exact()
        .filter(|size| *size <= MAX_BODY as u64)
    else {
        return Ok(response);
    };
    let (parts, body) = response.into_parts();
    let mut body = std::pin::pin!(body);
    let mut frames = std::collections::VecDeque::new();
    let mut bytes = 0usize;
    let mut metadata = 0usize;
    while let Some(frame) = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
        let frame = frame?;
        ensure!(
            frames.len() < MAX_FRAMES,
            "native finite response frame budget"
        );
        if let Some(data) = frame.data_ref() {
            bytes = bytes
                .checked_add(data.len())
                .context("native finite response byte overflow")?;
            ensure!(
                bytes <= MAX_BODY && bytes as u64 <= exact,
                "native finite response byte budget"
            );
        }
        if let Some(trailers) = frame.trailers_ref() {
            for (name, value) in trailers {
                metadata = metadata
                    .checked_add(name.as_str().len())
                    .and_then(|total| total.checked_add(value.len()))
                    .context("native finite response trailer overflow")?;
                ensure!(
                    metadata <= MAX_BODY,
                    "native finite response trailer budget"
                );
            }
        }
        frames.push_back(frame);
    }
    ensure!(
        bytes as u64 == exact,
        "native finite response length changed"
    );
    sink.retain_finite_app_io()?;
    Ok(Response::from_parts(
        parts,
        Body::new(PreparedBody {
            frames,
            remaining: exact,
        }),
    ))
}

fn finite_app_body_candidate(response: &Response) -> bool {
    use hyper::body::Body as _;
    response
        .body()
        .size_hint()
        .exact()
        .is_some_and(|size| size <= 64 * 1024)
}

struct PreparedBody {
    frames: std::collections::VecDeque<hyper::body::Frame<axum::body::Bytes>>,
    remaining: u64,
}

impl hyper::body::Body for PreparedBody {
    type Data = axum::body::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let frame = self.frames.pop_front();
        if let Some(data) = frame.as_ref().and_then(|frame| frame.data_ref()) {
            self.remaining -= data.len() as u64;
        }
        Poll::Ready(frame.map(Ok))
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.remaining)
    }
}

#[cfg(test)]
mod finite_response_tests {
    use super::*;
    use axum::body::Bytes;
    use hyper::body::Body as _;
    use std::{cell::Cell, rc::Rc};

    #[test]
    fn literal_platform_health_never_resolves_or_acquires_current() -> Result<()> {
        futures_executor::block_on(async {
            for ready in [false, true] {
                let response = crate::web::literal_health_fixture(&axum::http::Method::GET, ready);
                let called = Cell::new(0);
                let scope = response.app_scope(|| {
                    called.set(called.get() + 1);
                    anyhow::bail!("native supplier must not be entered by a literal probe")
                })?;
                assert!(scope.is_none());
                assert_eq!(called.get(), 0);
                let sink = super::super::native_management::Sink::new();
                sink.capture_literal_health(&response)?;
                sink.prepare_response(scope, false)?;
                let response = prepare_finite_app_body(response.into_response(), &sink).await?;
                assert!(!sink.uses_retained_app_io());
                assert!(
                    axum::body::to_bytes(response.into_body(), 1)
                        .await?
                        .is_empty()
                );
                sink.finish()?;
            }
            Ok(())
        })
    }

    #[test]
    fn ordinary_or_spoofed_empty_responses_still_require_the_real_app_scope() {
        for body in [Body::empty(), Body::from("private app result")] {
            let mut raw =
                crate::web::literal_health_fixture(&axum::http::Method::GET, true).into_response();
            *raw.body_mut() = body;
            raw.headers_mut()
                .insert("x-native-health", "true".parse().unwrap());
            let response = crate::web::NativeResponse::application(raw);
            let sink = super::super::native_management::Sink::new();
            assert!(sink.capture_literal_health(&response).is_err());
            let called = Cell::new(0);
            assert!(
                response
                    .app_scope(|| {
                        called.set(called.get() + 1);
                        anyhow::bail!("actual current supplier absent")
                    })
                    .is_err()
            );
            assert_eq!(called.get(), 1);
        }
    }

    fn app_scope_wiring_is_preserved(source: &str) -> bool {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Calls {
            scoped: usize,
            direct: usize,
            valid: bool,
        }
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
                if node.method == "app_scope" {
                    self.scoped += 1;
                    self.valid = matches!(&*node.receiver, syn::Expr::Path(path) if path.path.is_ident("response"))
                        && node.args.len() == 1
                        && matches!(&node.args[0], syn::Expr::Closure(closure)
                            if matches!(&*closure.body, syn::Expr::Call(call)
                                if matches!(&*call.func, syn::Expr::Path(path)
                                    if path.path.segments.iter().map(|part| part.ident.to_string()).collect::<Vec<_>>() == ["crate", "web", "native_runtime_response_scope"])
                                && call.args.len() == 1
                                && matches!(&call.args[0], syn::Expr::Path(path) if path.path.is_ident("host"))));
                    return;
                }
                syn::visit::visit_expr_method_call(self, node);
            }
            fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
                if matches!(&*node.func, syn::Expr::Path(path)
                    if path.path.segments.last().is_some_and(|part| part.ident == "native_runtime_response_scope"))
                {
                    self.direct += 1;
                }
                syn::visit::visit_expr_call(self, node);
            }
        }
        let file = syn::parse_file(source).unwrap();
        let mut selected = Vec::new();
        for item in &file.items {
            if let syn::Item::Impl(item) = item
                && matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("Endpoint"))
            {
                for method in &item.items {
                    if let syn::ImplItem::Fn(method) = method
                        && method.sig.ident == "prepare_response"
                    {
                        selected.push(&method.block);
                    }
                }
            }
        }
        assert_eq!(selected.len(), 1);
        let mut calls = Calls::default();
        calls.visit_block(selected[0]);
        calls.valid && calls.scoped == 1 && calls.direct == 0
    }

    #[test]
    fn actual_app_response_boundary_uses_the_closed_health_classification() {
        let source = include_str!("native_http.rs");
        assert!(app_scope_wiring_is_preserved(source));
        let selected = concat!(
            "response.app_scope(|| crate::web::",
            "native_runtime_response_scope(host))?"
        );
        assert_eq!(source.matches(selected).count(), 1);
        let old = source.replacen(
            selected,
            "crate::web::native_runtime_response_scope(host)?",
            1,
        );
        assert!(!app_scope_wiring_is_preserved(&old));
    }

    fn metadata_sink() -> super::super::native_management::Sink {
        super::super::native_management::Sink::fixture_unowned_app_response(
            day2_capabilities::security_epoch::AuthorityScope {
                installation: "testco".to_owned().try_into().unwrap(),
                environment: "test".to_owned().try_into().unwrap(),
                app: "calendar".to_owned().try_into().unwrap(),
            },
        )
    }

    #[test]
    fn simulated_owners_cannot_select_the_actual_native_response_driver() {
        let world = super::super::simulation::World::new(917);
        super::super::effects::scope(world, || {
            futures_executor::block_on(async {
                let sink = metadata_sink();
                assert!(!sink.can_retain_app_response().unwrap());
                assert!(sink.retain_finite_app_io().is_err());
                // This deferred body asserts that it is polled only for a
                // genuine native candidate. Model selection leaves it alone.
                let response = prepare_finite_app_body(
                    Response::new(Body::new(Deferred { produced: false })),
                    &sink,
                )
                .await
                .unwrap();
                assert!(!sink.uses_retained_app_io());
                drop(response);
            });
        });
        // Without a model hook, this DATA-only fixture still selects the real
        // driver, which must refuse its missing enrolled owner before I/O.
        assert!(metadata_sink().can_retain_app_response().unwrap());
    }

    struct Deferred {
        produced: bool,
    }

    impl hyper::body::Body for Deferred {
        type Data = Bytes;
        type Error = io::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
        ) -> Poll<Option<io::Result<hyper::body::Frame<Bytes>>>> {
            let sink = super::super::native_management::current_sink().unwrap();
            assert!(
                !sink.uses_retained_app_io(),
                "body production precedes the native lease"
            );
            assert!(sink.can_retain_app_response().unwrap());
            if std::mem::replace(&mut self.produced, true) {
                Poll::Ready(None)
            } else {
                Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_static(
                    b"abc",
                )))))
            }
        }
        fn size_hint(&self) -> hyper::body::SizeHint {
            hyper::body::SizeHint::with_exact(if self.produced { 0 } else { 3 })
        }
    }

    #[test]
    fn deferred_finite_body_finishes_before_lease_and_preserves_headers_and_trailers() {
        futures_executor::block_on(async {
            let sink = metadata_sink();
            let response = Response::new(Body::new(Deferred { produced: false }));
            let response = sink
                .scope(prepare_finite_app_body(response, &sink))
                .await
                .unwrap();
            assert!(sink.uses_retained_app_io());
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 10)
                    .await
                    .unwrap(),
                b"abc"[..]
            );

            let sink = metadata_sink();
            let mut trailers = axum::http::HeaderMap::new();
            trailers.insert("x-delivery", "same".parse().unwrap());
            let mut response = Response::new(Body::new(PreparedBody {
                frames: [
                    hyper::body::Frame::data(Bytes::from_static(b"abc")),
                    hyper::body::Frame::trailers(trailers.clone()),
                ]
                .into(),
                remaining: 3,
            }));
            response
                .headers_mut()
                .insert("x-owner", "original".parse().unwrap());
            let response = prepare_finite_app_body(response, &sink).await.unwrap();
            assert_eq!(response.headers()["x-owner"], "original");
            let mut body = Box::pin(response.into_body());
            let first = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first.data_ref().unwrap(), &Bytes::from_static(b"abc"));
            let second = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(second.trailers_ref().unwrap(), &trailers);
            assert!(
                std::future::poll_fn(|cx| body.as_mut().poll_frame(cx))
                    .await
                    .is_none()
            );
        });
    }

    #[test]
    fn finite_preparation_rejects_size_lies_and_frame_overflow_without_selecting_io() {
        futures_executor::block_on(async {
            for (frames, remaining) in [
                (
                    [hyper::body::Frame::data(Bytes::from_static(b"abc"))]
                        .into_iter()
                        .collect(),
                    4,
                ),
                (
                    (0..65)
                        .map(|_| hyper::body::Frame::data(Bytes::new()))
                        .collect(),
                    0,
                ),
            ] {
                let sink = metadata_sink();
                let response = Response::new(Body::new(PreparedBody { frames, remaining }));
                assert!(prepare_finite_app_body(response, &sink).await.is_err());
                assert!(!sink.uses_retained_app_io());
            }
        });
    }

    #[test]
    fn docs_asset_not_modified_keeps_empty_finite_body_and_representation_length() {
        futures_executor::block_on(async {
            for path in [
                "/assets/platform/api-docs.js",
                "/assets/platform/api-docs.css",
            ] {
                let selected =
                    crate::web_assets::platform(path, &axum::http::HeaderMap::new()).unwrap();
                let original_length =
                    selected.headers()[axum::http::header::CONTENT_LENGTH].clone();
                let mut headers = axum::http::HeaderMap::new();
                headers.insert(
                    axum::http::header::IF_NONE_MATCH,
                    selected.headers()[axum::http::header::ETAG].clone(),
                );
                let response = crate::web_assets::platform(path, &headers).unwrap();
                assert_eq!(response.status(), axum::http::StatusCode::NOT_MODIFIED);
                let sink = metadata_sink();
                let response = prepare_finite_app_body(response, &sink).await.unwrap();
                assert!(sink.uses_retained_app_io());
                assert_eq!(
                    response.headers()[axum::http::header::CONTENT_LENGTH],
                    original_length
                );
                assert_eq!(response.body().size_hint().exact(), Some(0));
                assert!(
                    axum::body::to_bytes(response.into_body(), 65_536)
                        .await
                        .unwrap()
                        .is_empty()
                );
                // This fixture supplies only classification DATA. A passing
                // body check never creates a native owner or settles delivery.
                assert!(!sink.is_complete());
            }
        });
    }

    #[test]
    fn live_and_large_bodies_keep_their_existing_scope_choreography() {
        futures_executor::block_on(async {
            let sink = metadata_sink();
            let polled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let captured = polled.clone();
            let body = Body::from_stream(futures_util::stream::once(async move {
                captured.fetch_add(1, Ordering::Relaxed);
                Ok::<_, io::Error>(Bytes::from_static(b"live"))
            }));
            let response = prepare_finite_app_body(Response::new(body), &sink)
                .await
                .unwrap();
            assert!(!sink.uses_retained_app_io());
            assert_eq!(polled.load(Ordering::Relaxed), 0);
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 10)
                    .await
                    .unwrap(),
                b"live"[..]
            );
            assert_eq!(polled.load(Ordering::Relaxed), 1);

            let sink = metadata_sink();
            let response =
                prepare_finite_app_body(Response::new(Body::from(vec![b'x'; 65537])), &sink)
                    .await
                    .unwrap();
            assert!(!sink.uses_retained_app_io());
            assert_eq!(response.body().size_hint().exact(), Some(65537));
        });
    }

    #[test]
    fn classification_data_cannot_create_native_owner_or_write_socket_bytes() {
        struct Socket(Rc<Cell<u32>>);
        impl rt::Write for Socket {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.0.set(self.0.get() + 1);
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
                self.0.set(self.0.get() + 1);
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
            ) -> Poll<io::Result<()>> {
                self.0.set(self.0.get() + 1);
                Poll::Ready(Ok(()))
            }
        }
        let sink = metadata_sink();
        let _ = futures_executor::block_on(prepare_finite_app_body(
            Response::new(Body::from("abc")),
            &sink,
        ))
        .unwrap();
        let polls = Rc::new(Cell::new(0));
        let mut io = OwnerIo {
            inner: Rc::new(RefCell::new(Socket(polls.clone()))),
            owner: std::thread::current().id(),
            sink: sink.clone(),
            driver: Rc::new(RefCell::new(None)),
            exchange: None,
        };
        let mut cx = TaskContext::from_waker(futures_util::task::noop_waker_ref());
        assert!(matches!(
            rt::Write::poll_write(Pin::new(&mut io), &mut cx, b"abc"),
            Poll::Ready(Err(_))
        ));
        assert_eq!(polls.get(), 0);
        assert!(!sink.is_open());
        assert!(matches!(
            rt::Write::poll_shutdown(Pin::new(&mut io), &mut cx),
            Poll::Ready(Err(_))
        ));
        assert_eq!(polls.get(), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use std::sync::{Condvar, Mutex};
    use std::thread;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn idle_wake(app: &str, seconds: u64) -> super::super::native_management::IdleCredentialWake {
        super::super::native_management::IdleCredentialWake {
            scope: day2_capabilities::security_epoch::AuthorityScope {
                installation: "example".to_owned().try_into().unwrap(),
                environment: "development".to_owned().try_into().unwrap(),
                app: app.to_owned().try_into().unwrap(),
            },
            delay: std::time::Duration::from_secs(seconds),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_wakes_keep_distinct_fixed_due_times_across_busy_and_publication() -> Result<()> {
        use futures_util::FutureExt;
        let start = super::super::effects::ReadinessInstant::now();
        let mut idle = IdleSchedule::default();
        idle.extend(vec![idle_wake("later", 40), idle_wake("first", 20)], start)?;
        assert!(!idle.paused());
        tokio::time::advance(std::time::Duration::from_secs(19)).await;
        assert!(idle.wait().now_or_never().is_none());
        assert!(!idle.paused());
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        idle.wait().await;
        assert_eq!(idle.ready().unwrap().scope.app.as_str(), "first");
        idle.defer_busy();
        assert!(idle.paused());
        assert!(idle.ready().is_none());
        tokio::time::advance(std::time::Duration::from_secs(7)).await;
        idle.wait().await;
        assert_eq!(idle.ready().unwrap().scope.app.as_str(), "first");
        idle.published(
            vec![idle_wake("first", 60)],
            super::super::effects::ReadinessInstant::now(),
        )?;
        assert!(!idle.paused());
        // Publishing one owner at t=27 cannot renew another owner's t=40
        // readiness projection, nor reuse the completed owner's old wake.
        assert_eq!(
            idle.waiting[0].1.deadline(),
            start
                .checked_add(std::time::Duration::from_secs(40))
                .unwrap()
        );
        assert_eq!(
            idle.waiting[1].1.deadline(),
            start
                .checked_add(std::time::Duration::from_secs(87))
                .unwrap()
        );
        tokio::time::advance(std::time::Duration::from_secs(13)).await;
        idle.wait().await;
        assert_eq!(idle.ready().unwrap().scope.app.as_str(), "later");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn idle_wake_cancellation_and_duplicate_hints_cannot_rearm_due_work() -> Result<()> {
        use futures_util::FutureExt;
        let mut idle = IdleSchedule::default();
        idle.extend(
            vec![idle_wake("reports", 5)],
            super::super::effects::ReadinessInstant::now(),
        )?;
        let deadline = idle.waiting[0].1.deadline();
        for _ in 0..4 {
            assert!(idle.wait().now_or_never().is_none());
            tokio::time::advance(std::time::Duration::from_secs(1)).await;
            assert_eq!(idle.waiting[0].1.deadline(), deadline);
        }
        assert!(
            idle.extend(
                vec![idle_wake("reports", 60)],
                super::super::effects::ReadinessInstant::now()
            )
            .is_err()
        );
        tokio::time::advance(std::time::Duration::from_secs(9)).await;
        idle.wait().await;
        assert!(idle.paused());
        assert!(
            idle.extend(
                vec![idle_wake("reports", 60)],
                super::super::effects::ReadinessInstant::now()
            )
            .is_err()
        );
        assert_eq!(idle.ready().unwrap().scope.app.as_str(), "reports");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn idle_projection_collection_cannot_start_a_fresh_late_relative_timer() -> Result<()> {
        let anchor = super::super::effects::ReadinessInstant::now();
        tokio::time::advance(std::time::Duration::from_secs(7)).await;
        let mut idle = IdleSchedule::default();
        idle.extend(vec![idle_wake("reports", 20)], anchor)?;
        assert_eq!(
            idle.waiting[0].1.deadline(),
            anchor
                .checked_add(std::time::Duration::from_secs(20))
                .unwrap()
        );
        // A caller-supplied impossible DATA duration is an error, not a panic
        // or a deadline wrapping into a new future interval.
        let mut overflow = idle_wake("other", 0);
        overflow.delay = std::time::Duration::MAX;
        assert!(idle.extend(vec![overflow], anchor).is_err());
        Ok(())
    }

    #[test]
    fn terminal_close_joins_tls_teardown_and_permanently_refuses_new_launches() -> Result<()> {
        struct ExitGate {
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }
        impl Drop for ExitGate {
            fn drop(&mut self) {
                let _ = self.entered.send(());
                let _ = self.release.recv();
            }
        }
        thread_local! {
            static EXIT_GATE: RefCell<Option<ExitGate>> = const { RefCell::new(None) };
        }
        let (entered, at_exit) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let mut owners = OwnerThreads::default();
        owners.spawn(move || {
            EXIT_GATE.with(|slot| {
                slot.replace(Some(ExitGate {
                    entered,
                    release: released,
                }));
            });
        })?;
        at_exit.recv_timeout(std::time::Duration::from_secs(2))?;
        let (started, threads) = owners.close();
        assert!(started && owners.closed);
        let (finished, observed) = std::sync::mpsc::channel();
        let joined = thread::spawn(move || {
            let result = join_owner_threads(threads);
            let _ = finished.send(result);
        });
        assert!(
            observed
                .recv_timeout(std::time::Duration::from_millis(20))
                .is_err()
        );
        release.send(())?;
        observed.recv_timeout(std::time::Duration::from_secs(2))??;
        joined.join().unwrap();
        let ran = Arc::new(AtomicBool::new(false));
        let attempted = ran.clone();
        assert!(
            owners
                .spawn(move || attempted.store(true, Ordering::Release))
                .is_err()
        );
        assert!(!ran.load(Ordering::Acquire));
        assert!(owners.close().1.is_empty());
        Ok(())
    }

    pub(crate) struct Exchange {
        calls: Mutex<Vec<ThreadId>>,
        bodies: Mutex<Vec<ThreadId>>,
        pub(super) writes: Mutex<Vec<ThreadId>>,
        pub(super) background: Mutex<Vec<ThreadId>>,
        entered: tokio::sync::Notify,
        pub(super) idle_wakes: Mutex<Vec<super::super::native_management::IdleCredentialWake>>,
        pub(super) idle_paused: tokio::sync::Notify,
        pub(super) connection_deadlines: Mutex<Vec<super::super::effects::ReadinessInstant>>,
        release: (Mutex<bool>, Condvar),
        large: bool,
    }

    impl Exchange {
        fn new(large: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                bodies: Mutex::new(Vec::new()),
                writes: Mutex::new(Vec::new()),
                background: Mutex::new(Vec::new()),
                entered: tokio::sync::Notify::new(),
                idle_wakes: Mutex::new(Vec::new()),
                idle_paused: tokio::sync::Notify::new(),
                connection_deadlines: Mutex::new(Vec::new()),
                release: (Mutex::new(false), Condvar::new()),
                large,
            })
        }

        pub(super) async fn handle(self: &Arc<Self>, request: Request) -> Response {
            assert!(
                Handle::try_current().is_err(),
                "dispatch must allow the blocking provider adapter"
            );
            self.calls.lock().unwrap().push(thread::current().id());
            self.entered.notify_one();
            if request.uri().path() == "/idle-stream" {
                return Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(Body::from_stream(futures_util::stream::pending::<
                        Result<Bytes, Infallible>,
                    >()))
                    .unwrap();
            }
            if request.uri().path() == "/live" {
                let (sender, receiver) = tokio::sync::oneshot::channel();
                let work = NativeLiveWork {
                    work: LiveJob::Probe(self.clone(), sender),
                    sink: super::super::native_management::current_sink().unwrap(),
                    effects: crate::managed_credentials::effects::capture(),
                };
                LIVE.with(|slot| {
                    slot.borrow()
                        .as_ref()
                        .unwrap()
                        .try_send(work)
                        .unwrap_or_else(|_| panic!("probe queue full"))
                });
                let exchange = self.clone();
                return Response::new(Body::from_stream(futures_util::stream::once(async move {
                    exchange.bodies.lock().unwrap().push(thread::current().id());
                    receiver.await.map(Bytes::from).map_err(io::Error::other)
                })));
            }
            if request.uri().path() == "/block" {
                let (lock, changed) = &self.release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = changed.wait(released).unwrap();
                }
            }
            let exchange = self.clone();
            let count = if self.large { 1024 } else { 1 };
            let body = Body::from_stream(futures_util::stream::unfold(
                (exchange, count),
                |(exchange, left)| async move {
                    if left == 0 {
                        return None;
                    }
                    exchange.bodies.lock().unwrap().push(thread::current().id());
                    Some((
                        Ok::<_, Infallible>(Bytes::from(vec![b'x'; 65536])),
                        (exchange, left - 1),
                    ))
                },
            ));
            Response::new(body)
        }
    }

    #[tokio::test]
    async fn idle_due_drains_actual_sse_timeout_before_attempting_real_owner_admission()
    -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let exchange = Exchange::new(false);
        exchange
            .idle_wakes
            .lock()
            .unwrap()
            .push(idle_wake("reports", 1));
        let admission = Arc::new(AtomicBool::new(true));
        let server = tokio::spawn(serve(
            Endpoint::Test(exchange.clone()),
            listener,
            2,
            admission.clone(),
            std::future::pending(),
        ));
        let mut streaming = tokio::net::TcpStream::connect(address).await?;
        streaming
            .write_all(b"GET /idle-stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            exchange.entered.notified(),
        )
        .await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            exchange.idle_paused.notified(),
        )
        .await?;
        // A real pending SSE connection is not queue-empty proof. A second
        // ready socket must not dispatch while the old connection drains.
        let mut queued = tokio::net::TcpStream::connect(address).await?;
        queued
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        assert!(!server.is_finished());
        assert_eq!(exchange.calls.lock().unwrap().len(), 1);
        assert!(admission.load(Ordering::Acquire));
        // Only the EXISTING socket timeout ends the stream. Readmission then
        // reaches the actual factory and refuses the absent native supplier.
        let result = tokio::time::timeout(std::time::Duration::from_secs(35), server).await??;
        let original_deadline = exchange.connection_deadlines.lock().unwrap()[0];
        assert!(
            super::super::effects::ReadinessInstant::now() >= original_deadline,
            "maintenance cancelled the accepted SSE before its original timeout"
        );
        assert!(matches!(result, Err(error)
            if error.to_string() == "native idle credential owner missing"));
        assert_eq!(exchange.calls.lock().unwrap().len(), 1);
        assert!(!admission.load(Ordering::Acquire));
        Ok(())
    }

    #[tokio::test]
    async fn owner_preparation_commits_before_http_and_refusal_never_dispatches() -> Result<()> {
        for refuse in [false, true] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("startup.sqlite");
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let exchange = Exchange::new(false);
            let entered = Arc::new(tokio::sync::Notify::new());
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            struct Release(Arc<(Mutex<bool>, Condvar)>);
            impl Drop for Release {
                fn drop(&mut self) {
                    *self.0.0.lock().unwrap() = true;
                    self.0.1.notify_all();
                }
            }
            let release = Release(gate.clone());
            let prepared_on = Arc::new(Mutex::new(None));
            let preparation = {
                let path = path.clone();
                let entered = entered.clone();
                let prepared_on = prepared_on.clone();
                move || {
                    *prepared_on.lock().unwrap() = Some(thread::current().id());
                    let mut db = rusqlite::Connection::open(path)?;
                    let tx = db.transaction()?;
                    tx.execute_batch(
                        "CREATE TABLE startup(value INTEGER); INSERT INTO startup VALUES(1);",
                    )?;
                    entered.notify_one();
                    let (lock, changed) = &*gate;
                    let (ready, timeout) = changed
                        .wait_timeout_while(
                            lock.lock().unwrap(),
                            std::time::Duration::from_secs(5),
                            |ready| !*ready,
                        )
                        .unwrap();
                    ensure!(
                        *ready && !timeout.timed_out(),
                        "startup test release watchdog"
                    );
                    ensure!(!refuse, "startup deliberately refused");
                    tx.commit()?;
                    Ok(())
                }
            };
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(serve(
                Endpoint::Prepared(
                    Box::new(Endpoint::Test(exchange.clone())),
                    Box::new(preparation),
                ),
                listener,
                1,
                Arc::new(AtomicBool::new(true)),
                async {
                    let _ = stopped.await;
                },
            ));
            let mut client = tokio::net::TcpStream::connect(address).await?;
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await?;
            tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified()).await?;
            assert!(exchange.calls.lock().unwrap().is_empty());
            let observer = rusqlite::Connection::open(path)?;
            let tables: i64 = observer.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='startup'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(tables, 0, "startup transaction leaked before commit");
            drop(release);
            if refuse {
                assert!(
                    tokio::time::timeout(std::time::Duration::from_secs(5), server)
                        .await??
                        .is_err()
                );
                assert!(exchange.calls.lock().unwrap().is_empty());
                let tables: i64 = observer.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name='startup'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(tables, 0);
            } else {
                let mut response = Vec::new();
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    client.read_to_end(&mut response),
                )
                .await??;
                assert!(response.starts_with(b"HTTP/1.1 200"));
                let value: i64 =
                    observer.query_row("SELECT value FROM startup", [], |row| row.get(0))?;
                assert_eq!(value, 1);
                assert_eq!(
                    exchange.calls.lock().unwrap().as_slice(),
                    &[prepared_on.lock().unwrap().unwrap()]
                );
                stop.send(()).unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(5), server).await???;
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_body_and_actual_socket_writes_keep_one_native_thread() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let exchange = Exchange::new(false);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve(
            Endpoint::Test(exchange.clone()),
            listener,
            1,
            Arc::new(AtomicBool::new(true)),
            async {
                let _ = stopped.await;
            },
        ));
        let mut client = tokio::net::TcpStream::connect(address).await?;
        client
            .write_all(b"GET /live HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        let mut bytes = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut bytes),
        )
        .await??;
        assert!(bytes.starts_with(b"HTTP/1.1 200"));
        assert!(bytes.windows(17).any(|w| w == b"connection: close"));
        stop.send(()).unwrap();
        server.await??;
        let calls = exchange.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_ne!(calls[0], thread::current().id());
        for observations in [&exchange.bodies, &exchange.background, &exchange.writes] {
            let observations = observations.lock().unwrap();
            assert!(!observations.is_empty());
            assert!(observations.iter().all(|id| id == &calls[0]));
        }
        Ok(())
    }

    #[tokio::test]
    async fn incomplete_connection_keeps_capacity_until_it_is_closed() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let exchange = Exchange::new(false);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve(
            Endpoint::Test(exchange.clone()),
            listener,
            1,
            Arc::new(AtomicBool::new(true)),
            async {
                let _ = stopped.await;
            },
        ));
        let mut first = tokio::net::TcpStream::connect(address).await?;
        first.write_all(b"GET / HTTP/1.1\r\n").await?;
        let mut second = tokio::net::TcpStream::connect(address).await?;
        second
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                exchange.entered.notified()
            )
            .await
            .is_err()
        );
        assert!(exchange.calls.lock().unwrap().is_empty());
        drop(first);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            exchange.entered.notified(),
        )
        .await?;
        let mut bytes = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            second.read_to_end(&mut bytes),
        )
        .await??;
        assert!(bytes.starts_with(b"HTTP/1.1 200"));
        stop.send(()).unwrap();
        server.await??;
        assert_eq!(exchange.calls.lock().unwrap().len(), 1);
        Ok(())
    }

    #[test]
    fn pending_socket_write_cannot_continue_after_original_expiry() -> Result<()> {
        struct Blocked(usize);
        impl rt::Write for Blocked {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
                _: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.0 += 1;
                Poll::Pending
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
                Poll::Pending
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        let world = crate::oauth::simulation::World::new(19);
        super::super::effects::scope(world.clone(), || -> Result<()> {
            let identity = crate::iap::Verified {
                email: "alice@example.com".into(),
                subject: "alice".into(),
            };
            let intent = super::super::fresh_auth::FreshIntent::fixture_oauth(
                &identity,
                "sink-attempt",
                &day2_capabilities::Digest::new(b"challenge"),
                "https://security.example.com",
                5,
                305,
            )?;
            let sink = super::super::native_management::Sink::new();
            futures_executor::block_on(
                sink.scope(async { super::super::native_management::reserve_shell(&intent, 5) }),
            )?;
            let mut io = OwnerIo {
                inner: std::rc::Rc::new(RefCell::new(Blocked(0))),
                owner: thread::current().id(),
                sink,
                driver: std::rc::Rc::new(RefCell::new(None)),
                exchange: None,
            };
            let waker = futures_util::task::noop_waker();
            let mut cx = TaskContext::from_waker(&waker);
            assert!(
                rt::Write::poll_write(Pin::new(&mut io), &mut cx, b"private response").is_pending()
            );
            assert_eq!(io.inner.borrow().0, 1);
            world.advance(300);
            assert!(matches!(
                rt::Write::poll_write(Pin::new(&mut io), &mut cx, b"private response"),
                Poll::Ready(Err(_))
            ));
            assert_eq!(io.inner.borrow().0, 1);
            Ok(())
        })
    }

    #[tokio::test]
    async fn disconnect_does_not_cancel_native_work_or_free_capacity_early() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let exchange = Exchange::new(true);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let mut server = tokio::spawn(serve(
            Endpoint::Test(exchange.clone()),
            listener,
            1,
            Arc::new(AtomicBool::new(true)),
            async {
                let _ = stopped.await;
            },
        ));
        let mut client = tokio::net::TcpStream::connect(address).await?;
        client
            .write_all(b"GET /block HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            exchange.entered.notified(),
        )
        .await?;
        drop(client);
        stop.send(()).unwrap();
        // Shutdown cannot report completion while the disconnected caller's
        // synchronous native operation still owns the executor.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut server)
                .await
                .is_err()
        );
        *exchange.release.0.lock().unwrap() = true;
        exchange.release.1.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), server).await???;
        assert_eq!(exchange.calls.lock().unwrap().len(), 1);
        Ok(())
    }
}
