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
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context as TaskContext, Poll},
    thread::ThreadId,
};
use tokio::{net::TcpListener, runtime::Handle};

pub(super) mod response_io;

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

    async fn handle(&self, request: Request, admission: Arc<AtomicBool>) -> Response {
        match self {
            Self::Shell(shell) => shell.clone().handle_native(request, admission).await,
            Self::App(host) => crate::web::handle_native(host.clone(), request).await,
            Self::Receiver(receiver) => receiver.clone().handle(request).await,
            #[cfg(test)]
            Self::Test(exchange) => exchange.handle(request).await,
            #[cfg(test)]
            Self::Prepared(_, _) => panic!("native fixture not prepared"),
        }
    }

    fn prepare_response(&self, sink: &super::native_management::Sink, finite: bool) -> Result<()> {
        let scope = match self {
            Self::App(host) => crate::web::native_runtime_response_scope(host)?,
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
    std::thread::Builder::new()
        .name("day2-oauth-owner".into())
        .spawn(move || {
            REACTOR.with(|slot| *slot.borrow_mut() = Some(reactor));
            let result = effects.run(|| futures_executor::block_on(launch.run(shutdown)));
            REACTOR.with(|slot| slot.borrow_mut().take());
            let _ = completed.send(result);
        })
        .context("start native HTTP owner")?;
    completion.await.context("native HTTP owner terminated")?
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
    loop {
        if draining && connections.is_empty() && live.is_empty() && pump_finished {
            return Ok(());
        }
        tokio::select! {
            biased;
            _ = &mut shutdown, if !draining => {
                draining = true;
                admission.store(false, Ordering::Release);
                let _ = pump_stop.send(true);
                live_receiver.close();
                while live_receiver.try_recv().is_ok() {} // Not-started work owns no external send.
            }
            result = &mut pump, if !pump_finished => {
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
            accepted = futures_util::future::poll_fn(|cx| timer(|| listener.poll_accept(cx))), if !draining && connections.len() < capacity => {
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
                    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                        let admitted = admitted.clone();
                        let sink = sink.clone();
                        async move {
                            let response = sink.scope(endpoint.handle(request.map(Body::new), admitted)).await;
                            let finite = finite_app_body_candidate(&response);
                            if endpoint.prepare_response(&sink, finite).is_err() {
                                sink.abort();
                                return Err(io::Error::other("native response authority unavailable"));
                            }
                            match sink.scope(prepare_finite_app_body(response, &sink)).await {
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
                    if let Ok(Ok(())) = timer(|| tokio::time::timeout(std::time::Duration::from_secs(30), connection)).await {
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
async fn prepare_finite_app_body(
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

    pub(crate) struct Exchange {
        calls: Mutex<Vec<ThreadId>>,
        bodies: Mutex<Vec<ThreadId>>,
        pub(super) writes: Mutex<Vec<ThreadId>>,
        pub(super) background: Mutex<Vec<ThreadId>>,
        entered: tokio::sync::Notify,
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
