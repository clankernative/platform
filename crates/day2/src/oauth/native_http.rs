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
    convert::Infallible,
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

thread_local! {
    // Only timer creation enters this handle. Keeping an entered Tokio runtime
    // across dispatch would prohibit reqwest's existing blocking adapter.
    static REACTOR: RefCell<Option<Handle>> = const { RefCell::new(None) };
}

pub(crate) fn timer<F>(create: impl FnOnce() -> F) -> F {
    REACTOR.with(|slot| {
        let slot = slot.borrow();
        let _entered = slot.as_ref().map(Handle::enter);
        create()
    })
}

#[cfg(test)]
pub(super) fn owns_thread() -> bool {
    REACTOR.with(|slot| slot.borrow().is_some())
}

/// Closed transport composition; never an app-supplied callback/task port.
pub(crate) enum Endpoint {
    Shell(Arc<super::security_shell::SecurityShell>),
    App(Arc<crate::web::Host>),
    Receiver(Arc<super::shell_transport::AppApprovalReceiver>),
    #[cfg(test)]
    Test(Arc<tests::Exchange>),
}

impl Endpoint {
    fn install(&self) -> Result<()> {
        #[cfg(test)]
        if super::native_management::simulation_installed() {
            return Ok(());
        }
        use crate::security_epoch::native_enrollment::NativeRole;
        let (scopes, role) = match self {
            Self::Shell(shell) => (shell.native_scopes().to_vec(), NativeRole::SecurityShell),
            Self::App(host) => (crate::web::native_scopes(host)?, NativeRole::AppHost),
            Self::Receiver(receiver) => (receiver.native_scopes()?, NativeRole::AppHost),
            #[cfg(test)]
            Self::Test(_) => return Ok(()),
        };
        if scopes.is_empty() {
            return Ok(());
        } // No selected management consumer.
        super::native_management::install(&scopes, role)
    }

    async fn handle(&self, request: Request, admission: Arc<AtomicBool>) -> Response {
        match self {
            Self::Shell(shell) => shell.clone().handle_native(request, admission).await,
            Self::App(host) => crate::web::handle_native(host.clone(), request).await,
            Self::Receiver(receiver) => receiver.clone().handle(request).await,
            #[cfg(test)]
            Self::Test(exchange) => exchange.handle(request).await,
        }
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
    let reactor = Handle::try_current().context("native HTTP readiness runtime missing")?;
    let effects = crate::managed_credentials::effects::capture();
    let (completed, completion) = tokio::sync::oneshot::channel();
    // Dropping the launcher's receiver cannot cancel native work or free its
    // capacity. The thread owns every live connection until drain completes.
    std::thread::Builder::new()
        .name("day2-oauth-owner".into())
        .spawn(move || {
            REACTOR.with(|slot| *slot.borrow_mut() = Some(reactor));
            let result = effects.run(|| {
                futures_executor::block_on(run(endpoint, listener, capacity, admission, shutdown))
            });
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
) -> Result<()> {
    let owner = std::thread::current().id();
    endpoint.install()?;
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            super::native_management::clear();
        }
    }
    let _clear = Clear;
    let endpoint = &endpoint;
    let mut connections = FuturesUnordered::new();
    let mut shutdown = std::pin::pin!(shutdown);
    let mut draining = false;
    loop {
        if draining && connections.is_empty() {
            return Ok(());
        }
        tokio::select! {
            biased;
            _ = &mut shutdown, if !draining => {
                draining = true;
                admission.store(false, Ordering::Release);
            }
            _ = connections.next(), if !connections.is_empty() => {}
            accepted = futures_util::future::poll_fn(|cx| timer(|| listener.poll_accept(cx))), if !draining && connections.len() < capacity => {
                let (stream, _) = accepted?;
                let sink = super::native_management::Sink::new();
                let io = OwnerIo { inner: TokioIo::new(stream), owner, sink: sink.clone(),
                    #[cfg(test)]
                    exchange: match endpoint { Endpoint::Test(exchange) => Some(exchange.clone()), _ => None },
                };
                let admitted = admission.clone();
                connections.push(async move {
                    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                        let admitted = admitted.clone();
                        let sink = sink.clone();
                        async move {
                            let response = sink.scope(endpoint.handle(request.map(Body::new), admitted)).await;
                            Ok::<_, Infallible>(response)
                        }
                    });
                    // A failed write means delivery is unknown/failed. Never
                    // replay the handler or turn it into a successful receipt.
                    let connection = http1::Builder::new().keep_alive(false)
                        .timer(OwnerTimer)
                        .header_read_timeout(std::time::Duration::from_secs(3))
                        .serve_connection(io, service);
                    let _ = timer(|| tokio::time::timeout(std::time::Duration::from_secs(30), connection)).await;
                });
            }
        }
    }
}

/// This wraps the socket, not just Body::poll_frame: response headers, buffered
/// body writes, flush and shutdown all run on the native owning OS thread.
struct OwnerIo<T> {
    inner: T,
    owner: ThreadId,
    sink: super::native_management::Sink,
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

impl<T: rt::Read + Unpin> rt::Read for OwnerIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: rt::Write + Unpin> rt::Write for OwnerIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        self.sink
            .check()
            .map_err(|_| io::Error::other("native response original unavailable"))?;
        #[cfg(test)]
        if let Some(exchange) = &self.exchange {
            exchange
                .writes
                .lock()
                .unwrap()
                .push(std::thread::current().id());
        }
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        self.sink
            .check()
            .map_err(|_| io::Error::other("native response original unavailable"))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        self.sink
            .check()
            .map_err(|_| io::Error::other("native response original unavailable"))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
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
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
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
        for observations in [&exchange.bodies, &exchange.writes] {
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
                inner: Blocked(0),
                owner: thread::current().id(),
                sink,
                exchange: None,
            };
            let waker = futures_util::task::noop_waker();
            let mut cx = TaskContext::from_waker(&waker);
            assert!(
                rt::Write::poll_write(Pin::new(&mut io), &mut cx, b"private response").is_pending()
            );
            assert_eq!(io.inner.0, 1);
            world.advance(300);
            assert!(matches!(
                rt::Write::poll_write(Pin::new(&mut io), &mut cx, b"private response"),
                Poll::Ready(Err(_))
            ));
            assert_eq!(io.inner.0, 1);
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
