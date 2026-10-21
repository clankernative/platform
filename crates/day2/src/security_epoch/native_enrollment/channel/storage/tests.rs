//! Actual Linux socket/CLOEXEC/HUP primitives only, not enrolled holder/P3
//! qualification. The synthetic acquisition cannot construct a native stage.

use super::*;
use day2_capabilities::Digest;
use std::time::Duration;

const EXEC_CONTROL: &str = "DAY2_STORAGE_PEER_EXEC_COMPONENT";
const EXEC_CHILD: &str =
    "security_epoch::native_enrollment::channel::storage::tests::exec_component_child";

struct OwnedChild(std::process::Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        // This is the still-owned, unreaped child, never a reconstructed PID.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn acquisition() -> NativeAcquisition {
    NativeAcquisition::fixture(
        Digest::new(b"socket-component-only"),
        std::process::id(),
        Duration::from_secs(100),
        Duration::from_secs(5),
    )
}

fn pair() -> (File, File) {
    let (a, b) = net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .unwrap();
    (File::from(a), File::from(b))
}

#[test]
fn live_socket_does_not_require_a_queued_packet() {
    let (receiver, _sender) = pair();
    require_connected(&receiver, &mut acquisition()).unwrap();
}

#[test]
fn buffered_final_packet_is_rejected_after_peer_close_while_process_is_alive() {
    let (receiver, sender) = pair();
    net::send(&sender, b"buffered-final", SendFlags::NOSIGNAL).unwrap();
    drop(sender);
    let mut fds = [PollFd::new(&receiver, PollFlags::IN)];
    rustix::event::poll(
        &mut fds,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .unwrap();
    assert!(
        fds[0].revents().contains(PollFlags::IN),
        "control packet was not readable"
    );
    let mut original = acquisition();
    assert!(require_connected(&receiver, &mut original).is_err());
    assert!(original.remaining().is_err());
}

#[test]
fn lost_cloexec_or_eof_permanently_refuses_the_original_acquisition() {
    let (receiver, sender) = pair();
    rustix::io::fcntl_setfd(&receiver, rustix::io::FdFlags::empty()).unwrap();
    let mut original = acquisition();
    assert!(require_connected(&receiver, &mut original).is_err());
    rustix::io::fcntl_setfd(&receiver, rustix::io::FdFlags::CLOEXEC).unwrap();
    assert!(require_connected(&receiver, &mut original).is_err());
    let mut next_component_control = acquisition();
    drop(sender);
    assert!(require_connected(&receiver, &mut next_component_control).is_err());
}

#[test]
fn exec_component_child() {
    use std::os::unix::process::CommandExt;
    match std::env::var(EXEC_CONTROL).as_deref() {
        Ok("before") => {
            let socket = std::io::stdin();
            rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC).unwrap();
            net::send(&socket, b"buffered-before-exec", SendFlags::NOSIGNAL).unwrap();
            let error = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", EXEC_CHILD, "--nocapture"])
                .env(EXEC_CONTROL, "after")
                // Preserve stdin until exec: replacing it here would test a
                // parent-side close, rather than the actual CLOEXEC boundary.
                .exec();
            panic!("component child exec failed: {error}");
        }
        Ok("after") => std::thread::sleep(Duration::from_secs(10)),
        _ => {}
    }
}

#[test]
fn actual_exec_refuses_buffered_final_while_original_pidfd_remains_live() {
    let (receiver, sender) = pair();
    let mut child = OwnedChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", EXEC_CHILD, "--nocapture"])
            .env(EXEC_CONTROL, "before")
            .stdin(std::process::Stdio::from(sender))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let pid = rustix::process::Pid::from_raw(child.0.id().try_into().unwrap()).unwrap();
    let pidfd =
        File::from(rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap());
    // RDHUP alone waits through the readable pre-exec packet until the child
    // actually execs and the original CLOEXEC socket closes.
    let mut fds = [PollFd::new(&receiver, PollFlags::RDHUP)];
    rustix::event::poll(
        &mut fds,
        Some(&rustix::event::Timespec {
            tv_sec: 5,
            tv_nsec: 0,
        }),
    )
    .unwrap();
    assert!(
        fds[0]
            .revents()
            .intersects(PollFlags::HUP | PollFlags::RDHUP)
    );
    let mut readable = [PollFd::new(&receiver, PollFlags::IN)];
    rustix::event::poll(
        &mut readable,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .unwrap();
    assert!(readable[0].revents().contains(PollFlags::IN));
    assert!(child.0.try_wait().unwrap().is_none());
    crate::security_epoch::native_enrollment::process::live(&pidfd, &mut acquisition()).unwrap();
    let mut original = acquisition();
    assert!(require_connected(&receiver, &mut original).is_err());
    assert!(original.remaining().is_err());
    crate::security_epoch::native_enrollment::process::live(&pidfd, &mut acquisition()).unwrap();
}
