//! Actual Linux socket/CLOEXEC/HUP primitives only, not enrolled holder/P3
//! qualification. The synthetic acquisition cannot construct a native stage.

use super::*;
use day2_capabilities::Digest;
use std::time::Duration;

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
