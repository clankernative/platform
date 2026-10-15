//! Kernel connection-peer controls only. They do not qualify a message sender,
//! trusted endpoint, Pod/image/role/provider or production authority factory.

use super::*;

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_connection_peer_refuses_original_acquisition() {
    use std::time::Duration;
    let mut interval = NativeAcquisition::fixture(
        Digest::new(b"unsupported-peer"),
        std::process::id(),
        Duration::from_secs(100),
        Duration::from_secs(5),
    );
    assert!(
        NativeConnectionPeerObservation::observe(tempfile::tempfile().unwrap(), &mut interval)
            .is_err()
    );
    assert!(interval.remaining().is_err());
}

#[cfg(target_os = "linux")]
fn file(socket: std::os::unix::net::UnixStream) -> File {
    let owned: std::os::fd::OwnedFd = socket.into();
    owned.into()
}

#[cfg(target_os = "linux")]
#[test]
fn actual_kernel_peer_descriptor_observes_connection_creator_only() {
    let mut interval = NativeAcquisition::begin(5).unwrap();
    let (socket, _other) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut observed =
        NativeConnectionPeerObservation::observe(file(socket), &mut interval).unwrap();
    observed.check(&mut interval).unwrap();
    assert_eq!(observed.into_data().process, std::process::id());
    // No message was attributed and no role/runtime/storage capability exists.
}

#[cfg(target_os = "linux")]
#[test]
fn ordinary_file_never_becomes_a_peer_descriptor_or_pid_fallback() {
    let mut interval = NativeAcquisition::begin(5).unwrap();
    assert!(
        NativeConnectionPeerObservation::observe(tempfile::tempfile().unwrap(), &mut interval)
            .is_err()
    );
    assert!(interval.remaining().is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn changed_acquisition_refuses_peer_owner_permanently() {
    let mut original = NativeAcquisition::begin(5).unwrap();
    let (socket, _other) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut observed =
        NativeConnectionPeerObservation::observe(file(socket), &mut original).unwrap();
    let mut other = NativeAcquisition::begin(5).unwrap();
    assert!(observed.check(&mut other).is_err());
    assert!(other.remaining().is_err());
    assert!(observed.check(&mut original).is_err());
    assert!(original.remaining().is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn peer_fixture_child() {
    use std::io::Read;
    let Some(path) = std::env::var_os("DAY2_TEST_CONNECTION_PEER_SOCKET") else {
        return;
    };
    let mut socket = std::os::unix::net::UnixStream::connect(path).unwrap();
    let mut byte = [0_u8; 1];
    // Parent owns/reaps this process and kills it after retaining the pidfd.
    let _ = socket.read(&mut byte);
}

#[cfg(target_os = "linux")]
struct ReapedChild(std::process::Child);

#[cfg(target_os = "linux")]
impl Drop for ReapedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn actual_peer_process_exit_refuses_retained_pidfd_and_preserves_trace() {
    use std::{
        io::Write,
        os::unix::net::UnixListener,
        process::{Command, Stdio},
        time::{SystemTime, UNIX_EPOCH},
    };
    let base = std::path::Path::new("artifacts/native-connection-peer");
    std::fs::create_dir_all(base).unwrap();
    let directory = base.join(format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    // Relative socket path stays within the Linux Unix-address bound.
    let socket_path = directory.join("s");
    let mut interval = NativeAcquisition::begin(5).unwrap();
    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut child = ReapedChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "security_epoch::native_connection_peer::tests::peer_fixture_child",
                "--nocapture",
            ])
            .env("DAY2_TEST_CONNECTION_PEER_SOCKET", &socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let child_process = child.0.id();
    let socket = loop {
        interval.remaining().unwrap();
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1))
            }
            Err(error) => panic!("peer fixture accept failed: {error}"),
        }
    };
    let mut observed =
        NativeConnectionPeerObservation::observe(file(socket), &mut interval).unwrap();
    assert_eq!(observed.peer.process, child_process);
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    let refused = observed.check(&mut interval).is_err();
    let acquisition_refused = interval.remaining().is_err();
    let trace = serde_json::json!({"kind":"actual connection-peer process exit; no role/provider/P3 qualification",
        "observed_connection_creator":child_process,"exit":status.to_string(),"retained_pidfd_refused":refused,
        "original_acquisition_refused":acquisition_refused});
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("trace.json"))
        .unwrap();
    output
        .write_all(&serde_json::to_vec_pretty(&trace).unwrap())
        .unwrap();
    output.sync_all().unwrap();
    assert!(refused && acquisition_refused);
}
