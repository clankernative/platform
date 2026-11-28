//! The single approved authored-unsafe exception. Only a newly-created fixed
//! writer page is mapped. Arbitrary received descriptors are NEVER mapped or
//! cast to Rust references; kernel pread copies into owned arrays instead.
#![allow(unsafe_code)]

use super::{
    Binding, CleanupData, Error, FRAME_BYTES, FailureKind, HEADER_BYTES, KNOWN, PAGE_BYTES,
    PENDING, REFUSED, STATE_OFFSET, StateData,
};
use rustix::{
    fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd},
    fs::{FileType, MemfdFlags, Mode, OFlags, SealFlags},
    io::{IoSlice, pread, pwrite},
    mm::{MapFlags, ProtFlags, mmap, munmap},
    net::{
        AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketType, sendmsg,
        sockopt,
    },
};
use std::{
    ffi::c_void,
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::NonNull,
    rc::Rc,
    sync::atomic::{AtomicU8, Ordering, fence},
};

const SEALS: SealFlags = SealFlags::SHRINK
    .union(SealFlags::GROW)
    .union(SealFlags::FUTURE_WRITE)
    .union(SealFlags::SEAL);
const _: () = assert!(size_of::<AtomicU8>() == 1 && align_of::<AtomicU8>() == 1);

fn io_error(kind: FailureKind, error: rustix::io::Errno) -> Error {
    Error {
        kind,
        errno: Some(error.raw_os_error()),
    }
}
fn file_check(fd: BorrowedFd<'_>) -> Result<(u64, u64), Error> {
    let stat = rustix::fs::fstat(fd).map_err(|e| io_error(FailureKind::File, e))?;
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|e| io_error(FailureKind::File, e))?;
    let seals = rustix::fs::fcntl_get_seals(fd).map_err(|e| io_error(FailureKind::File, e))?;
    let fdflags = rustix::io::fcntl_getfd(fd).map_err(|e| io_error(FailureKind::File, e))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_size != PAGE_BYTES as i64
        || flags & OFlags::ACCMODE != OFlags::RDONLY
        || seals != SEALS
        || !fdflags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(Error::invalid(FailureKind::File));
    }
    Ok((stat.st_dev, stat.st_ino))
}

struct Backing {
    address: Option<NonNull<c_void>>,
    descriptor: Option<OwnedFd>,
    frame: [u8; FRAME_BYTES],
    process: u32,
    _local: PhantomData<Rc<()>>,
}

impl Backing {
    fn state(&self) -> &AtomicU8 {
        let address = self.address.expect("private live writer mapping");
        // SAFETY: Only this type's fresh memfd is mapped, never an incoming FD.
        // It owns a full 4096-byte RW MAP_SHARED mapping until disposal; shrink
        // and grow are sealed. Offset4095 is in-bounds, one-byte aligned and
        // initialized before mapping. All in-component accesses to this byte
        // use this same AtomicU8; no shared byte slice covers it. The reference
        // cannot escape &self. No mapping pointer, writer FD or clone is exported.
        unsafe {
            &*address
                .as_ptr()
                .cast::<u8>()
                .add(STATE_OFFSET as usize)
                .cast::<AtomicU8>()
        }
    }

    fn check(&self) -> Result<(), Error> {
        if self.process != rustix::process::getpid().as_raw_nonzero().get() as u32 {
            return Err(Error::invalid(FailureKind::Process));
        }
        let fd = self
            .descriptor
            .as_ref()
            .ok_or_else(|| Error::invalid(FailureKind::File))?;
        let (dev, ino) = file_check(fd.as_fd())?;
        if self.frame[HEADER_BYTES..HEADER_BYTES + 8] != dev.to_le_bytes()
            || self.frame[HEADER_BYTES + 8..] != ino.to_le_bytes()
        {
            return Err(Error::invalid(FailureKind::Frame));
        }
        let mut header = [0; HEADER_BYTES];
        if pread(fd, &mut header, 0).map_err(|e| io_error(FailureKind::Read, e))? != HEADER_BYTES
            || header != self.frame[..HEADER_BYTES]
        {
            return Err(Error::invalid(FailureKind::Frame));
        }
        if self.state().load(Ordering::Relaxed) != PENDING {
            return Err(Error::invalid(FailureKind::State));
        }
        Ok(())
    }

    fn refuse(&self) {
        // A forked mechanical wrapper is not a native creator. Do not let its
        // destructor refuse the parent's page. Actual native no-fork/sole-writer
        // provenance is a separate mandatory obligation, not inferred here.
        if self.address.is_some()
            && self.process == rustix::process::getpid().as_raw_nonzero().get() as u32
        {
            let _ = self.state().compare_exchange(
                PENDING,
                REFUSED,
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }

    fn dispose(&mut self) -> CleanupData {
        if let Some(address) = self.address {
            // SAFETY: Exactly the live mapping this object created, no exposed
            // address or ownership alias; a failed unmap retains that owner.
            if let Err(error) = unsafe { munmap(address.as_ptr(), PAGE_BYTES) } {
                return CleanupData {
                    unmapped: false,
                    descriptor_released: false,
                    unmap_errno: Some(error.raw_os_error()),
                    close_errno: None,
                };
            }
            self.address = None;
        }
        let close_errno = self.descriptor.take().and_then(|fd| {
            // SAFETY: Consumes the unique FD. On Linux it is no longer owned
            // even on close error; never retry using a potentially recycled ID.
            unsafe { rustix::io::try_close(fd.into_raw_fd()) }
                .err()
                .map(|e| e.raw_os_error())
        });
        CleanupData {
            unmapped: true,
            descriptor_released: true,
            unmap_errno: None,
            close_errno,
        }
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        let _ = self.dispose();
    }
}

/// Fresh mechanical publisher, not a Controller owner or an authenticated source.
/// Actual native construction must rule out fork/adoption/older writer aliases.
pub struct FreshPage {
    inner: Option<Backing>,
}
pub struct PendingPublication {
    inner: Option<Backing>,
}
pub struct ReadyPublication {
    inner: Option<Backing>,
}
/// Inert owning DATA. Later disposal never changes the shared terminal byte.
pub struct PublishedData {
    inner: Backing,
}
/// Local refusal; the shared byte may already be Known from an unqualified
/// competing alias. This is NOT proof that shared state became Refused.
pub struct LocalRefusalData {
    inner: Backing,
}
pub enum Publication {
    Known(PublishedData),
    Refused(LocalRefusalData),
}

impl FreshPage {
    pub fn create(binding: Binding) -> Result<Self, Error> {
        let rw = rustix::fs::memfd_create(
            c"day2-backup-completion-v1",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .map_err(|e| io_error(FailureKind::File, e))?;
        rustix::fs::ftruncate(&rw, PAGE_BYTES as u64)
            .map_err(|e| io_error(FailureKind::File, e))?;
        let mut initial = [0; PAGE_BYTES];
        initial[..HEADER_BYTES].copy_from_slice(&binding.header());
        if pwrite(&rw, &initial, 0).map_err(|e| io_error(FailureKind::File, e))? != PAGE_BYTES {
            return Err(Error::invalid(FailureKind::File));
        }
        // SAFETY: New private regular memfd, exact initialized size, offset0,
        // no requested address/MAP_FIXED, no previous mapping/adoption. Only
        // this private type owns the returned RW mapping and exposes no pointer.
        let pointer = unsafe {
            mmap(
                std::ptr::null_mut(),
                PAGE_BYTES,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                &rw,
                0,
            )
        }
        .map_err(|e| io_error(FailureKind::Mapping, e))?;
        let Some(address) = NonNull::new(pointer) else {
            // SAFETY: The successful fresh mapping is still ours, even if the
            // kernel selected address zero. Refuse without leaking that mapping.
            let _ = unsafe { munmap(pointer, PAGE_BYTES) };
            return Err(Error::invalid(FailureKind::Mapping));
        };
        let mut backing = Backing {
            address: Some(address),
            descriptor: None,
            frame: [0; FRAME_BYTES],
            process: rustix::process::getpid().as_raw_nonzero().get() as u32,
            _local: PhantomData,
        };
        rustix::fs::fcntl_add_seals(&rw, SEALS).map_err(|e| io_error(FailureKind::File, e))?;
        // The only reopening is this creator's private descriptor, never a
        // caller path. Identity/readonly/seals/CLOEXEC are checked independently.
        let ro = rustix::fs::open(
            format!("/proc/self/fd/{}", rw.as_raw_fd()),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| io_error(FailureKind::File, e))?;
        let before = rustix::fs::fstat(&rw).map_err(|e| io_error(FailureKind::File, e))?;
        let (dev, ino) = file_check(ro.as_fd())?;
        if before.st_dev != dev || before.st_ino != ino {
            return Err(Error::invalid(FailureKind::File));
        }
        backing.frame[..HEADER_BYTES].copy_from_slice(&binding.header());
        backing.frame[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&dev.to_le_bytes());
        backing.frame[HEADER_BYTES + 8..].copy_from_slice(&ino.to_le_bytes());
        backing.descriptor = Some(ro);
        drop(rw);
        Ok(Self {
            inner: Some(backing),
        })
    }

    /// An owned copy of the already fixed PUBLIC envelope, including this
    /// file's dev/ino. No state byte, resource handle or live observation is
    /// returned. A native signer must take this DATA from its actual retained
    /// page; a caller-supplied equal array proves neither creator nor authority.
    pub fn pending_envelope_data(&self) -> [u8; FRAME_BYTES] {
        self.inner.as_ref().expect("private fresh page").frame
    }

    /// Exactly one fixed pending envelope and THIS read-only page descriptor.
    /// The actual caller owns socket authentication, waits and original/posts.
    /// No retry is performed, including after a consumed/ambiguous send.
    pub fn send_pending(mut self, socket: BorrowedFd<'_>) -> Result<PendingPublication, Error> {
        let inner = self.inner.as_ref().expect("private fresh page");
        inner.check()?;
        if sockopt::socket_type(socket).map_err(|e| io_error(FailureKind::Socket, e))?
            != SocketType::SEQPACKET
            || sockopt::socket_domain(socket).map_err(|e| io_error(FailureKind::Socket, e))?
                != AddressFamily::UNIX
        {
            return Err(Error::invalid(FailureKind::Socket));
        }
        let fds = [inner
            .descriptor
            .as_ref()
            .expect("private RO descriptor")
            .as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if !ancillary.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(Error::invalid(FailureKind::Send));
        }
        if sendmsg(
            socket,
            &[IoSlice::new(&inner.frame)],
            &mut ancillary,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )
        .map_err(|e| io_error(FailureKind::Send, e))?
            != FRAME_BYTES
        {
            return Err(Error::invalid(FailureKind::Send));
        }
        Ok(PendingPublication {
            inner: self.inner.take(),
        })
    }
}

impl PendingPublication {
    /// All mechanical fallible checks precede the caller's final native posts.
    /// This is NOT those posts, native completion or an authenticated creator.
    pub fn prepare(mut self) -> Result<ReadyPublication, Error> {
        self.inner.as_ref().expect("private pending page").check()?;
        Ok(ReadyPublication {
            inner: self.inner.take(),
        })
    }
}

impl ReadyPublication {
    /// Consuming, single atomic terminal transition. No syscall, allocation,
    /// retry, native check or resource destruction follows successful Known.
    pub fn publish(mut self) -> Publication {
        let inner = self.inner.take().expect("private ready page");
        let known = inner
            .state()
            .compare_exchange(PENDING, KNOWN, Ordering::Release, Ordering::Relaxed)
            .is_ok();
        if known {
            Publication::Known(PublishedData { inner })
        } else {
            Publication::Refused(LocalRefusalData { inner })
        }
    }
}

impl PublishedData {
    pub fn dispose(&mut self) -> CleanupData {
        self.inner.dispose()
    }
}
impl LocalRefusalData {
    pub fn dispose(&mut self) -> CleanupData {
        self.inner.dispose()
    }
}
impl Drop for FreshPage {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            inner.refuse();
        }
    }
}
impl Drop for PendingPublication {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            inner.refuse();
        }
    }
}
impl Drop for ReadyPublication {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            inner.refuse();
        }
    }
}

/// Untrusted mechanical DATA only. There is deliberately no creator-proof,
/// native completion, role, original, source, FD or upload getter/constructor.
pub struct ReceivedData {
    descriptor: OwnedFd,
}

/// The existing strict ancillary receiver retains its own PIDFD/credentials.
/// This consumes ONLY its separate page FD; equality is not authentication.
/// Arbitrary/malicious older writable aliases cannot violate Rust memory safety:
/// no received memory is mapped or read through a Rust reference at all.
pub fn validate_received_data(
    descriptor: OwnedFd,
    frame: [u8; FRAME_BYTES],
    expected: Binding,
) -> Result<ReceivedData, Error> {
    let (dev, ino) = file_check(descriptor.as_fd())?;
    let mut expected_frame = [0; FRAME_BYTES];
    expected_frame[..HEADER_BYTES].copy_from_slice(&expected.header());
    expected_frame[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&dev.to_le_bytes());
    expected_frame[HEADER_BYTES + 8..].copy_from_slice(&ino.to_le_bytes());
    let mut header = [0; HEADER_BYTES];
    if frame != expected_frame
        || pread(&descriptor, &mut header, 0).map_err(|e| io_error(FailureKind::Read, e))?
            != HEADER_BYTES
        || header != expected.header()
    {
        return Err(Error::invalid(FailureKind::Frame));
    }
    let received = ReceivedData { descriptor };
    received.state_data()?;
    Ok(received)
}

impl ReceivedData {
    /// One kernel byte-copy, with NO read_exact/retry loop. The fence orders
    /// subsequent local work; this is Linux ABI DATA observation, NOT Rust
    /// release/acquire synchronization or an authenticated Known disposition.
    /// All image/header DATA must already be immutable and verified independently.
    pub fn state_data(&self) -> Result<StateData, Error> {
        let mut byte = [0];
        if pread(&self.descriptor, &mut byte, STATE_OFFSET)
            .map_err(|e| io_error(FailureKind::Read, e))?
            != 1
        {
            return Err(Error::invalid(FailureKind::Read));
        }
        fence(Ordering::Acquire);
        super::state_data(byte[0])
    }
}

// Compile-time negative assertions, not a native-owner constructor.
const _: () = {
    macro_rules! assert_not_impl {
        ($owner:ty,$trait:path) => {{
            trait Ambiguous<A> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            struct IfImpl;
            impl<T: ?Sized + $trait> Ambiguous<IfImpl> for T {}
            let _ = <$owner as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Backing, Clone);
    assert_not_impl!(Backing, Copy);
    assert_not_impl!(Backing, Default);
    assert_not_impl!(Backing, std::fmt::Debug);
    assert_not_impl!(Backing, rustix::fd::AsFd);
    assert_not_impl!(Backing, rustix::fd::AsRawFd);
    assert_not_impl!(Backing, std::ops::Deref);
    assert_not_impl!(Backing, Send);
    assert_not_impl!(Backing, Sync);
    assert_not_impl!(FreshPage, Clone);
    assert_not_impl!(FreshPage, Copy);
    assert_not_impl!(FreshPage, Default);
    assert_not_impl!(FreshPage, std::fmt::Debug);
    assert_not_impl!(FreshPage, rustix::fd::AsFd);
    assert_not_impl!(FreshPage, rustix::fd::AsRawFd);
    assert_not_impl!(FreshPage, std::ops::Deref);
    assert_not_impl!(FreshPage, Send);
    assert_not_impl!(FreshPage, Sync);
    assert_not_impl!(PendingPublication, Clone);
    assert_not_impl!(PendingPublication, Copy);
    assert_not_impl!(PendingPublication, Default);
    assert_not_impl!(PendingPublication, std::fmt::Debug);
    assert_not_impl!(PendingPublication, rustix::fd::AsFd);
    assert_not_impl!(PendingPublication, rustix::fd::AsRawFd);
    assert_not_impl!(PendingPublication, std::ops::Deref);
    assert_not_impl!(PendingPublication, Send);
    assert_not_impl!(PendingPublication, Sync);
    assert_not_impl!(ReadyPublication, Clone);
    assert_not_impl!(ReadyPublication, Copy);
    assert_not_impl!(ReadyPublication, Default);
    assert_not_impl!(ReadyPublication, std::fmt::Debug);
    assert_not_impl!(ReadyPublication, rustix::fd::AsFd);
    assert_not_impl!(ReadyPublication, rustix::fd::AsRawFd);
    assert_not_impl!(ReadyPublication, std::ops::Deref);
    assert_not_impl!(ReadyPublication, Send);
    assert_not_impl!(ReadyPublication, Sync);
    assert_not_impl!(PublishedData, Clone);
    assert_not_impl!(PublishedData, Copy);
    assert_not_impl!(PublishedData, Default);
    assert_not_impl!(PublishedData, std::fmt::Debug);
    assert_not_impl!(PublishedData, rustix::fd::AsFd);
    assert_not_impl!(PublishedData, rustix::fd::AsRawFd);
    assert_not_impl!(PublishedData, std::ops::Deref);
    assert_not_impl!(PublishedData, Send);
    assert_not_impl!(PublishedData, Sync);
    assert_not_impl!(LocalRefusalData, Clone);
    assert_not_impl!(LocalRefusalData, Copy);
    assert_not_impl!(LocalRefusalData, Default);
    assert_not_impl!(LocalRefusalData, std::fmt::Debug);
    assert_not_impl!(LocalRefusalData, rustix::fd::AsFd);
    assert_not_impl!(LocalRefusalData, rustix::fd::AsRawFd);
    assert_not_impl!(LocalRefusalData, std::ops::Deref);
    assert_not_impl!(LocalRefusalData, Send);
    assert_not_impl!(LocalRefusalData, Sync);
    assert_not_impl!(ReceivedData, Clone);
    assert_not_impl!(ReceivedData, Copy);
    assert_not_impl!(ReceivedData, Default);
    assert_not_impl!(ReceivedData, std::fmt::Debug);
    assert_not_impl!(ReceivedData, rustix::fd::AsFd);
    assert_not_impl!(ReceivedData, rustix::fd::AsRawFd);
    assert_not_impl!(ReceivedData, std::ops::Deref);
};

#[cfg(all(test, feature = "kernel-qualification"))]
pub(super) fn run_kernel_qualification() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => {
            tests::actual_kernel_qualification();
            tests::verify_kernel_qualification();
        }
        [only] if only == "--completion-child" => tests::cross_process_child(),
        _ => panic!("qualification has no case filters or skip selector"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::{
        PidfdRightsCount, ReceivedPidfdRights, RecvFlags, SocketFlags, recv_pidfd_rights_packet,
    };
    use std::{
        io::IoSliceMut,
        process::{Child, Command},
        time::{Duration, Instant},
    };

    #[cfg(feature = "kernel-qualification")]
    fn actual_selected_rustix_backend_is_bound_to_its_build_script() {
        // This file is the BuildInfo.flags output of the SAME selected rustix
        // producer used by this test target, not a claimed environment label.
        let flags = include_str!(env!("COMPLETION_RUSTIX_FLAGS"));
        let raw = flags
            .lines()
            .filter(|line| *line == "--cfg=linux_raw")
            .count();
        let libc = flags.lines().filter(|line| *line == "--cfg=libc").count();
        let expected = if cfg!(feature = "qualification-libc") {
            (0, 1)
        } else {
            (1, 0)
        };
        assert_eq!(
            (raw, libc),
            expected,
            "actual rustix producer backend mismatch"
        );
        println!(
            "COMPLETION_BACKEND {}",
            if raw == 1 { "linux_raw" } else { "libc" }
        );
    }

    fn binding() -> Binding {
        Binding {
            controller: [1; 32],
            requester: [2; 32],
            connection: [3; 32],
            requester_nonce: [4; 32],
            controller_nonce: [5; 32],
            original: [6; 32],
            operation: [7; 32],
            intent: [8; 32],
            image: [9; 32],
            destination: [10; 32],
        }
    }

    fn sockets() -> (OwnedFd, OwnedFd) {
        let (left, right) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        sockopt::set_socket_passcred(&right, true).unwrap();
        sockopt::set_socket_passpidfd(&right, true).unwrap();
        (left, right)
    }

    fn packet(socket: BorrowedFd<'_>) -> (OwnedFd, [u8; FRAME_BYTES]) {
        let mut frame = [0; FRAME_BYTES];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match recv_pidfd_rights_packet(
                socket,
                &mut [IoSliceMut::new(&mut frame)],
                PidfdRightsCount::One,
            ) {
                Ok(message) => {
                    assert_eq!(message.packet.bytes, FRAME_BYTES);
                    let ReceivedPidfdRights::One(fd) = message.rights else {
                        panic!("wrong fixed rights count")
                    };
                    return (fd, frame);
                }
                Err(rustix::net::RecvPidfdError::Io(rustix::io::Errno::AGAIN))
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) => panic!("strict local kernel packet refused: {error}"),
            }
        }
    }

    fn delivered() -> (PendingPublication, ReceivedData) {
        let (left, right) = sockets();
        let pending = FreshPage::create(binding())
            .unwrap()
            .send_pending(left.as_fd())
            .unwrap();
        let (fd, frame) = packet(right.as_fd());
        let received = validate_received_data(fd, frame, binding()).unwrap();
        (pending, received)
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn owned_public_envelope_copy_matches_actual_send_and_refuses_equal_binding_substitution() {
        let first = FreshPage::create(binding()).unwrap();
        let second = FreshPage::create(binding()).unwrap();
        // Only public mechanical DATA is copied here, not a signature or a
        // fabricated native creator/receiver. Both real files stay alive.
        let first_envelope = first.pending_envelope_data();
        let second_envelope = second.pending_envelope_data();
        assert_eq!(
            &first_envelope[..HEADER_BYTES],
            &second_envelope[..HEADER_BYTES]
        );
        assert_ne!(first_envelope, second_envelope);
        let mut changed_copy = first_envelope;
        changed_copy.fill(0xff);
        assert_ne!(changed_copy, first_envelope);
        assert_eq!(first.pending_envelope_data(), first_envelope);

        let (left, right) = sockets();
        let first_pending = first.send_pending(left.as_fd()).unwrap();
        let (first_file, first_actual) = packet(right.as_fd());
        assert_eq!(first_actual, first_envelope);
        let first_received = validate_received_data(first_file, first_envelope, binding()).unwrap();
        assert_eq!(first_received.state_data().unwrap(), StateData::Pending);

        let second_pending = second.send_pending(left.as_fd()).unwrap();
        let (second_file, second_actual) = packet(right.as_fd());
        assert_eq!(second_actual, second_envelope);
        let duplicate = rustix::io::fcntl_dupfd_cloexec(&second_file, 0).unwrap();
        let second_received = validate_received_data(duplicate, second_actual, binding()).unwrap();
        assert_eq!(second_received.state_data().unwrap(), StateData::Pending);
        // A later native receiver must authenticate the FULL original
        // envelope. Equal core Binding DATA does not select another file.
        assert_eq!(
            validate_received_data(second_file, first_envelope, binding())
                .err()
                .unwrap()
                .kind,
            FailureKind::Frame
        );
        let Publication::Known(mut known) = first_pending.prepare().unwrap().publish() else {
            panic!("original page refused")
        };
        drop(second_pending);
        assert_eq!(first_received.state_data().unwrap(), StateData::Known);
        assert_eq!(second_received.state_data().unwrap(), StateData::Refused);
        assert!(known.dispose().unmapped);
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn real_pending_publication_and_later_cleanup_keep_known_irreversible() {
        let (pending, received) = delivered();
        assert_eq!(received.state_data().unwrap(), StateData::Pending);
        let Publication::Known(mut data) = pending.prepare().unwrap().publish() else {
            panic!("first publication refused")
        };
        assert_eq!(received.state_data().unwrap(), StateData::Known);
        let cleanup = data.dispose();
        assert_eq!(
            cleanup,
            CleanupData {
                unmapped: true,
                descriptor_released: true,
                unmap_errno: None,
                close_errno: None
            }
        );
        drop(data);
        assert_eq!(received.state_data().unwrap(), StateData::Known);
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn abandoning_pending_or_ready_refuses_without_inventing_known() {
        let (pending, received) = delivered();
        drop(pending);
        assert_eq!(received.state_data().unwrap(), StateData::Refused);
        let (pending, received) = delivered();
        drop(pending.prepare().unwrap());
        assert_eq!(received.state_data().unwrap(), StateData::Refused);
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn competing_terminal_state_never_becomes_local_known_or_gets_overwritten() {
        for terminal in [KNOWN, REFUSED, 255] {
            let (pending, received) = delivered();
            let ready = pending.prepare().unwrap();
            ready
                .inner
                .as_ref()
                .unwrap()
                .state()
                .store(terminal, Ordering::Release);
            let Publication::Refused(mut local) = ready.publish() else {
                panic!("competing state regranted local Known")
            };
            if terminal == KNOWN {
                assert_eq!(received.state_data().unwrap(), StateData::Known);
            } else if terminal == REFUSED {
                assert_eq!(received.state_data().unwrap(), StateData::Refused);
            } else {
                assert!(received.state_data().is_err());
            }
            assert!(local.dispose().unmapped);
            if terminal == KNOWN {
                assert_eq!(received.state_data().unwrap(), StateData::Known);
            }
        }
    }

    fn duplicate_cloexec(fd: BorrowedFd<'_>) -> OwnedFd {
        let copy = rustix::io::dup(fd).unwrap();
        rustix::io::fcntl_setfd(&copy, rustix::io::FdFlags::CLOEXEC).unwrap();
        copy
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn exact_immutable_header_frame_and_all_binding_fields_are_required() {
        let (left, right) = sockets();
        let pending = FreshPage::create(binding())
            .unwrap()
            .send_pending(left.as_fd())
            .unwrap();
        let (fd, frame) = packet(right.as_fd());
        for index in [
            0, 16, 17, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 360, 367,
        ] {
            let copy = duplicate_cloexec(fd.as_fd());
            file_check(copy.as_fd()).unwrap();
            let baseline = validate_received_data(copy, frame, binding()).unwrap();
            assert_eq!(baseline.state_data().unwrap(), StateData::Pending);
            let mut changed = frame;
            changed[index] ^= 1;
            let failure = validate_received_data(duplicate_cloexec(fd.as_fd()), changed, binding())
                .err()
                .unwrap();
            assert_eq!(failure.kind, FailureKind::Frame);
        }
        for index in 0..10 {
            let copy = duplicate_cloexec(fd.as_fd());
            file_check(copy.as_fd()).unwrap();
            assert!(validate_received_data(copy, frame, binding()).is_ok());
            let mut other = binding();
            let field = match index {
                0 => &mut other.controller,
                1 => &mut other.requester,
                2 => &mut other.connection,
                3 => &mut other.requester_nonce,
                4 => &mut other.controller_nonce,
                5 => &mut other.original,
                6 => &mut other.operation,
                7 => &mut other.intent,
                8 => &mut other.image,
                _ => &mut other.destination,
            };
            *field = [33; 32];
            let failure = validate_received_data(duplicate_cloexec(fd.as_fd()), frame, other)
                .err()
                .unwrap();
            assert_eq!(failure.kind, FailureKind::Frame);
        }
        assert!(validate_received_data(fd, frame, binding()).is_ok());
        // Corrupt the ACTUAL file header while leaving the frame canonical.
        // Frame-only mutations cannot detect deletion of the file comparison.
        for index in [0, 16, 17, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320] {
            let (valid, frame) = foreign_page(PENDING, SEALS);
            assert!(validate_received_data(valid, frame, binding()).is_ok());
            let (changed, frame) = foreign_profile(PENDING, SEALS, PAGE_BYTES, Some(index));
            file_check(changed.as_fd()).unwrap();
            assert_eq!(
                validate_received_data(changed, frame, binding())
                    .err()
                    .unwrap()
                    .kind,
                FailureKind::Frame
            );
        }
        drop(pending);
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn actual_readonly_transfer_cannot_write_grow_shrink_or_make_new_writable_mapping() {
        let (pending, received) = delivered();
        let fd = &received.descriptor;
        assert_eq!(pwrite(fd, b"x", STATE_OFFSET), Err(rustix::io::Errno::BADF));
        assert!(rustix::fs::ftruncate(fd, 1).is_err());
        assert!(rustix::fs::ftruncate(fd, 8192).is_err());
        // SAFETY: This negative syscall asks for a new mapping but never
        // dereferences it. Any unexpected success is immediately unmapped.
        let result = unsafe {
            mmap(
                std::ptr::null_mut(),
                PAGE_BYTES,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                fd,
                0,
            )
        };
        if let Ok(pointer) = result {
            // SAFETY: Immediate cleanup of that unexpected owned mapping.
            unsafe { munmap(pointer, PAGE_BYTES) }.unwrap();
            panic!("read-only transfer became writable");
        }
        // Reopening the RO proc descriptor may produce an RDWR descriptor;
        // that is not authority. FUTURE_WRITE must still reject write/mmap.
        let reopened = rustix::fs::open(
            format!("/proc/self/fd/{}", fd.as_raw_fd()),
            OFlags::RDWR | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(pwrite(&reopened, b"x", STATE_OFFSET).is_err());
        // SAFETY: Negative mapping request only; any unexpected mapping is
        // immediately owned and disposed, never dereferenced.
        if let Ok(pointer) = unsafe {
            mmap(
                std::ptr::null_mut(),
                PAGE_BYTES,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                &reopened,
                0,
            )
        } {
            // SAFETY: The same unexpected fresh mapping is no longer used.
            unsafe { munmap(pointer, PAGE_BYTES) }.unwrap();
            panic!("reopened descriptor became writable");
        }
        // SAFETY: A fresh private READ-only mapping of this exact fixed RO FD.
        // It is never made into a Rust reference and is disposed below.
        let readonly = unsafe {
            mmap(
                std::ptr::null_mut(),
                PAGE_BYTES,
                ProtFlags::READ,
                MapFlags::SHARED,
                fd,
                0,
            )
        }
        .unwrap();
        // SAFETY: A negative protection change on our owned complete mapping.
        let change = unsafe {
            rustix::mm::mprotect(
                readonly,
                PAGE_BYTES,
                rustix::mm::MprotectFlags::READ | rustix::mm::MprotectFlags::WRITE,
            )
        };
        // SAFETY: The same owned mapping is no longer used.
        unsafe { munmap(readonly, PAGE_BYTES) }.unwrap();
        assert!(change.is_err());
        drop(pending);
    }

    fn foreign_page(state: u8, seals: SealFlags) -> (OwnedFd, [u8; FRAME_BYTES]) {
        foreign_profile(state, seals, PAGE_BYTES, None)
    }

    fn foreign_profile(
        state: u8,
        seals: SealFlags,
        length: usize,
        corrupt: Option<usize>,
    ) -> (OwnedFd, [u8; FRAME_BYTES]) {
        assert!((HEADER_BYTES..=PAGE_BYTES + 1).contains(&length));
        let rw = rustix::fs::memfd_create(
            c"foreign-mechanical-page",
            MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
        )
        .unwrap();
        rustix::fs::ftruncate(&rw, length as u64).unwrap();
        let mut bytes = [0; PAGE_BYTES + 1];
        bytes[..HEADER_BYTES].copy_from_slice(&binding().header());
        bytes[STATE_OFFSET as usize] = state;
        if let Some(index) = corrupt {
            assert!(index < HEADER_BYTES);
            bytes[index] ^= 1;
        }
        // A short-size fixture must not regrow through its initializer.
        assert_eq!(pwrite(&rw, &bytes[..length], 0).unwrap(), length);
        assert_eq!(rustix::fs::fstat(&rw).unwrap().st_size, length as i64);
        rustix::fs::fcntl_add_seals(&rw, seals).unwrap();
        let ro = rustix::fs::open(
            format!("/proc/self/fd/{}", rw.as_raw_fd()),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let stat = rustix::fs::fstat(&ro).unwrap();
        let mut frame = [0; FRAME_BYTES];
        frame[..HEADER_BYTES].copy_from_slice(&binding().header());
        frame[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&stat.st_dev.to_le_bytes());
        frame[HEADER_BYTES + 8..].copy_from_slice(&stat.st_ino.to_le_bytes());
        (ro, frame)
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn forged_known_is_only_mechanical_data_not_creator_or_native_completion() {
        let (fd, frame) = foreign_page(KNOWN, SEALS);
        let data = validate_received_data(fd, frame, binding()).unwrap();
        assert_eq!(data.state_data().unwrap(), StateData::Known);
        // There is no conversion from this observation to a native owner,
        // accepted creator, completed handoff, source loan or upload grant.
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn every_required_seal_and_valid_state_is_checked() {
        for missing in [
            SealFlags::GROW,
            SealFlags::SHRINK,
            SealFlags::FUTURE_WRITE,
            SealFlags::SEAL,
        ] {
            let (fd, frame) = foreign_page(PENDING, SEALS & !missing);
            assert!(validate_received_data(fd, frame, binding()).is_err());
        }
        let (fd, frame) = foreign_page(255, SEALS);
        assert_eq!(
            validate_received_data(fd, frame, binding())
                .err()
                .unwrap()
                .kind,
            FailureKind::State
        );
        for length in [PAGE_BYTES - 1, PAGE_BYTES + 1] {
            let (fd, frame) = foreign_profile(PENDING, SEALS, length, None);
            assert_eq!(rustix::fs::fstat(&fd).unwrap().st_size, length as i64);
            assert_eq!(
                validate_received_data(fd, frame, binding())
                    .err()
                    .unwrap()
                    .kind,
                FailureKind::File
            );
        }
        let (fd, frame) = foreign_page(PENDING, SEALS);
        let not_cloexec = rustix::io::dup(&fd).unwrap();
        assert!(
            !rustix::io::fcntl_getfd(&not_cloexec)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert_eq!(
            validate_received_data(not_cloexec, frame, binding())
                .err()
                .unwrap()
                .kind,
            FailureKind::File
        );
        let writable = rustix::fs::open(
            format!("/proc/self/fd/{}", fd.as_raw_fd()),
            OFlags::RDWR | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert_eq!(
            validate_received_data(writable, frame, binding())
                .err()
                .unwrap()
                .kind,
            FailureKind::File
        );
        assert!(validate_received_data(fd, frame, binding()).is_ok());
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn failed_fixed_send_refuses_the_page_and_never_supplies_a_ready_publisher() {
        let (left, right) = sockets();
        drop(right);
        assert!(
            FreshPage::create(binding())
                .unwrap()
                .send_pending(left.as_fd())
                .is_err()
        );
        let (left, _right) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        assert!(
            FreshPage::create(binding())
                .unwrap()
                .send_pending(left.as_fd())
                .is_err()
        );
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn independent_generated_terminal_histories_replay_twice() {
        #[derive(Clone, Copy)]
        enum Reference {
            Waiting,
            Published,
            Abandoned,
        }
        for seed in 0..64_u64 {
            let mut random = seed + 1;
            let mut operations = [0_u8; 16];
            for op in &mut operations {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                *op = (random % 4) as u8;
            }
            let mut expected = Vec::new();
            let mut model = Reference::Waiting;
            let mut owned = true;
            for op in operations {
                let mut local_known = false;
                if owned && op == 0 {
                    local_known = matches!(model, Reference::Waiting);
                    if local_known {
                        model = Reference::Published;
                    }
                    owned = false;
                } else if owned && op == 1 {
                    if matches!(model, Reference::Waiting) {
                        model = Reference::Abandoned;
                    }
                    owned = false;
                } else if owned && op == 2 && matches!(model, Reference::Waiting) {
                    model = Reference::Published;
                }
                expected.push((
                    match model {
                        Reference::Waiting => StateData::Pending,
                        Reference::Published => StateData::Known,
                        Reference::Abandoned => StateData::Refused,
                    },
                    local_known,
                ));
            }
            for _ in 0..2 {
                let (pending, received) = delivered();
                let mut ready = Some(pending.prepare().unwrap());
                let mut actual = Vec::new();
                let mut holds = Vec::new();
                for op in operations {
                    let mut local_known = false;
                    if op == 0 {
                        if let Some(owner) = ready.take() {
                            match owner.publish() {
                                Publication::Known(hold) => {
                                    local_known = true;
                                    holds.push(Publication::Known(hold));
                                }
                                other => holds.push(other),
                            }
                        }
                    } else if op == 1 {
                        drop(ready.take());
                    } else if op == 2
                        && let Some(owner) = &ready
                    {
                        let _ = owner.inner.as_ref().unwrap().state().compare_exchange(
                            PENDING,
                            KNOWN,
                            Ordering::Release,
                            Ordering::Relaxed,
                        );
                    }
                    actual.push((received.state_data().unwrap(), local_known));
                }
                if actual != expected {
                    let root = std::env::var_os("TEST_UNDECLARED_OUTPUTS_DIR")
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(std::env::temp_dir);
                    let path = root.join(format!("completion-replay-failure-{seed}.txt"));
                    use std::{io::Write, os::unix::fs::OpenOptionsExt};
                    let mut output = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                        .unwrap();
                    writeln!(output,"seed {seed} operations {operations:?} expected {expected:?} actual {actual:?}").unwrap();
                    output.sync_all().unwrap();
                    panic!("bounded completion model disagreement; seed {seed}");
                }
            }
        }
    }

    fn wait_state(received: &ReceivedData, expected: StateData) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let actual = received.state_data().unwrap();
            if actual == expected {
                return;
            }
            assert_eq!(actual, StateData::Pending);
            assert!(
                Instant::now() < deadline,
                "bounded mechanical state observation"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn listener(path: &std::path::Path) -> OwnedFd {
        let socket = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        rustix::net::bind(&socket, &rustix::net::SocketAddrUnix::new(path).unwrap()).unwrap();
        rustix::net::listen(&socket, 1).unwrap();
        socket
    }

    fn accept(listener: BorrowedFd<'_>) -> OwnedFd {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match rustix::net::accept_with(listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK) {
                Ok(peer) => return peer,
                Err(rustix::io::Errno::AGAIN) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => panic!("bounded local accept refused"),
            }
        }
    }

    fn ack(socket: BorrowedFd<'_>, expected: u8) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut byte = [0];
            match rustix::net::recv(socket, &mut byte, RecvFlags::DONTWAIT) {
                Ok((1, 1)) => {
                    assert_eq!(byte[0], expected);
                    return;
                }
                Err(rustix::io::Errno::AGAIN) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                _ => panic!("bounded local acknowledgement refused"),
            }
        }
    }

    struct OwnedChild(Option<Child>);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn child(path: &std::path::Path, mode: &str) -> OwnedChild {
        OwnedChild(Some(
            Command::new(std::env::current_exe().unwrap())
                .args(if cfg!(feature = "kernel-qualification") {
                    vec!["--completion-child"]
                } else {
                    vec![
                        "--exact",
                        "linux::tests::cross_process_child",
                        "--ignored",
                        "--nocapture",
                    ]
                })
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("DAY2_COMPLETION_SOCKET", path)
                .env("DAY2_COMPLETION_MODE", mode)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }

    fn reaped(mut owned: OwnedChild) {
        let child = owned.0.as_mut().unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("bounded mechanical child exceeded deadline");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // These are fixed local child assertions, not a native receipt. Do not
        // print child stderr or inherited environments on a failure.
        let output = owned.0.take().unwrap().wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("COMPLETION_CHILD_PASS"));
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn real_foreign_reader_observes_only_after_publication_or_actual_refusal() {
        for mode in ["reader-known", "reader-refused"] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("socket");
            let listener = listener(&path);
            let child = child(&path, mode);
            let peer = accept(listener.as_fd());
            let pending = FreshPage::create(binding())
                .unwrap()
                .send_pending(peer.as_fd())
                .unwrap();
            ack(peer.as_fd(), b'P');
            if mode == "reader-known" {
                let Publication::Known(data) = pending.prepare().unwrap().publish() else {
                    panic!("first known refused")
                };
                reaped(child);
                drop(data);
            } else {
                drop(pending.prepare().unwrap());
                reaped(child);
            }
        }
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn real_producer_death_before_or_after_publication_does_not_invent_or_erase_known() {
        for mode in [
            "producer-death-pending",
            "producer-death-known",
            "producer-late-refusal",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("socket");
            let listener = listener(&path);
            let child = child(&path, mode);
            let peer = accept(listener.as_fd());
            sockopt::set_socket_passcred(&peer, true).unwrap();
            sockopt::set_socket_passpidfd(&peer, true).unwrap();
            rustix::net::send(&peer, b"S", SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
            let (fd, frame) = packet(peer.as_fd());
            let received = validate_received_data(fd, frame, binding()).unwrap();
            if mode == "producer-late-refusal" {
                assert_eq!(received.state_data().unwrap(), StateData::Pending);
                rustix::net::send(&peer, b"P", SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
            }
            reaped(child);
            assert_eq!(
                received.state_data().unwrap(),
                match mode {
                    "producer-death-pending" => StateData::Pending,
                    "producer-death-known" => StateData::Known,
                    _ => StateData::Refused,
                }
            );
        }
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn real_foreign_older_nonatomic_writer_remains_safe_data_not_a_mapping_precondition() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("socket");
        let listener = listener(&path);
        let child = child(&path, "foreign-alias");
        let peer = accept(listener.as_fd());
        sockopt::set_socket_passcred(&peer, true).unwrap();
        sockopt::set_socket_passpidfd(&peer, true).unwrap();
        rustix::net::send(&peer, b"S", SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
        let (fd, frame) = packet(peer.as_fd());
        let received = validate_received_data(fd, frame, binding()).unwrap();
        assert_eq!(received.state_data().unwrap(), StateData::Known);
        rustix::net::send(&peer, b"P", SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
        ack(peer.as_fd(), b'M');
        assert_eq!(
            received.state_data().err().unwrap().kind,
            FailureKind::State
        );
        reaped(child);
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    fn isolated_descriptor_zero_and_repeated_cleanup_are_real_kernel_cases() {
        for mode in ["descriptor-zero", "cleanup-census"] {
            let temp = tempfile::tempdir().unwrap();
            reaped(child(&temp.path().join("unused"), mode));
        }
    }

    #[cfg(feature = "kernel-qualification")]
    pub(super) fn verify_kernel_qualification() {
        use std::io::Read;
        let root = std::env::var_os("TEST_UNDECLARED_OUTPUTS_DIR")
            .map(std::path::PathBuf::from)
            .expect("Bazel bounded output directory");
        let file = std::fs::File::open(root.join("completion-kernel.txt")).unwrap();
        assert!(file.metadata().unwrap().is_file());
        let mut actual = Vec::new();
        file.take(4097).read_to_end(&mut actual).unwrap();
        assert!(actual.len() <= 4096, "bounded kernel receipt");
        let expected = concat!(
            "completion_kernel_v1 x86_64 mechanical_only\n",
            "PASS actual_backend\nPASS published_cleanup\nPASS abandonment\nPASS competing_terminal\n",
            "PASS all_binding_fields\nPASS readonly_transfer\nPASS forged_known_data\nPASS seals_and_state\n",
            "PASS failed_send\nPASS twice_replay\nPASS foreign_reader\nPASS producer_death\n",
            "PASS older_nonatomic_alias\nPASS descriptor_zero_cleanup\nPASS owned_envelope_data\nCOMPLETE 15\n"
        );
        assert_eq!(
            actual,
            expected.as_bytes(),
            "complete actual kernel qualification receipt required"
        );
    }

    /// Atomic ABI conformance only, not a native operational recipe or upload.
    /// The dedicated hosted test selects this once per actual rustix backend.
    #[cfg(feature = "kernel-qualification")]
    pub(super) fn actual_kernel_qualification() {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let output = std::env::var_os("TEST_UNDECLARED_OUTPUTS_DIR")
            .map(std::path::PathBuf::from)
            .expect("Bazel bounded output directory");
        let create = |name: &str| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(output.join(name))
                .unwrap()
        };
        // Fixed public kernel metadata only, never process argv/environment or
        // the host/node name. Read a bounded prefix, refusing truncation.
        use std::io::Read;
        let mut release = String::new();
        std::fs::File::open("/proc/sys/kernel/osrelease")
            .unwrap()
            .take(257)
            .read_to_string(&mut release)
            .unwrap();
        assert!(release.len() <= 256 && !release.trim().is_empty());
        assert!(
            release
                .trim()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-()".contains(&b))
        );
        let mut kernel = create("kernel-release.txt");
        kernel.write_all(release.as_bytes()).unwrap();
        kernel.sync_all().unwrap();
        let mut report = create("completion-kernel.txt");
        writeln!(report, "completion_kernel_v1 x86_64 mechanical_only").unwrap();
        report.sync_all().unwrap();
        for (name, bytes) in [
            ("component-lib.rs", include_bytes!("lib.rs").as_slice()),
            ("component-linux.rs", include_bytes!("linux.rs").as_slice()),
            (
                "selected-rustix-flags.txt",
                include_bytes!(env!("COMPLETION_RUSTIX_FLAGS")).as_slice(),
            ),
        ] {
            let mut file = create(name);
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
        let cases: [(&str, fn()); 15] = [
            (
                "actual_backend",
                actual_selected_rustix_backend_is_bound_to_its_build_script,
            ),
            (
                "published_cleanup",
                real_pending_publication_and_later_cleanup_keep_known_irreversible,
            ),
            (
                "abandonment",
                abandoning_pending_or_ready_refuses_without_inventing_known,
            ),
            (
                "competing_terminal",
                competing_terminal_state_never_becomes_local_known_or_gets_overwritten,
            ),
            (
                "all_binding_fields",
                exact_immutable_header_frame_and_all_binding_fields_are_required,
            ),
            (
                "readonly_transfer",
                actual_readonly_transfer_cannot_write_grow_shrink_or_make_new_writable_mapping,
            ),
            (
                "forged_known_data",
                forged_known_is_only_mechanical_data_not_creator_or_native_completion,
            ),
            (
                "seals_and_state",
                every_required_seal_and_valid_state_is_checked,
            ),
            (
                "failed_send",
                failed_fixed_send_refuses_the_page_and_never_supplies_a_ready_publisher,
            ),
            (
                "twice_replay",
                independent_generated_terminal_histories_replay_twice,
            ),
            (
                "foreign_reader",
                real_foreign_reader_observes_only_after_publication_or_actual_refusal,
            ),
            (
                "producer_death",
                real_producer_death_before_or_after_publication_does_not_invent_or_erase_known,
            ),
            (
                "older_nonatomic_alias",
                real_foreign_older_nonatomic_writer_remains_safe_data_not_a_mapping_precondition,
            ),
            (
                "descriptor_zero_cleanup",
                isolated_descriptor_zero_and_repeated_cleanup_are_real_kernel_cases,
            ),
            (
                "owned_envelope_data",
                owned_public_envelope_copy_matches_actual_send_and_refuses_equal_binding_substitution,
            ),
        ];
        for (name, case) in cases {
            case();
            writeln!(report, "PASS {name}").unwrap();
            report.sync_all().unwrap();
        }
        writeln!(report, "COMPLETE 15").unwrap();
        report.sync_all().unwrap();
        println!("COMPLETION_KERNEL_COMPLETE 15");
    }

    #[cfg_attr(not(feature = "kernel-qualification"), test)]
    #[cfg_attr(
        not(feature = "kernel-qualification"),
        ignore = "executed only by the bounded cross-process parent"
    )]
    pub(super) fn cross_process_child() {
        let path =
            std::env::var_os("DAY2_COMPLETION_SOCKET").expect("explicit isolated child path");
        let mode = std::env::var("DAY2_COMPLETION_MODE").expect("explicit child case");
        if mode == "descriptor-zero" {
            let (fd, frame) = foreign_page(PENDING, SEALS);
            // SAFETY: Only this isolated test child gives up its own stdin;
            // it never operates on fd0 again except through its new owner.
            let _ = unsafe { rustix::io::try_close(0) };
            let zero = rustix::io::dup(&fd).unwrap();
            assert_eq!(zero.as_raw_fd(), 0);
            rustix::io::fcntl_setfd(&zero, rustix::io::FdFlags::CLOEXEC).unwrap();
            let received = validate_received_data(zero, frame, binding()).unwrap();
            assert_eq!(received.state_data().unwrap(), StateData::Pending);
            drop(received);
            println!("COMPLETION_CHILD_PASS");
            return;
        }
        if mode == "cleanup-census" {
            let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
            let before = count();
            for _ in 0..24 {
                let (pending, received) = delivered();
                drop(pending);
                assert_eq!(received.state_data().unwrap(), StateData::Refused);
                drop(received);
            }
            assert_eq!(count(), before);
            println!("COMPLETION_CHILD_PASS");
            return;
        }
        let socket = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        if mode.starts_with("reader-") {
            sockopt::set_socket_passcred(&socket, true).unwrap();
            sockopt::set_socket_passpidfd(&socket, true).unwrap();
        }
        rustix::net::connect(
            &socket,
            &rustix::net::SocketAddrUnix::new(std::path::Path::new(&path)).unwrap(),
        )
        .unwrap();
        if mode == "foreign-alias" {
            ack(socket.as_fd(), b'S');
            let rw = rustix::fs::memfd_create(
                c"older-foreign-writer",
                MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
            )
            .unwrap();
            rustix::fs::ftruncate(&rw, PAGE_BYTES as u64).unwrap();
            let mut bytes = [0; PAGE_BYTES];
            bytes[..HEADER_BYTES].copy_from_slice(&binding().header());
            bytes[STATE_OFFSET as usize] = KNOWN;
            assert_eq!(pwrite(&rw, &bytes, 0).unwrap(), PAGE_BYTES);
            // SAFETY: This isolated adversary owns a fresh byte-only mapping;
            // no Rust atomic/reference is ever made to that page by the reader.
            let address = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    PAGE_BYTES,
                    ProtFlags::READ | ProtFlags::WRITE,
                    MapFlags::SHARED,
                    &rw,
                    0,
                )
            }
            .unwrap();
            rustix::fs::fcntl_add_seals(&rw, SEALS).unwrap();
            let ro = rustix::fs::open(
                format!("/proc/self/fd/{}", rw.as_raw_fd()),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let stat = rustix::fs::fstat(&ro).unwrap();
            let mut frame = [0; FRAME_BYTES];
            frame[..HEADER_BYTES].copy_from_slice(&binding().header());
            frame[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&stat.st_dev.to_le_bytes());
            frame[HEADER_BYTES + 8..].copy_from_slice(&stat.st_ino.to_le_bytes());
            let fds = [ro.as_fd()];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&fds)));
            assert_eq!(
                sendmsg(
                    &socket,
                    &[IoSlice::new(&frame)],
                    &mut ancillary,
                    SendFlags::DONTWAIT | SendFlags::NOSIGNAL
                )
                .unwrap(),
                FRAME_BYTES
            );
            ack(socket.as_fd(), b'P');
            // SAFETY: Deliberate foreign overlapping/wider NON-atomic writes
            // into this child's own byte mapping, outside any Rust references.
            // The receiver can safely handle them because it only uses pread.
            unsafe {
                address
                    .cast::<u8>()
                    .add(STATE_OFFSET as usize - 7)
                    .cast::<u64>()
                    .write_unaligned(u64::MAX);
                address.cast::<u8>().write(255);
            }
            rustix::net::send(&socket, b"M", SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
            // SAFETY: The same private byte mapping is no longer used.
            unsafe { munmap(address, PAGE_BYTES) }.unwrap();
            println!("COMPLETION_CHILD_PASS");
            return;
        }
        if mode.starts_with("reader-") {
            let (fd, frame) = packet(socket.as_fd());
            let received = validate_received_data(fd, frame, binding()).unwrap();
            assert_eq!(received.state_data().unwrap(), StateData::Pending);
            rustix::net::send(&socket, b"P", SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
            wait_state(
                &received,
                if mode == "reader-known" {
                    StateData::Known
                } else {
                    StateData::Refused
                },
            );
        } else {
            ack(socket.as_fd(), b'S');
            let pending = FreshPage::create(binding())
                .unwrap()
                .send_pending(socket.as_fd())
                .unwrap();
            let ready = pending.prepare().unwrap();
            if mode == "producer-death-pending" {
                println!("COMPLETION_CHILD_PASS");
                std::process::exit(0);
            }
            if mode == "producer-death-known" {
                let Publication::Known(_hold) = ready.publish() else {
                    panic!("first known refused")
                };
                println!("COMPLETION_CHILD_PASS");
                std::process::exit(0);
            }
            assert_eq!(mode, "producer-late-refusal");
            ack(socket.as_fd(), b'P');
            drop(ready);
        }
        println!("COMPLETION_CHILD_PASS");
    }
}
