//! Retained identity, not a renewable permission. Only the private kernel packet
//! and fixed runtime adapters construct it; certificate rows cannot adopt it.

use super::{executable_bytes, issuer_costs::HashCosts};
use crate::security_epoch::native_enrollment::protocol::ProcessData;
use crate::security_epoch::{
    namespace_protocol, native_clock::NativeAcquisition, native_namespace as ns,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use rustix::{
    event::{PollFd, PollFlags},
    fs::{Mode, OFlags},
    net::{KernelPidVisibility, ReceivedPidfdPacket},
};
use std::{collections::BTreeMap, fs::File, marker::PhantomData, rc::Rc, thread::ThreadId};

const NAMESPACES: [&str; 6] = ["time", "time_for_children", "pid", "mnt", "user", "cgroup"];

pub(super) struct SelfSnapshot {
    pub process: crate::security_epoch::NativeProcessObservation,
    pub namespace: crate::security_epoch::NativeNamespaceObservation,
    pub data: ProcessData,
}

impl SelfSnapshot {
    pub(super) fn acquire(
        code: &Digest,
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<Self> {
        let process =
            crate::security_epoch::NativeProcessObservation::acquire(code, acquisition, costs)?;
        let namespace = crate::security_epoch::NativeNamespaceObservation::acquire(acquisition)?;
        let proc = ns::open_root(acquisition)?;
        let root = open_process(&proc, std::process::id(), acquisition)?;
        let data = ProcessData {
            process: std::process::id(),
            start_ticks: start(&root, std::process::id(), acquisition)?,
            code: code.clone(),
            boot: boot(acquisition)?,
            namespaces: namespace
                .data()
                .namespaces
                .iter()
                .map(|(k, v)| (k.clone(), (v.device, v.inode)))
                .collect(),
        };
        Ok(Self {
            process,
            namespace,
            data,
        })
    }

    pub(super) fn check(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        {
            let _profile = crate::security_epoch::self_check_profile::enter(
                crate::security_epoch::self_check_profile::Category::SelfProcess,
            );
            self.process.check(acquisition)?;
        }
        {
            let _profile = crate::security_epoch::self_check_profile::enter(
                crate::security_epoch::self_check_profile::Category::Namespace,
            );
            self.namespace.check(acquisition)?;
        }
        Ok(())
    }

    pub(super) fn require_node_init(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        self.check(acquisition)?;
        let root = ns::open_root(acquisition)?;
        let init = open_process(&root, 1, acquisition)?;
        for name in ["time", "time_for_children", "pid", "user"] {
            let file = ns::open_namespace(&init, name, acquisition)?;
            let value = ns::namespace_identity(&file)?;
            ensure!(
                self.data.namespaces.get(name) == Some(&(value.device, value.inode)),
                "native_enrollment_node_init_namespace"
            );
        }
        self.check(acquisition)
    }
}

pub(super) struct MessageProcess {
    pidfd: File,
    proc: File,
    process: File,
    executable: File,
    executable_stamp: executable_bytes::Stamp,
    namespaces: BTreeMap<String, File>,
    data: ProcessData,
    local_process: u32,
    thread: ThreadId,
    refused: bool,
    local: PhantomData<Rc<()>>,
}

impl MessageProcess {
    pub(super) fn receive(
        packet: ReceivedPidfdPacket,
        expected_code: &Digest,
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<Self> {
        Self::observe(
            packet.process,
            packet.credentials.process,
            expected_code,
            acquisition,
            costs,
        )
    }

    /// Retain the actual first sender's native resources for this channel.
    /// This duplicates owned descriptors, never a PID lookup or parsed proof.
    /// It grants no role or request authority; those checks stay with Peer.
    pub(super) fn retain_message_anchor(
        &mut self,
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<Self> {
        let result = (|| {
            self.check_identity(acquisition, costs)?;
            let mut retained = Self {
                pidfd: File::try_clone(&self.pidfd)?,
                proc: File::try_clone(&self.proc)?,
                process: File::try_clone(&self.process)?,
                executable: File::try_clone(&self.executable)?,
                executable_stamp: self.executable_stamp.clone(),
                namespaces: self
                    .namespaces
                    .iter()
                    .map(|(name, file)| File::try_clone(file).map(|file| (name.clone(), file)))
                    .collect::<std::io::Result<BTreeMap<_, _>>>()?,
                data: self.data.clone(),
                local_process: self.local_process,
                thread: self.thread,
                refused: false,
                local: PhantomData,
            };
            Self::check_same_actor(&mut [&mut *self, &mut retained], acquisition, costs)?;
            Ok(retained)
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }

    /// Every later packet still contributes its ORIGINAL received SCM_PIDFD.
    /// Join it to the same live admitted sender and original native anchors;
    /// a transferred socket, reused PID or changed path/namespace cannot borrow
    /// the selected executable admission from another actor.
    pub(super) fn receive_admitted(
        packet: ReceivedPidfdPacket,
        admitted: &mut Self,
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<Self> {
        let result = (|| {
            let process = match packet.credentials.process {
                KernelPidVisibility::Visible(pid) => pid.get(),
                KernelPidVisibility::NotVisible => {
                    anyhow::bail!("native_enrollment_pid_not_visible")
                }
            };
            ensure!(
                process == admitted.data.process,
                "native_enrollment_packet_actor_changed"
            );
            let pidfd = File::from(packet.process);
            live(&pidfd, acquisition)?;
            let mut received = admitted.retain_message_anchor(acquisition, costs)?;
            // Drop the duplicate of the admission packet's pidfd and retain
            // THIS packet's actual kernel-installed descriptor instead.
            received.pidfd = pidfd;
            Self::check_same_actor(&mut [&mut *admitted, &mut received], acquisition, costs)?;
            Ok(received)
        })();
        if result.is_err() {
            admitted.refused = true;
            acquisition.refuse();
        }
        result
    }

    /// Only the fixed runtime adapter calls this on its newly connected socket.
    /// Connection identity has deliberately different provenance from a packet.
    pub(super) fn runtime_peer(
        socket: &std::os::unix::net::UnixStream,
        code: &Digest,
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<Self> {
        acquisition.remaining()?;
        let credentials =
            nix::sys::socket::getsockopt(socket, nix::sys::socket::sockopt::PeerCredentials)?;
        let pid = std::num::NonZeroU32::new(u32::try_from(credentials.pid())?)
            .ok_or_else(|| anyhow::anyhow!("native_enrollment_runtime_peer_pid"))?;
        let pidfd = nix::sys::socket::getsockopt(socket, nix::sys::socket::sockopt::PeerPidfd)?;
        acquisition.remaining()?;
        Self::observe(
            pidfd,
            KernelPidVisibility::Visible(pid),
            code,
            acquisition,
            costs,
        )
    }

    fn observe(
        pidfd: std::os::fd::OwnedFd,
        visibility: KernelPidVisibility,
        expected_code: &Digest,
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<Self> {
        let result = (|| {
            let pid = match visibility {
                KernelPidVisibility::Visible(pid) => pid.get(),
                KernelPidVisibility::NotVisible => {
                    anyhow::bail!("native_enrollment_pid_not_visible")
                }
            };
            let pidfd = File::from(pidfd);
            live(&pidfd, acquisition)?;
            let proc = ns::open_root(acquisition)?;
            let process = open_process(&proc, pid, acquisition)?;
            let executable = executable(&process, acquisition)?;
            let mut current_executable = self::executable(&process, acquisition)?;
            let executable_stamp = executable_bytes::admit(
                &[&executable],
                &mut current_executable,
                expected_code,
                acquisition,
                costs,
            )?;
            let mut namespaces = BTreeMap::new();
            let mut identities = BTreeMap::new();
            for name in NAMESPACES {
                let fd = ns::open_namespace(&process, name, acquisition)?;
                let value = ns::namespace_identity(&fd)?;
                identities.insert(name.to_owned(), (value.device, value.inode));
                namespaces.insert(name.to_owned(), fd);
            }
            ensure!(
                identities["time"] == identities["time_for_children"],
                "native_enrollment_child_time_namespace"
            );
            let start_ticks = start(&process, pid, acquisition)?;
            let boot = boot(acquisition)?;
            let mut owner = Self {
                pidfd,
                proc,
                process,
                executable,
                executable_stamp,
                namespaces,
                data: ProcessData {
                    process: pid,
                    start_ticks,
                    // The complete admission above checked the selected bytes;
                    // this DATA cannot reconstruct the retained native owner.
                    code: expected_code.clone(),
                    boot,
                    namespaces: identities,
                },
                local_process: std::process::id(),
                thread: std::thread::current().id(),
                refused: false,
                local: PhantomData,
            };
            // This provisional value never escapes before its full admission
            // and the final held/current/path, namespace, process, liveness and
            // original-clock joins. Later checks keep those actual resources
            // rather than reading the complete executable again.
            owner.check_identity(acquisition, costs)?;
            Ok(owner)
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    pub(super) fn data(&self) -> &ProcessData {
        &self.data
    }

    /// Rechecks the actual admitted process handles in a bounded acquisition.
    /// This does not extend any earlier acquisition or grant a role by itself.
    pub(super) fn check_identity(
        &mut self,
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<()> {
        Self::check_same_actor(&mut [self], acquisition, costs)
    }

    /// One fresh observation for 1..=5 retained handles of the SAME actual actor.
    /// Every owner originates in a kernel packet or the fixed runtime socket;
    /// matching signed DATA alone cannot join them. Every actual native handle
    /// is rechecked against its admitted stamp without another content scan.
    /// No reusable checked token escapes; later boundaries check these actual
    /// resources, original clocks and refusal again.
    pub(super) fn check_same_actor(
        processes: &mut [&mut Self],
        acquisition: &mut NativeAcquisition,
        costs: &HashCosts,
    ) -> Result<()> {
        let mut profile = crate::security_epoch::self_check_profile::enter(
            crate::security_epoch::self_check_profile::Category::Peer,
        );
        let mut timing = costs.start_identity();
        let result = (|| {
            ensure!(
                (1..=5).contains(&processes.len()),
                "native_enrollment_process_owner_bound"
            );
            let first = &*processes[0];
            for owner in processes.iter() {
                ensure!(!owner.refused, "native_enrollment_process_refused");
                ensure!(
                    owner.local_process == std::process::id()
                        && owner.thread == std::thread::current().id(),
                    "native_enrollment_process_owner_changed"
                );
                ensure!(
                    owner.data == first.data,
                    "native_enrollment_process_actor_changed"
                );
                live(&owner.pidfd, acquisition)?;
            }
            let proc = ns::open_root(acquisition)?;
            let current = open_process(&proc, first.data.process, acquisition)?;
            let proc_identity = ns::proc_identity(&proc)?;
            let process_identity = ns::proc_identity(&current)?;
            for owner in processes.iter() {
                ensure!(
                    proc_identity == ns::proc_identity(&owner.proc)?,
                    "native_enrollment_proc_mount_changed"
                );
                ensure!(
                    process_identity == ns::proc_identity(&owner.process)?,
                    "native_enrollment_process_replaced"
                );
            }
            ensure!(
                start(&current, first.data.process, acquisition)? == first.data.start_ticks,
                "native_enrollment_process_start_changed"
            );
            ensure!(
                boot(acquisition)? == first.data.boot,
                "native_enrollment_boot_changed"
            );
            let current_executable = executable(&current, acquisition)?;
            let held_executables = processes
                .iter()
                .map(|owner| &owner.executable)
                .collect::<Vec<_>>();
            let executable_stamp = &first.executable_stamp;
            for owner in processes.iter() {
                ensure!(
                    owner.executable_stamp == *executable_stamp,
                    "native_enrollment_executable_admission_changed"
                );
            }
            executable_bytes::check_handles(
                &held_executables,
                &current_executable,
                &current_executable,
                executable_stamp,
                acquisition,
            )?;
            for name in NAMESPACES {
                let namespace = ns::open_namespace(&current, name, acquisition)?;
                for fd in std::iter::once(&namespace)
                    .chain(processes.iter().map(|owner| &owner.namespaces[name]))
                {
                    let value = ns::namespace_identity(fd)?;
                    ensure!(
                        (value.device, value.inode) == first.data.namespaces[name],
                        "native_enrollment_namespace_changed"
                    );
                }
            }
            let mut offsets = ns::open_proc(&current, "timens_offsets", acquisition)?;
            namespace_protocol::require_zero(&namespace_protocol::offsets(&ns::read_proc(
                &mut offsets,
                1024,
                acquisition,
            )?)?)?;
            // Reopen the actual process path after the remaining namespace work.
            // Earlier descriptors alone cannot observe a later exec/path change.
            let final_executable = executable(&current, acquisition)?;
            executable_bytes::check_handles(
                &held_executables,
                &current_executable,
                &final_executable,
                executable_stamp,
                acquisition,
            )?;
            // Diagnostic sampling finishes before the final pidfd/original-clock
            // guard. Held executable FDs survive process exit.
            costs.finish_identity(&mut timing);
            profile.finish();
            for owner in processes.iter() {
                live(&owner.pidfd, acquisition)?;
            }
            Ok(())
        })();
        // On earlier errors there is no authority to return. Record the failed
        // body without replacing its error or clearing the original refusal.
        costs.finish_identity(&mut timing);
        if result.is_err() {
            for owner in processes.iter_mut() {
                owner.refused = true;
            }
            acquisition.refuse();
        }
        result
    }
}

pub(super) fn live(fd: &File, acquisition: &mut NativeAcquisition) -> Result<()> {
    acquisition.remaining()?;
    let mut fds = [PollFd::new(fd, PollFlags::IN)];
    let zero = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure!(
        rustix::event::poll(&mut fds, Some(&zero))? == 0 && fds[0].revents().is_empty(),
        "native_enrollment_process_exited"
    );
    acquisition.remaining()?;
    Ok(())
}

fn open_process(proc: &File, pid: u32, acquisition: &mut NativeAcquisition) -> Result<File> {
    acquisition.remaining()?;
    let fd = File::from(rustix::fs::openat(
        proc,
        pid.to_string(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    ns::require_proc(&fd)?;
    acquisition.remaining()?;
    Ok(fd)
}

fn executable(process: &File, acquisition: &mut NativeAcquisition) -> Result<File> {
    acquisition.remaining()?;
    // Fixed kernel-owned procfs magic link, never a caller path.
    let fd = File::from(rustix::fs::openat(
        process,
        "exe",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    acquisition.remaining()?;
    Ok(fd)
}

fn start(process: &File, pid: u32, acquisition: &mut NativeAcquisition) -> Result<u64> {
    let mut stat = ns::open_proc(process, "stat", acquisition)?;
    let mut status = ns::open_proc(process, "status", acquisition)?;
    let facts = namespace_protocol::task(
        &ns::read_proc(&mut stat, 16_384, acquisition)?,
        &ns::read_proc(&mut status, 65_536, acquisition)?,
    )?;
    ensure!(
        facts.process == pid && facts.thread == pid,
        "native_enrollment_process_leader"
    );
    Ok(facts.start_ticks)
}

pub(super) fn boot(acquisition: &mut NativeAcquisition) -> Result<String> {
    acquisition.remaining()?;
    let mut file = File::from(rustix::fs::open(
        "/proc/sys/kernel/random/boot_id",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    ns::require_proc(&file)?;
    let bytes = ns::read_proc(&mut file, 37, acquisition)?;
    let value = std::str::from_utf8(&bytes)?
        .strip_suffix('\n')
        .ok_or_else(|| anyhow::anyhow!("native_enrollment_boot_format"))?;
    ensure!(
        value.len() == 36
            && value
                .bytes()
                .enumerate()
                .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }),
        "native_enrollment_boot_format"
    );
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::native_enrollment::{
        channel::Channel,
        issuer_costs::{Outcome, Recorder, Subject},
        protocol::Packet,
    };
    use anyhow::Context;
    use std::{
        process::{Command, Stdio},
        time::Duration,
    };

    fn packet() -> Packet {
        Packet::BirthChallenge {
            policy: Digest::new(b"same-actor-test-only"),
            nonce: Digest::new(b"actual-kernel-packets"),
        }
    }

    fn self_receipts(count: usize) -> Result<Vec<MessageProcess>> {
        let code = Digest::new(&std::fs::read("/proc/self/exe")?);
        let mut a = NativeAcquisition::begin(5)?;
        let (mut channel, sender) = Channel::pair(&mut a)?;
        let mut owners = Vec::new();
        for _ in 0..count {
            let mut a = NativeAcquisition::begin(5)?;
            rustix::net::send(
                &sender,
                &serde_json::to_vec(&packet())?,
                rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
            )?;
            let (_, owner) = channel.receive(&code, &mut a, &HashCosts::disabled())?;
            owners.push(owner);
        }
        Ok(owners)
    }

    #[test]
    fn admitted_packet_retains_this_messages_original_kernel_pidfd() -> Result<()> {
        use rustix::net::{self, AddressFamily, SocketFlags, SocketType};
        use std::{io::IoSliceMut, os::fd::AsRawFd};
        // Real kernel sender/FD conformance only, without role or peer grants.
        let code = Digest::new(&std::fs::read("/proc/self/exe")?);
        let (receiver, sender) = net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        net::sockopt::set_socket_passcred(&receiver, true)?;
        net::sockopt::set_socket_passpidfd(&receiver, true)?;
        let receive = || -> Result<ReceivedPidfdPacket> {
            net::send(&sender, b"public kernel sender", net::SendFlags::NOSIGNAL)?;
            let mut bytes = [0_u8; 64];
            Ok(net::recv_pidfd_packet(
                &receiver,
                &mut [IoSliceMut::new(&mut bytes)],
            )?)
        };
        let mut acquisition = NativeAcquisition::begin(5)?;
        let mut admitted =
            MessageProcess::receive(receive()?, &code, &mut acquisition, &HashCosts::disabled())?;
        for _ in 0..2 {
            let mut acquisition = NativeAcquisition::begin(5)?;
            let packet = receive()?;
            let actual_message_pidfd = packet.process.as_raw_fd();
            let mut received = MessageProcess::receive_admitted(
                packet,
                &mut admitted,
                &mut acquisition,
                &HashCosts::disabled(),
            )?;
            assert_eq!(received.pidfd.as_raw_fd(), actual_message_pidfd);
            assert_ne!(received.pidfd.as_raw_fd(), admitted.pidfd.as_raw_fd());
            received.check_identity(&mut acquisition, &HashCosts::disabled())?;
        }
        Ok(())
    }

    struct ChildOwner(std::process::Child);

    impl Drop for ChildOwner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "actual SCM_PIDFD sender subprocess for same-actor controls"]
    fn packet_child() -> Result<()> {
        ensure!(std::env::var_os("DAY2_NATIVE_SAME_ACTOR_CHILD").is_some());
        let mut a = NativeAcquisition::begin(5)?;
        let mut channel = Channel::startup(&mut a)?;
        for _ in 0..2 {
            channel.send(&packet(), &mut a)?;
        }
        loop {
            std::thread::park();
        }
    }

    fn child_receipts(costs: &HashCosts) -> Result<(ChildOwner, Vec<MessageProcess>)> {
        let code = Digest::new(&std::fs::read("/proc/self/exe")?);
        let mut a = NativeAcquisition::begin(5)?;
        let (mut channel, sender) = Channel::pair(&mut a)?;
        let child = ChildOwner(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "security_epoch::native_enrollment::process::tests::packet_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("DAY2_NATIVE_SAME_ACTOR_CHILD", "1")
                .stdin(Stdio::from(sender))
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        let mut owners = Vec::new();
        for _ in 0..2 {
            let mut a = NativeAcquisition::begin(5)?;
            let (_, owner) = channel.receive(&code, &mut a, costs)?;
            assert_eq!(owner.data().process, child.0.id());
            owners.push(owner);
        }
        Ok((child, owners))
    }

    fn recorded(output: Vec<u8>) -> Result<serde_json::Value> {
        Ok(serde_json::from_str(
            String::from_utf8(output)?
                .strip_prefix("day2-native-issuer-cost ")
                .unwrap(),
        )?)
    }

    #[test]
    #[ignore = "scoped Linux cost fixture; not a full enrolled Controller or node qualification"]
    fn profile_actual_retained_peer_and_self_guards() -> Result<()> {
        use crate::security_epoch::self_check_profile::{self, Profile};
        let code = Digest::new(&std::fs::read("/proc/self/exe")?);
        let length = std::fs::metadata("/proc/self/exe")?.len();
        let mut original = NativeAcquisition::begin(5)?;
        let mut current = SelfSnapshot::acquire(&code, &mut original, &HashCosts::disabled())?;
        let mut owners = self_receipts(5)?;
        let mut total = Profile::EMPTY;
        for _ in 0..8 {
            let mut peer = NativeAcquisition::begin(5)?;
            let (checked, profile) = self_check_profile::sample(|| {
                current.check(&mut original)?;
                MessageProcess::check_same_actor(
                    &mut owners.iter_mut().collect::<Vec<_>>(),
                    &mut peer,
                    &HashCosts::disabled(),
                )
            });
            total.add(profile.unwrap());
            checked?;
            // Actual clocks are still sampled after all diagnostic work.
            original.remaining()?;
            peer.remaining()?;
        }
        assert_eq!(total.samples, Some(8));
        assert_eq!(total.rows[1].0, Some(0));
        for index in [2, 3, 5] {
            assert_eq!(total.rows[index].0, Some(8));
        }
        eprintln!(
            "day2-native-peer-profile-fixture {}",
            serde_json::json!({
                "scope": "actual_retained_peer_and_self_guards_only",
                "executable_length": length,
                "profile": total,
            })
        );
        Ok(())
    }

    #[test]
    fn actual_admitted_receipts_recheck_handles_without_another_executable_read() -> Result<()> {
        let mut owners = self_receipts(5)?;
        let mut output = Vec::new();
        {
            let mut recorder = Recorder::new(&mut output);
            let costs = recorder.connection();
            for _ in 0..2 {
                let mut a = NativeAcquisition::begin(5)?;
                MessageProcess::check_same_actor(
                    &mut owners.iter_mut().collect::<Vec<_>>(),
                    &mut a,
                    &costs.hashes(Subject::Requester),
                )?;
                a.remaining()?;
            }
            recorder.emit(&costs, Outcome::Completed)?;
        }
        let record = recorded(output)?;
        let rows = record["rows"].as_array().unwrap();
        assert!(rows.iter().all(|row| row[0] != "hash_requester"));
        let body = rows
            .iter()
            .find(|r| r[0] == "identity_requester_body")
            .unwrap();
        assert_eq!(body[1][0], 2);
        Ok(())
    }

    #[test]
    fn substituted_actual_retained_executable_refuses_before_and_after_restoration() -> Result<()> {
        let mut owners = self_receipts(1)?;
        let owner = &mut owners[0];
        let mut foreign = tempfile::NamedTempFile::new()?;
        std::io::Write::write_all(foreign.as_file_mut(), b"foreign actual descriptor")?;
        let admitted = std::mem::replace(&mut owner.executable, foreign.reopen()?);
        let mut acquisition = NativeAcquisition::begin(5)?;
        let error = owner
            .check_identity(&mut acquisition, &HashCosts::disabled())
            .err()
            .context("substituted actual descriptor must refuse")?;
        assert_eq!(error.to_string(), "native_enrollment_executable_changed");
        assert!(owner.refused);
        assert!(acquisition.remaining().is_err());
        owner.executable = admitted;
        let mut later = NativeAcquisition::begin(5)?;
        let error = owner
            .check_identity(&mut later, &HashCosts::disabled())
            .err()
            .context("restoration cannot revive the actual process owner")?;
        assert_eq!(error.to_string(), "native_enrollment_process_refused");
        assert!(later.remaining().is_err());
        Ok(())
    }

    #[test]
    fn distinct_real_actor_is_hashed_on_receipt_and_refuses_the_entire_group() -> Result<()> {
        let mut local = self_receipts(1)?.remove(0);
        let length = std::fs::metadata("/proc/self/exe")?.len();
        let mut output = Vec::new();
        {
            let mut recorder = Recorder::new(&mut output);
            let costs = recorder.connection();
            let (_child, mut owners) = child_receipts(&costs.hashes(Subject::Requester))?;
            let mut a = NativeAcquisition::begin(5)?;
            let error = MessageProcess::check_same_actor(
                &mut [&mut local, &mut owners[0]],
                &mut a,
                &costs.hashes(Subject::Requester),
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "native_enrollment_process_actor_changed");
            assert!(a.remaining().is_err());
            for owner in [&mut local, &mut owners[0]] {
                let mut later = NativeAcquisition::begin(5)?;
                assert!(
                    owner
                        .check_identity(&mut later, &HashCosts::disabled())
                        .is_err()
                );
                assert!(later.remaining().is_err());
            }
            // The ungrouped second actual receipt was not refused by association.
            owners[1].check_identity(&mut NativeAcquisition::begin(5)?, &HashCosts::disabled())?;
            recorder.emit(&costs, Outcome::Completed)?;
        }
        let record = recorded(output)?;
        let hash = record["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r[0] == "hash_requester")
            .unwrap();
        // Each NEW receipt gets its own closed, full fresh-byte observation.
        // Matching executable bytes never adopt another process or skip it.
        assert_eq!(hash[1][0], 2);
        assert_eq!(hash[1][1], 2 * length);
        Ok(())
    }

    #[test]
    fn wrong_selected_bytes_never_return_an_owner_or_revive_the_channel() -> Result<()> {
        let code = Digest::new(&std::fs::read("/proc/self/exe")?);
        let length = std::fs::metadata("/proc/self/exe")?.len();
        let wrong = Digest::new(b"not-the-actual-sender-executable");
        assert_ne!(wrong, code);
        let mut a = NativeAcquisition::begin(5)?;
        let (mut channel, sender) = Channel::pair(&mut a)?;
        rustix::net::send(
            &sender,
            &serde_json::to_vec(&packet())?,
            rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
        )?;
        let mut output = Vec::new();
        {
            let mut recorder = Recorder::new(&mut output);
            let costs = recorder.connection();
            let error = match channel.receive(&wrong, &mut a, &costs.hashes(Subject::Requester)) {
                Err(error) => error,
                Ok(_) => panic!("a wrong selected digest must not return a native owner"),
            };
            assert_eq!(error.to_string(), "native_enrollment_code_mismatch");
            assert!(a.remaining().is_err());
            let mut later = NativeAcquisition::begin(5)?;
            let error = match channel.receive(&code, &mut later, &HashCosts::disabled()) {
                Err(error) => error,
                Ok(_) => panic!("a later correct pin must not revive the refused channel"),
            };
            assert_eq!(error.to_string(), "native_enrollment_channel_refused");
            assert!(later.remaining().is_err());
            recorder.emit(&costs, Outcome::RequestError)?;
        }
        let record = recorded(output)?;
        let hash = record["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r[0] == "hash_requester")
            .unwrap();
        assert_eq!(hash[1][0], 1);
        assert_eq!(hash[1][1], length);
        Ok(())
    }

    #[test]
    fn exited_actual_actor_refuses_every_retained_receipt() -> Result<()> {
        let (mut child, mut owners) = child_receipts(&HashCosts::disabled())?;
        child.0.kill()?;
        child.0.wait()?;
        let mut a = NativeAcquisition::begin(5)?;
        let error = MessageProcess::check_same_actor(
            &mut owners.iter_mut().collect::<Vec<_>>(),
            &mut a,
            &HashCosts::disabled(),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "native_enrollment_process_exited");
        assert!(a.remaining().is_err());
        for owner in &mut owners {
            let mut later = NativeAcquisition::begin(5)?;
            assert!(
                owner
                    .check_identity(&mut later, &HashCosts::disabled())
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn expired_original_refuses_all_owners_and_a_new_clock_cannot_revive_them() -> Result<()> {
        let mut owners = self_receipts(2)?;
        let mut a = NativeAcquisition::fixture(
            Digest::new(b"expired-same-actor-only"),
            std::process::id(),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert!(
            MessageProcess::check_same_actor(
                &mut owners.iter_mut().collect::<Vec<_>>(),
                &mut a,
                &HashCosts::disabled(),
            )
            .is_err()
        );
        assert!(a.remaining().is_err());
        for owner in &mut owners {
            let mut later = NativeAcquisition::begin(5)?;
            assert!(
                owner
                    .check_identity(&mut later, &HashCosts::disabled())
                    .is_err()
            );
            assert!(later.remaining().is_err());
        }
        Ok(())
    }

    #[test]
    fn empty_and_oversized_groups_refuse_without_a_permission_token() -> Result<()> {
        let mut a = NativeAcquisition::begin(5)?;
        assert!(MessageProcess::check_same_actor(&mut [], &mut a, &HashCosts::disabled()).is_err());
        assert!(a.remaining().is_err());
        let mut owners = self_receipts(6)?;
        let mut a = NativeAcquisition::begin(5)?;
        let error = MessageProcess::check_same_actor(
            &mut owners.iter_mut().collect::<Vec<_>>(),
            &mut a,
            &HashCosts::disabled(),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "native_enrollment_process_owner_bound");
        assert!(a.remaining().is_err());
        for owner in &mut owners {
            let mut later = NativeAcquisition::begin(5)?;
            assert!(
                owner
                    .check_identity(&mut later, &HashCosts::disabled())
                    .is_err()
            );
        }
        Ok(())
    }
}
