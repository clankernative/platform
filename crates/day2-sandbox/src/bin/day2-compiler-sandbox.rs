//! Private build capability. Never installed in an application's runtime image.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("compiler confinement requires Linux")
}

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context, Result, ensure};
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };
    use nix::{
        libc,
        sys::{
            prctl,
            resource::{Resource, setrlimit},
            signal::Signal,
        },
        unistd::{close, getppid},
    };
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule,
    };
    use std::{
        collections::BTreeMap, fs, os::unix::process::CommandExt, path::PathBuf, process::Command,
    };

    fn bounded_metadata(path: &str) -> Result<String> {
        use std::io::Read;
        let mut text = String::new();
        fs::File::open(path)?
            .take(1_048_577)
            .read_to_string(&mut text)?;
        ensure!(text.len() <= 1_048_576, "compiler kernel metadata budget");
        Ok(text)
    }

    fn tmpfs_size(value: &str) -> Result<u64> {
        let (number, multiplier) = if let Some(value) = value.strip_suffix('k') {
            (value, 1024_u64)
        } else if let Some(value) = value.strip_suffix('m') {
            (value, 1024_u64 * 1024)
        } else {
            (value, 1)
        };
        ensure!(
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()),
            "finite tmpfs quota required"
        );
        number
            .parse::<u64>()?
            .checked_mul(multiplier)
            .context("tmpfs quota overflow")
    }

    fn bounded_tmpfs(mounts: &str, path: &std::path::Path, maximum: u64) -> Result<()> {
        let mut selected = None;
        for line in mounts.lines() {
            let (left, right) = line
                .split_once(" - ")
                .context("invalid compiler mount metadata")?;
            let fields: Vec<_> = left.split_whitespace().collect();
            let filesystem: Vec<_> = right.split_whitespace().collect();
            ensure!(
                fields.len() >= 6 && filesystem.len() >= 3,
                "invalid compiler mount fields"
            );
            // Platform build paths are fixed ASCII paths; escaped paths are not
            // admitted in this first native Linux build profile.
            let mount = std::path::Path::new(fields[4]);
            if path.starts_with(mount) {
                let depth = mount.components().count();
                if selected
                    .as_ref()
                    .is_none_or(|(previous, _)| depth >= *previous)
                {
                    let quota = filesystem[2]
                        .split(',')
                        .find_map(|option| option.strip_prefix("size="));
                    let valid = filesystem[0] == "tmpfs"
                        && fields[5].split(',').any(|option| option == "rw")
                        && quota
                            .map(tmpfs_size)
                            .transpose()?
                            .is_some_and(|bytes| bytes > 0 && bytes <= maximum);
                    selected = Some((depth, valid));
                }
            }
            ensure!(
                mount == path || !mount.starts_with(path),
                "nested compiler output mounts forbidden"
            );
        }
        ensure!(
            selected.is_some_and(|(_, valid)| valid),
            "compiler output requires bounded writable tmpfs: {}",
            path.display()
        );
        Ok(())
    }

    fn output_guards(stage: &std::path::Path, generated: &std::path::Path) -> Result<()> {
        ensure!(
            bounded_metadata("/proc/self/cgroup")?.trim() == "0::/",
            "compiler requires private cgroup v2 namespace"
        );
        let memory = bounded_metadata("/sys/fs/cgroup/memory.max")?;
        let memory: u64 = memory
            .trim()
            .parse()
            .context("finite compiler cgroup memory required")?;
        ensure!(
            (1..=6 * 1024 * 1024 * 1024).contains(&memory),
            "compiler cgroup memory exceeds 6 GiB"
        );
        let mounts = bounded_metadata("/proc/self/mountinfo")?;
        bounded_tmpfs(&mounts, stage, 1024 * 1024 * 1024)?;
        bounded_tmpfs(&mounts, generated, 64 * 1024 * 1024)?;
        Ok(())
    }

    pub fn run() -> Result<()> {
        let mut args = std::env::args_os().skip(1);
        let root = PathBuf::from(args.next().context("missing platform root")?).canonicalize()?;
        let stage = PathBuf::from(args.next().context("missing build stage")?).canonicalize()?;
        let roc = PathBuf::from(args.next().context("missing compiler")?).canonicalize()?;
        let parent: i32 = args
            .next()
            .context("missing parent")?
            .to_str()
            .context("parent encoding")?
            .parse()?;
        ensure!(
            args.next().is_some_and(|arg| arg == "--"),
            "missing compiler argument delimiter"
        );
        ensure!(
            stage == root.join("artifacts/build").canonicalize()?
                || stage == root.join("artifacts/admission").canonicalize()?,
            "compiler stage must be a platform-owned build or admission stage"
        );
        ensure!(
            roc == root.join("../.toolchains/roc").canonicalize()?,
            "compiler must be the pinned platform toolchain"
        );
        let generated = root.join("crates/worker/generated").canonicalize()?;
        output_guards(&stage, &generated)?;
        ensure!(
            parent > 0 && getppid().as_raw() == parent,
            "compiler supervisor exited"
        );
        prctl::set_pdeathsig(Some(Signal::SIGKILL))?;
        ensure!(
            getppid().as_raw() == parent,
            "compiler supervisor exited during setup"
        );

        // These descriptors came from the host process, not the source snapshot.
        let descriptors = fs::read_dir("/proc/self/fd")?
            .map(|entry| -> Result<i32> {
                Ok(entry?
                    .file_name()
                    .to_str()
                    .context("descriptor name")?
                    .parse()?)
            })
            .collect::<Result<Vec<_>>>()?;
        for fd in descriptors.into_iter().filter(|fd| *fd > 2) {
            match close(fd) {
                Ok(()) | Err(nix::errno::Errno::EBADF) => {}
                Err(error) => return Err(error.into()),
            }
        }
        prctl::set_no_new_privs()?;
        prctl::set_dumpable(false)?;
        for (resource, limit) in [
            (Resource::RLIMIT_AS, 16 * 1024 * 1024 * 1024),
            (Resource::RLIMIT_CPU, 300),
            (Resource::RLIMIT_NOFILE, 256),
            (Resource::RLIMIT_CORE, 0),
            // Roc ftruncates a sparse memfd to 2 TiB before reducing its virtual
            // mapping. Real output is bounded independently by mandatory tmpfs
            // quotas above, and physical memory by the cgroup, not this limit.
            (Resource::RLIMIT_FSIZE, 2 * 1024 * 1024 * 1024 * 1024),
        ] {
            setrlimit(resource, limit, limit)?;
        }

        let read = AccessFs::ReadFile | AccessFs::ReadDir;
        let write = read
            | AccessFs::WriteFile
            | AccessFs::Truncate
            | AccessFs::RemoveFile
            | AccessFs::RemoveDir
            | AccessFs::MakeDir
            | AccessFs::MakeReg
            | AccessFs::Refer;
        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V3))?
            .create()?;
        for path in [stage.clone(), generated] {
            ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(path)?, write))?;
        }
        for path in [
            root.join("tools"),
            root.join("vendor"),
            root.join("../.toolchains"),
            PathBuf::from("/usr/lib"),
        ] {
            ruleset =
                ruleset.add_rule(PathBeneath::new(PathFd::new(path.canonicalize()?)?, read))?;
        }
        for path in [
            root.join("sdk/main.roc"),
            PathBuf::from("/proc/cpuinfo"),
            PathBuf::from("/proc/meminfo"),
        ] {
            ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(path)?, AccessFs::ReadFile))?;
        }
        ruleset = ruleset.add_rule(PathBeneath::new(
            PathFd::new(&roc)?,
            AccessFs::ReadFile | AccessFs::Execute,
        ))?;
        ruleset = ruleset.add_rule(PathBeneath::new(
            PathFd::new("/dev/null")?,
            AccessFs::ReadFile | AccessFs::WriteFile,
        ))?;
        let loader = if cfg!(target_arch = "aarch64") {
            "/lib/ld-linux-aarch64.so.1"
        } else {
            "/lib64/ld-linux-x86-64.so.2"
        };
        if let Ok(loader) = PathBuf::from(loader).canonicalize() {
            ruleset = ruleset.add_rule(PathBeneath::new(
                PathFd::new(loader)?,
                AccessFs::ReadFile | AccessFs::Execute,
            ))?;
        }
        let status = ruleset.restrict_self()?;
        ensure!(
            status.ruleset == RulesetStatus::FullyEnforced && status.no_new_privs,
            "compiler filesystem isolation not fully enforced"
        );

        // The reviewed compiler is trusted native code, unlike the app worker.
        // It needs compiler threads, but no sockets, processes, namespaces or tracing.
        let mut denied = BTreeMap::new();
        for syscall in [
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_execveat,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
        ] {
            denied.insert(syscall, vec![]);
        }
        #[cfg(target_arch = "x86_64")]
        for syscall in [libc::SYS_fork, libc::SYS_vfork] {
            denied.insert(syscall, vec![]);
        }
        // Reject clone unless all thread-sharing flags are set, and reject any
        // namespace flag even on a thread. clone3 cannot be inspected by BPF.
        let mut clone_rules = Vec::new();
        for flag in [libc::CLONE_THREAD, libc::CLONE_VM, libc::CLONE_SIGHAND] {
            clone_rules.push(SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(flag as u64),
                0,
            )?])?);
        }
        for flag in [
            libc::CLONE_NEWNS,
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWNET,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWCGROUP,
        ] {
            clone_rules.push(SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(flag as u64),
                flag as u64,
            )?])?);
        }
        denied.insert(libc::SYS_clone, clone_rules);
        let filter: BpfProgram = SeccompFilter::new(
            denied,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            std::env::consts::ARCH.try_into()?,
        )?
        .try_into()?;
        seccompiler::apply_filter(&filter)?;
        let clone3: BpfProgram = SeccompFilter::new(
            BTreeMap::from([(libc::SYS_clone3, vec![])]),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::ENOSYS as u32),
            std::env::consts::ARCH.try_into()?,
        )?
        .try_into()?;
        seccompiler::apply_filter(&clone3)?;
        let error = Command::new(roc)
            .args(args)
            .current_dir(root)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("HOME", stage.join("home"))
            .env("TMPDIR", stage.join("tmp"))
            .env("ROC_CACHE_DIR", stage.join("cache"))
            .env("XDG_CACHE_HOME", stage.join("cache"))
            .exec();
        Err(error).context("execute confined compiler")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::Path;

        #[test]
        fn real_compiler_outputs_require_bounded_tmpfs() -> Result<()> {
            let mounts = "1 0 0:1 / / rw - overlay overlay rw\n2 1 0:2 / /build rw - tmpfs tmpfs rw,size=1048576k\n";
            bounded_tmpfs(mounts, Path::new("/build/app"), 1024 * 1024 * 1024)?;
            for invalid in [
                mounts.replace("tmpfs", "ext4"),
                mounts.replace("1048576k", "1048577k"),
                mounts.replace("size=1048576k", "unbounded"),
                format!("{mounts}3 2 0:3 / /build/app/out rw - overlay overlay rw\n"),
            ] {
                assert!(
                    bounded_tmpfs(&invalid, Path::new("/build/app"), 1024 * 1024 * 1024).is_err()
                );
            }
            assert!(tmpfs_size("18446744073709551615m").is_err());
            Ok(())
        }
    }
}
