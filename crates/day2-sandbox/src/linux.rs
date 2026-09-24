//! Enforce confinement in a fresh, single-threaded process before executing Roc.

use anyhow::{Context, Result, bail, ensure};
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};
use nix::libc;
use nix::sys::{
    prctl,
    resource::{Resource, setrlimit},
    signal::Signal,
    stat::{SFlag, fstat, makedev},
};
use nix::unistd::{close, getpid, getppid};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
};

use crate::{ADDRESS_SPACE_BYTES, CPU_SECONDS, OPEN_FILES};

fn runtime_files() -> Result<BTreeSet<PathBuf>> {
    let (triplet, loader) = match std::env::consts::ARCH {
        "x86_64" => ("x86_64-linux-gnu", "ld-linux-x86-64.so.2"),
        "aarch64" => ("aarch64-linux-gnu", "ld-linux-aarch64.so.1"),
        _ => bail!("unsupported Linux worker architecture"),
    };
    let mut paths = BTreeSet::new();
    let libraries = [
        loader,
        "libc.so.6",
        "libgcc_s.so.1",
        "libm.so.6",
        "libpthread.so.0",
        "libdl.so.2",
        "librt.so.1",
    ];
    for directory in [
        format!("/usr/lib/{triplet}"),
        format!("/lib/{triplet}"),
        "/lib64".into(),
        "/lib".into(),
    ] {
        for library in libraries {
            let path = Path::new(&directory).join(library);
            match path.canonicalize() {
                Ok(path) => {
                    ensure!(
                        fs::metadata(&path)?.is_file(),
                        "runtime dependency is not a file"
                    );
                    ensure!(
                        path.starts_with("/usr/lib")
                            || path.starts_with("/lib")
                            || path.starts_with("/lib64"),
                        "runtime dependency leaves approved library roots"
                    );
                    paths.insert(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("resolve runtime dependency"),
            }
        }
    }
    ensure!(
        paths
            .iter()
            .any(|p| p.file_name().is_some_and(|n| n == loader)),
        "approved glibc loader missing"
    );
    Ok(paths)
}

fn close_inherited_descriptors() -> Result<()> {
    // Collect first so the directory iterator is closed before any descriptor reuse.
    let descriptors = fs::read_dir("/proc/self/fd")?
        .map(|entry| -> Result<i32> {
            Ok(entry?
                .file_name()
                .to_str()
                .context("invalid descriptor name")?
                .parse()?)
        })
        .collect::<Result<Vec<_>>>()?;
    for fd in descriptors.into_iter().filter(|fd| *fd > 2) {
        match close(fd) {
            Ok(()) | Err(nix::errno::Errno::EBADF) => {}
            Err(error) => return Err(error).context("close inherited descriptor"),
        }
    }
    Ok(())
}

fn validate_standard_descriptors() -> Result<()> {
    for descriptor in [fstat(std::io::stdin())?, fstat(std::io::stdout())?] {
        ensure!(
            SFlag::from_bits_truncate(descriptor.st_mode) & SFlag::S_IFMT == SFlag::S_IFIFO,
            "worker protocol requires pipe descriptors"
        );
    }
    let error = fstat(std::io::stderr())?;
    let mode = SFlag::from_bits_truncate(error.st_mode) & SFlag::S_IFMT;
    ensure!(
        mode == SFlag::S_IFIFO || (mode == SFlag::S_IFCHR && error.st_rdev == makedev(1, 3)),
        "worker stderr must be a pipe or /dev/null"
    );
    Ok(())
}

fn exact_arg(index: u8, value: u64) -> Result<SeccompRule> {
    Ok(SeccompRule::new(vec![SeccompCondition::new(
        index,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::Eq,
        value,
    )?])?)
}

fn syscall_filter() -> Result<BpfProgram> {
    let mut rules = BTreeMap::new();
    for syscall in [
        libc::SYS_read,
        libc::SYS_pread64,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_readlinkat,
        libc::SYS_ppoll,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_brk,
        libc::SYS_madvise,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_futex,
        libc::SYS_rseq,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getppid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_clock_gettime,
        libc::SYS_getrandom,
        libc::SYS_sched_getaffinity,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_execve,
    ] {
        rules.insert(syscall, vec![]);
    }
    #[cfg(target_arch = "x86_64")]
    for syscall in [
        libc::SYS_arch_prctl,
        libc::SYS_access,
        libc::SYS_readlink,
        libc::SYS_getrlimit,
        libc::SYS_poll,
    ] {
        rules.insert(syscall, vec![]);
    }
    for syscall in [libc::SYS_write, libc::SYS_writev] {
        rules.insert(syscall, vec![exact_arg(0, 1)?, exact_arg(0, 2)?]);
    }
    // Runtime startup may inspect limits but cannot raise the hard limits.
    rules.insert(libc::SYS_prlimit64, vec![exact_arg(2, 0)?]);
    rules.insert(
        libc::SYS_prctl,
        vec![
            exact_arg(0, libc::PR_GET_NO_NEW_PRIVS as u64)?,
            exact_arg(0, libc::PR_GET_SECCOMP as u64)?,
        ],
    );
    rules.insert(
        libc::SYS_fcntl,
        vec![
            exact_arg(1, libc::F_GETFD as u64)?,
            exact_arg(1, libc::F_GETFL as u64)?,
        ],
    );
    rules.insert(
        libc::SYS_openat,
        vec![SeccompRule::new(vec![SeccompCondition::new(
            2,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(
                (libc::O_ACCMODE | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u64,
            ),
            0,
        )?])?],
    );
    Ok(SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into()?,
    )?
    .try_into()?)
}

pub fn launch(worker: &Path, parent: u32) -> Result<()> {
    ensure!(
        parent >= 1 && parent <= i32::MAX as u32,
        "invalid supervisor identity"
    );
    ensure!(
        getppid().as_raw() == parent as i32,
        "supervisor exited before sandbox setup"
    );
    prctl::set_pdeathsig(Some(Signal::SIGKILL))?;
    ensure!(
        getppid().as_raw() == parent as i32,
        "supervisor exited during sandbox setup"
    );
    let worker = worker.canonicalize().context("resolve worker")?;
    let metadata = fs::metadata(&worker)?;
    ensure!(metadata.is_file(), "worker must be a regular executable");
    let mode = metadata.permissions().mode();
    ensure!(
        mode & 0o111 != 0 && mode & 0o6022 == 0,
        "unsafe worker executable permissions"
    );
    let dependencies = runtime_files()?;
    let filter = syscall_filter()?;
    validate_standard_descriptors()?;
    close_inherited_descriptors()?;
    std::env::set_current_dir("/")?;
    prctl::set_no_new_privs()?;
    prctl::set_dumpable(false)?;
    for (resource, maximum) in [
        (Resource::RLIMIT_AS, ADDRESS_SPACE_BYTES),
        (Resource::RLIMIT_CPU, CPU_SECONDS),
        (Resource::RLIMIT_NOFILE, OPEN_FILES),
        (Resource::RLIMIT_NPROC, 0),
        (Resource::RLIMIT_CORE, 0),
        (Resource::RLIMIT_FSIZE, 0),
    ] {
        setrlimit(resource, maximum, maximum)?;
    }
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V3))?
        .create()?;
    ruleset = ruleset.add_rule(PathBeneath::new(
        PathFd::new(&worker)?,
        AccessFs::ReadFile | AccessFs::Execute,
    ))?;
    for dependency in dependencies {
        let access = if dependency
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("ld-linux-"))
        {
            AccessFs::ReadFile | AccessFs::Execute
        } else {
            AccessFs::ReadFile.into()
        };
        ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(dependency)?, access))?;
    }
    let status = ruleset.restrict_self()?;
    ensure!(
        status.ruleset == RulesetStatus::FullyEnforced && status.no_new_privs,
        "Linux filesystem isolation was not fully enforced"
    );
    seccompiler::apply_filter(&filter).context("enforce worker syscall filter")?;
    // Exec is needed for this handoff. Landlock limits later re-exec to this worker
    // and the approved loader; no syscall permits creating another process/thread.
    let error = Command::new(&worker)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .exec();
    Err(error).with_context(|| format!("execute isolated worker (pid {})", getpid()))
}
