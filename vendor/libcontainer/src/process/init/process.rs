use std::collections::HashMap;
#[cfg(test)]
use std::io::Read;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::{fs, mem};

use caps::{CapSet, CapsHashSet};
use nix::mount::MsFlags;
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use nix::unistd::{self, Gid, Uid, close, dup2, setsid};
#[cfg(test)]
use oci_spec::runtime::User;
use oci_spec::runtime::{
    IOPriorityClass, LinuxIOPriority, LinuxNamespaceType, LinuxNetDevice, LinuxPersonalityDomain,
    LinuxSchedulerFlag, LinuxSchedulerPolicy, Process, Scheduler, Spec,
};
use pathrs::flags::OpenFlags;
#[cfg(test)]
use pathrs::procfs::ProcfsHandle;
use pathrs::procfs::{ProcfsBase, ProcfsHandleBuilder};

use super::Result;
use super::context::InitContext;
use super::error::InitProcessError;
use crate::config::PersonalityDomain;
use crate::error::MissingSpecError;
use crate::namespaces::Namespaces;
use crate::network::address::AddressClient;
use crate::network::link::LinkClient;
use crate::network::network_device::{resolve_device_name, setup_addresses_in_network_namespace};
use crate::network::wrapper::create_network_client;
use crate::process::args::{ContainerArgs, ContainerType};
use crate::process::{channel, memory_policy};
use crate::rootfs::RootFS;
#[cfg(test)]
use crate::rootfs::device::open_device_fd;
use crate::rootfs::device::verify_dev_null;
#[cfg(feature = "libseccomp")]
use crate::seccomp;
use crate::syscall::{Syscall, SyscallError};
#[cfg(test)]
use crate::user_ns::UserNamespaceConfig;
#[cfg(test)]
use crate::utils;
use crate::{apparmor, capabilities, hooks, tty};

const CAPABILITY_ERROR_ANNOTATION: &str = "cn.org.linyaps.internal.compatibility.capability-error";
const NS_LAST_PID_ANNOTATION: &str = "cn.org.linyaps.runtime.ns_last_pid";

#[repr(C)]
struct SchedulerAttributes {
    size: u32,
    sched_policy: u32,
    sched_flags: u64,
    sched_nice: i32,
    sched_priority: u32,
    sched_runtime: u64,
    sched_deadline: u64,
    sched_period: u64,
    sched_util_min: u32,
    sched_util_max: u32,
}

// Some variables are unused in the case where libseccomp feature is not enabled.
#[allow(unused_variables)]
pub fn container_init_process(
    args: &ContainerArgs,
    main_sender: &mut channel::MainSender,
    init_receiver: &mut channel::InitReceiver,
) -> Result<()> {
    if matches!(args.container_type, ContainerType::InitContainer) {
        wait_for_trace_signal()?;
    }
    let ctx = InitContext::try_from(args)?;

    ctx.syscall.close_range(args.preserve_fds).map_err(|err| {
        tracing::error!(?err, "failed to cleanup extra fds");
        InitProcessError::SyscallOther(err)
    })?;

    set_io_priority(ctx.syscall.as_ref(), ctx.process.io_priority())?;

    setup_scheduler(ctx.process.scheduler())?;

    memory_policy::setup_memory_policy(ctx.linux.memory_policy(), ctx.syscall.as_ref())?;

    // If no console socket, set up stdio now
    if args.console_socket.is_none() {
        if let Some(stdin) = args.stdin {
            dup2(stdin, 0).map_err(InitProcessError::NixOther)?;
            close(stdin).map_err(InitProcessError::NixOther)?;
        }
        if let Some(stdout) = args.stdout {
            dup2(stdout, 1).map_err(InitProcessError::NixOther)?;
            close(stdout).map_err(InitProcessError::NixOther)?;
        }
        if let Some(stderr) = args.stderr {
            dup2(stderr, 2).map_err(InitProcessError::NixOther)?;
            close(stderr).map_err(InitProcessError::NixOther)?;
        }
    }

    apply_rest_namespaces(&ctx.ns, ctx.spec, ctx.syscall.as_ref())?;

    if matches!(args.container_type, ContainerType::InitContainer) {
        let rootfs_path = if args.canonicalize_rootfs {
            fs::canonicalize(ctx.rootfs).map_err(|error| {
                InitProcessError::RootfsCanonicalize(format!(
                    "filesystem error: cannot make canonical path: {} [{}]",
                    io_error_message(&error),
                    ctx.rootfs.display()
                ))
            })?
        } else {
            fs::metadata(ctx.rootfs)
                .map_err(|error| InitProcessError::RootfsAccess(io_error_message(&error)))?;
            ctx.rootfs.to_path_buf()
        };
        let has_mount_namespace = ctx.ns.get(LinuxNamespaceType::Mount)?.is_some();
        let rootfs = RootFS::new();
        let mounts_configured = rootfs
            .prepare_rootfs(
                ctx.spec,
                &rootfs_path,
                ctx.ns.get(LinuxNamespaceType::Cgroup)?.is_some(),
                has_mount_namespace,
            )
            .map_err(|err| {
                tracing::error!(?err, "failed to prepare rootfs");
                InitProcessError::RootFS(err)
            })?;

        if let Some(hooks) = ctx.hooks {
            // send a request to the main process to run prestart and create_runtime hooks.
            // prestart and create_runtime hook needs to be called after the namespace setup, but
            // before pivot_root is called. This runs in the runtime(not container) namespaces.
            main_sender.hook_request()?;
            init_receiver.wait_for_hook_request_done()?;

            // create_container hook needs to be called after the namespace setup, but
            // before pivot_root is called. This runs in the container namespaces.
            hooks::run_hooks(
                hooks.create_container().as_ref(),
                ctx.container.map(|c| &c.state),
                None,
                None,
                None,
            )
            .map_err(|err| {
                tracing::error!(?err, "failed to run create container hooks");
                InitProcessError::Hooks(err)
            })?;
        }

        // Entering into the rootfs jail. If mount namespace is specified, then
        // we use pivot_root, but if we are on the host mount namespace, we will
        // use simple chroot. Scary things will happen if you try to pivot_root
        // in the host mount namespace...
        do_pivot_root(ctx.syscall.as_ref(), &ctx.ns, args.no_pivot, &rootfs_path)?;

        // As we have changed the root mount, from here on
        // logs are no longer visible in journalctl
        // so make sure that you bubble up any errors
        // and do not call unwrap() as any panics would not be correctly logged
        if mounts_configured && has_mount_namespace {
            rootfs
                .adjust_root_mount_propagation(ctx.linux)
                .map_err(|err| {
                    tracing::error!(?err, "failed to adjust root mount propagation");
                    InitProcessError::RootFS(err)
                })?;
        }

        reopen_dev_null().map_err(|err| {
            tracing::error!(?err, "failed to reopen /dev/null");
            err
        })?;

        if let Some(kernel_params) = ctx.linux.sysctl() {
            sysctl(kernel_params)?;
        }
    }

    setsid().map_err(|err| {
        tracing::error!(?err, "failed to setsid to create a session");
        InitProcessError::NixOther(err)
    })?;

    // Setup console AFTER reopen_dev_null (for init) or at start (for exec).
    // This follows runc's order:
    //   - standard_init_linux.go: setupConsole() is called after prepareRootfs()
    //     (which includes pivotRoot and reOpenDevNull)
    //   - setns_init_linux.go: setupConsole() is called early
    // mount=true for init (mount /dev/console), false for exec (already mounted)
    // See: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/standard_init_linux.go
    // See: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/setns_init_linux.go
    if let Some(csocketfd) = args.console_socket {
        let mount_console = matches!(args.container_type, ContainerType::InitContainer);
        tty::setup_console(ctx.syscall.as_ref(), csocketfd, mount_console).map_err(|err| {
            tracing::error!(?err, "failed to set up tty");
            InitProcessError::Tty(err)
        })?;
    }

    if let Some(personality) = ctx.linux.personality() {
        if let Some(flags) = personality.flags() {
            if !flags.is_empty() {
                tracing::error!("personality flag has not supported at this time");
                return Err(InitProcessError::UnsupportedPersonalityFlag);
            }
        }

        let domain = match personality.domain() {
            // https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#personality
            LinuxPersonalityDomain::PerLinux => PersonalityDomain::Linux,
            LinuxPersonalityDomain::PerLinux32 => PersonalityDomain::Linux32,
        };

        ctx.syscall.personality(domain).map_err(|err| {
            tracing::error!(?err, "failed to set linux personality ");
            InitProcessError::SyscallOther(err)
        })?;
    }

    if let Some(profile) = ctx.process.apparmor_profile() {
        apparmor::apply_profile(profile).map_err(|err| {
            tracing::error!(?err, "failed to apply apparmor profile");
            InitProcessError::AppArmor(err)
        })?;
    }

    if let Some(umask) = ctx.process.user().umask() {
        match Mode::from_bits(umask) {
            Some(mode) => {
                nix::sys::stat::umask(mode);
            }
            None => {
                return Err(InitProcessError::InvalidUmask(umask));
            }
        }
    }

    if matches!(args.container_type, ContainerType::InitContainer) {
        process_linyaps_extensions(ctx.spec)?;
    }

    // Setup some operations in the network namespace.
    // This is done here before dropping capabilities because we need to be able to add IP addresses to the device
    // and set up the device.
    if let Some(network_devices) = ctx.linux.net_devices() {
        configure_container_network_devices(network_devices, main_sender, init_receiver).map_err(
            |err| {
                tracing::error!(?err, "failed to setup net_device");
                err
            },
        )?;
    }

    // Without no new privileges, seccomp is a privileged operation. We have to
    // do this before dropping capabilities. Otherwise, we should do it later,
    // as close to exec as possible.
    #[cfg(feature = "libseccomp")]
    if let Some(seccomp) = ctx.linux.seccomp() {
        if ctx.process.no_new_privileges().is_none() {
            let notify_fd = seccomp::initialize_seccomp(seccomp).map_err(|err| {
                tracing::error!(?err, "failed to initialize seccomp");
                err
            })?;
            sync_seccomp(notify_fd, main_sender, init_receiver).map_err(|err| {
                tracing::error!(?err, "failed to sync seccomp");
                err
            })?;
        }
    }
    #[cfg(not(feature = "libseccomp"))]
    if ctx.linux.seccomp().is_some() && ctx.process.no_new_privileges().is_none() {
        tracing::warn!("seccomp not available, unable to enforce no_new_privileges!")
    }

    if let Some(error) = ctx
        .spec
        .annotations()
        .as_ref()
        .and_then(|annotations| annotations.get(CAPABILITY_ERROR_ANNOTATION))
    {
        return Err(InitProcessError::UnknownCapability(error.clone()));
    }
    set_process_security(ctx.process, ctx.syscall.as_ref())?;

    // Initialize seccomp profile right before we are ready to execute the
    // payload so as few syscalls will happen between here and payload exec. The
    // notify socket will still need network related syscalls.
    #[cfg(feature = "libseccomp")]
    if let Some(seccomp) = ctx.linux.seccomp() {
        if ctx.process.no_new_privileges().is_some() {
            let notify_fd = seccomp::initialize_seccomp(seccomp).map_err(|err| {
                tracing::error!(?err, "failed to initialize seccomp");
                err
            })?;
            sync_seccomp(notify_fd, main_sender, init_receiver).map_err(|err| {
                tracing::error!(?err, "failed to sync seccomp");
                err
            })?;
        }
    }
    #[cfg(not(feature = "libseccomp"))]
    if ctx.linux.seccomp().is_some() && ctx.process.no_new_privileges().is_some() {
        tracing::warn!("seccomp not available, unable to set seccomp privileges!")
    }

    args.executor.validate(ctx.spec)?;

    // Notify main process that the init process is ready to execute the
    // payload.  Note, because we are already inside the pid namespace, the pid
    // outside the pid namespace should be recorded by the intermediate process
    // already.
    main_sender.init_ready().map_err(|err| {
        tracing::error!(
            ?err,
            "failed to notify main process that init process is ready"
        );
        InitProcessError::Channel(err)
    })?;
    main_sender.close().map_err(|err| {
        tracing::error!(?err, "failed to close down main sender in init process");
        InitProcessError::Channel(err)
    })?;

    // listing on the notify socket for container start command
    ctx.notify_listener
        .wait_for_container_start()
        .map_err(|err| {
            tracing::error!(?err, "failed to wait for container start");
            err
        })?;
    ctx.notify_listener.close().map_err(|err| {
        tracing::error!(?err, "failed to close notify socket");
        err
    })?;

    // start_container hook needs to be called after the namespace setup, but
    // before pivot_root is called. This runs in the container namespaces.
    if matches!(args.container_type, ContainerType::InitContainer) {
        if let Some(hooks) = ctx.hooks {
            hooks::run_hooks(
                hooks.start_container().as_ref(),
                ctx.container.map(|c| &c.state),
                None,
                None,
                None,
            )
            .map_err(|err| {
                tracing::error!(?err, "failed to run start container hooks");
                InitProcessError::StartContainerHooks(err)
            })?;
        }
    }

    reset_process_signals()?;

    unistd::chdir(ctx.process.cwd()).map_err(|err| {
        let cwd = ctx.process.cwd();
        tracing::error!(?err, ?cwd, "failed to chdir to cwd");
        InitProcessError::Chdir(io_error_message(&std::io::Error::from_raw_os_error(
            err as i32,
        )))
    })?;

    verify_cwd().map_err(|err| {
        tracing::error!(?err, "failed to verify cwd");
        err
    })?;

    if ctx.process.args().is_none() {
        tracing::error!("on non-Windows, at least one process arg entry is required");
        Err(MissingSpecError::Args)?;
    }

    args.executor.exec(ctx.spec).map_err(|err| {
        tracing::error!(?err, "failed to execute payload");
        err
    })?;

    // Once the executor is executed without error, it should not return. For
    // example, the default executor is expected to call `exec` and replace the
    // current process.
    unreachable!("the executor should not return if it is successful.");
}

fn process_linyaps_extensions(spec: &Spec) -> Result<()> {
    let Some(value) = spec
        .annotations()
        .as_ref()
        .and_then(|annotations| annotations.get(NS_LAST_PID_ANNOTATION))
    else {
        return Ok(());
    };
    let parsed = value.parse::<i64>().map_err(|error| {
        InitProcessError::LinyapsExtension(format!("parse ns_last_pid {value} failed: {error}"))
    })?;
    if !(0..=i32::MAX as i64).contains(&parsed) {
        return Err(InitProcessError::LinyapsExtension(format!(
            "ns_last_pid value out of range: {value} (must be between 0 and {})",
            i32::MAX
        )));
    }
    set_ns_last_pid_at(Path::new("/proc/sys/kernel/ns_last_pid"), value)
}

fn set_ns_last_pid_at(path: &Path, value: &str) -> Result<()> {
    if !path.try_exists().map_err(|error| {
        InitProcessError::LinyapsExtension(format!("failed to inspect {}: {error}", path.display()))
    })? {
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| {
            InitProcessError::LinyapsExtension(format!(
                "failed to open {}: {error}",
                path.display()
            ))
        })?;
    file.write_all(value.as_bytes()).map_err(|error| {
        InitProcessError::LinyapsExtension(format!(
            "failed to write to {}: {error}",
            path.display()
        ))
    })?;
    Ok(())
}

fn io_error_message(error: &std::io::Error) -> String {
    let Some(errno) = error.raw_os_error() else {
        return error.to_string();
    };
    let pointer = unsafe { libc::strerror(errno) };
    if pointer.is_null() {
        return error.to_string();
    }
    unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

extern "C" fn trace_signal_handler(_signal: libc::c_int) {
    static MESSAGE: &[u8] = b"[DEBUG] Signal USR1 received.\n";
    unsafe {
        libc::write(libc::STDERR_FILENO, MESSAGE.as_ptr().cast(), MESSAGE.len());
    }
}

fn wait_for_trace_signal() -> Result<()> {
    if std::env::var_os("LINYAPS_BOX_CONTAINER_PROCESS_TRACE_ME").is_none() {
        return Ok(());
    }
    let handler = trace_signal_handler as *const () as libc::sighandler_t;
    let previous = unsafe { libc::signal(libc::SIGUSR1, handler) };
    if previous == libc::SIG_ERR {
        let error = std::io::Error::last_os_error();
        return Err(InitProcessError::TraceSignal(format!(
            "signal: {}",
            io_error_message(&error)
        )));
    }
    unsafe {
        libc::pause();
    }
    let previous = unsafe { libc::signal(libc::SIGUSR1, libc::SIG_DFL) };
    if previous == libc::SIG_ERR {
        let error = std::io::Error::last_os_error();
        return Err(InitProcessError::TraceSignal(format!(
            "signal: {}",
            io_error_message(&error)
        )));
    }
    Ok(())
}

fn set_process_security(process: &Process, syscall: &dyn Syscall) -> Result<()> {
    let Some(capability_sets) = process.capabilities() else {
        return Ok(());
    };

    if let Some(bounding) = capability_sets.bounding() {
        syscall
            .set_capability(CapSet::Bounding, &capabilities::to_set(bounding))
            .map_err(InitProcessError::SyscallOther)?;
    }

    syscall
        .set_keep_capabilities(true)
        .map_err(InitProcessError::SyscallOther)?;
    syscall
        .set_gid(Gid::from_raw(process.user().gid()))
        .map_err(InitProcessError::SyscallOther)?;

    if let Some(additional_gids) = process.user().additional_gids() {
        let additional_gids = additional_gids
            .iter()
            .copied()
            .map(Gid::from_raw)
            .collect::<Vec<_>>();
        syscall
            .set_groups(&additional_gids)
            .map_err(InitProcessError::SyscallOther)?;
    }

    syscall
        .set_uid(Uid::from_raw(process.user().uid()))
        .map_err(InitProcessError::SyscallOther)?;

    let empty = CapsHashSet::new();
    let effective = capability_sets
        .effective()
        .as_ref()
        .map(capabilities::to_set)
        .unwrap_or_default();
    let permitted = capability_sets
        .permitted()
        .as_ref()
        .map(capabilities::to_set)
        .unwrap_or_default();
    let inheritable = capability_sets
        .inheritable()
        .as_ref()
        .map(capabilities::to_set)
        .unwrap_or_default();
    syscall
        .set_process_capabilities(&effective, &permitted, &inheritable)
        .map_err(InitProcessError::SyscallOther)?;

    let ambient = capability_sets
        .ambient()
        .as_ref()
        .map(capabilities::to_set)
        .unwrap_or(empty);
    syscall
        .set_capability(CapSet::Ambient, &ambient)
        .map_err(InitProcessError::SyscallOther)?;

    if process.no_new_privileges().is_some() {
        syscall
            .set_no_new_privileges()
            .map_err(InitProcessError::SyscallOther)?;
    }

    Ok(())
}

fn reset_process_signals() -> Result<()> {
    let mut signals = unsafe { mem::zeroed::<libc::sigset_t>() };
    if unsafe { libc::sigfillset(&mut signals) } == -1 {
        return Err(InitProcessError::NixOther(nix::errno::Errno::last()));
    }
    if unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) } == -1 {
        return Err(InitProcessError::NixOther(nix::errno::Errno::last()));
    }

    let mut action = unsafe { mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = libc::SIG_DFL;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } == -1 {
        return Err(InitProcessError::NixOther(nix::errno::Errno::last()));
    }
    for signal in 1..=libc::SIGRTMAX() {
        if signal == libc::SIGKILL || signal == libc::SIGSTOP {
            continue;
        }
        match unsafe { libc::sigismember(&signals, signal) } {
            0 => continue,
            1 => {}
            _ => return Err(InitProcessError::NixOther(nix::errno::Errno::last())),
        }
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == -1 {
            return Err(InitProcessError::NixOther(nix::errno::Errno::last()));
        }
    }
    Ok(())
}

fn sysctl(kernel_params: &HashMap<String, String>) -> Result<()> {
    let procfs = ProcfsHandleBuilder::new().unmasked().build()?;
    let sys = PathBuf::from("sys");
    for (kernel_param, value) in kernel_params {
        tracing::debug!(
            "apply value {} to kernel parameter {}.",
            value,
            kernel_param
        );

        let subpath = sys.join(kernel_param.replace('.', "/"));
        let mut f = procfs.open(
            ProcfsBase::ProcRoot,
            subpath,
            OpenFlags::O_WRONLY | OpenFlags::O_CLOEXEC,
        )?;
        f.write_all(value.as_bytes()).map_err(|err| {
            tracing::error!("failed to set sysctl {kernel_param}={value}: {err}");
            InitProcessError::Sysctl(err)
        })?;
    }

    Ok(())
}

// make a read only path
// The first time we bind mount, other flags are ignored,
// so we need to mount it once and then remount it with the necessary flags specified.
// https://man7.org/linux/man-pages/man2/mount.2.html
#[cfg(test)]
fn readonly_path(path: &Path, syscall: &dyn Syscall) -> Result<()> {
    if let Err(err) = syscall.mount(
        Some(path),
        path,
        None,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None,
    ) {
        if let SyscallError::Nix(errno) = err {
            // ignore error if path is not exist.
            if matches!(errno, nix::errno::Errno::ENOENT) {
                return Ok(());
            }
        }

        tracing::error!(?path, ?err, "failed to mount path as readonly");
        return Err(InitProcessError::MountPathReadonly(err));
    }

    syscall
        .mount(
            Some(path),
            path,
            None,
            MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV
                | MsFlags::MS_NOEXEC
                | MsFlags::MS_BIND
                | MsFlags::MS_REMOUNT
                | MsFlags::MS_RDONLY,
            None,
        )
        .map_err(|err| {
            tracing::error!(?path, ?err, "failed to remount path as readonly");
            InitProcessError::MountPathReadonly(err)
        })?;

    tracing::debug!("readonly path {:?} mounted", path);
    Ok(())
}

// For files, bind mounts /dev/null over the top of the specified path.
// For directories, mounts read-only tmpfs over the top of the specified path.
#[cfg(test)]
fn masked_paths(
    paths: &Vec<String>,
    mount_label: &Option<String>,
    syscall: &dyn Syscall,
) -> Result<()> {
    let (dev_null_fd, dev_null_stat) =
        open_device_fd(Path::new("/dev/null")).map_err(InitProcessError::NixOther)?;
    verify_dev_null(&dev_null_stat).map_err(|err| {
        tracing::error!(?err, "invalid /dev/null device");
        InitProcessError::Device(err)
    })?;

    for path_str in paths {
        let path = Path::new(path_str);
        if !path.exists() {
            // Skip if the path does not exist.
            continue;
        }

        if path.is_dir() {
            // Destination is a directory, mount a read-only tmpfs over the top of it.
            let label = match mount_label {
                Some(l) => format!("context=\"{l}\""),
                None => "".to_string(),
            };
            syscall
                .mount(
                    Some(Path::new("tmpfs")),
                    path,
                    Some("tmpfs"),
                    MsFlags::MS_RDONLY,
                    Some(label.as_str()),
                )
                .map_err(|err| {
                    tracing::error!(?path, ?err, "failed to mount path as masked using tempfs");
                    InitProcessError::MountPathMasked(err)
                })?;
        } else {
            // Destination is a file, bind mount /dev/null over the top of it.
            syscall.mount_from_fd(&dev_null_fd, path).map_err(|err| {
                tracing::error!(
                    ?path,
                    ?err,
                    "failed to mount path as masked using /dev/null"
                );
                InitProcessError::MountPathMasked(err)
            })?;
        }
    }

    Ok(())
}

// Enter into rest of namespace. Note, we already entered into user and pid
// namespace. We also have to enter into mount namespace last since
// namespace may be bind to /proc path. The /proc path will need to be
// accessed before pivot_root.
fn apply_rest_namespaces(
    namespaces: &Namespaces,
    spec: &Spec,
    syscall: &dyn Syscall,
) -> Result<()> {
    namespaces
        .apply_namespaces(|ns_type| -> bool {
            ns_type != CloneFlags::CLONE_NEWUSER
                && ns_type != CloneFlags::CLONE_NEWPID
                && ns_type != crate::namespaces::CLONE_NEWTIME_FLAG
        })
        .map_err(|err| {
            tracing::error!(
                ?err,
                "failed to apply rest of the namespaces (exclude user and pid)"
            );
            InitProcessError::Namespaces(err)
        })?;

    // Only set the host name if entering into a new uts namespace
    if let Some(uts_namespace) = namespaces.get(LinuxNamespaceType::Uts)? {
        if uts_namespace.path().is_none() {
            if let Some(hostname) = spec.hostname() {
                syscall.set_hostname(hostname).map_err(|err| {
                    tracing::error!(?err, ?hostname, "failed to set hostname");
                    InitProcessError::SetHostname(err)
                })?;
            }

            if let Some(domainname) = spec.domainname() {
                syscall.set_domainname(domainname).map_err(|err| {
                    tracing::error!(?err, ?domainname, "failed to set domainname");
                    InitProcessError::SetDomainname(err)
                })?;
            }
        }
    }
    Ok(())
}

fn reopen_dev_null() -> Result<()> {
    // At this point we should be inside of the container and now
    // we can re-open /dev/null if it is in use to the /dev/null
    // in the container.
    let dev_null = fs::File::open("/dev/null").map_err(|err| {
        tracing::error!(?err, "failed to open /dev/null inside the container");
        InitProcessError::ReopenDevNull(err)
    })?;
    let dev_null_fstat_info = nix::sys::stat::fstat(dev_null.as_raw_fd()).map_err(|err| {
        tracing::error!(?err, "failed to fstat /dev/null inside the container");
        InitProcessError::NixOther(err)
    })?;
    verify_dev_null(&dev_null_fstat_info).map_err(|err| {
        tracing::error!(?err, "invalid /dev/null device inside the container");
        InitProcessError::Device(err)
    })?;

    // Check if stdin, stdout or stderr point to /dev/null
    for fd in 0..3 {
        let fstat_info = nix::sys::stat::fstat(fd).map_err(|err| {
            tracing::error!(?err, "failed to fstat stdio fd {}", fd);
            InitProcessError::NixOther(err)
        })?;

        if dev_null_fstat_info.st_rdev == fstat_info.st_rdev {
            // This FD points to /dev/null outside of the container.
            // Let's point to /dev/null inside of the container.
            nix::unistd::dup2(dev_null.as_raw_fd(), fd).map_err(|err| {
                tracing::error!(?err, "failed to dup2 fd {} to /dev/null", fd);
                InitProcessError::NixOther(err)
            })?;
        }
    }

    Ok(())
}

fn move_root(syscall: &dyn Syscall, rootfs: &Path) -> Result<()> {
    unistd::chdir(rootfs).map_err(InitProcessError::NixOther)?;
    syscall
        .mount(
            Some(rootfs),
            Path::new("/"),
            Some(""),
            MsFlags::MS_MOVE,
            None,
        )
        .map_err(|err| {
            tracing::error!(?err, ?rootfs, "failed to mount ms_move");
            InitProcessError::SyscallOther(err)
        })?;

    syscall.chroot(Path::new(".")).map_err(|err| {
        tracing::error!(?err, ?rootfs, "failed to chroot");
        InitProcessError::SyscallOther(err)
    })?;

    unistd::chdir("/").map_err(InitProcessError::NixOther)?;

    Ok(())
}

fn do_pivot_root(
    syscall: &dyn Syscall,
    namespaces: &Namespaces,
    no_pivot: bool,
    rootfs: impl AsRef<Path>,
) -> Result<()> {
    let rootfs_path = rootfs.as_ref();

    let handle_error = |err: SyscallError, msg: &str| -> InitProcessError {
        tracing::error!(?err, ?rootfs_path, msg);
        InitProcessError::SyscallOther(err)
    };

    match namespaces.get(LinuxNamespaceType::Mount)? {
        Some(_) if no_pivot => move_root(syscall, rootfs_path),
        Some(_) => match syscall.pivot_rootfs(rootfs.as_ref()) {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::debug!(?error, ?rootfs_path, "pivot_root failed, using MS_MOVE");
                move_root(syscall, rootfs_path)
            }
        },
        None => {
            unistd::chdir(rootfs_path).map_err(InitProcessError::NixOther)?;
            syscall
                .chroot(Path::new("."))
                .map_err(|err| handle_error(err, "failed to chroot"))?;
            unistd::chdir("/").map_err(InitProcessError::NixOther)
        }
    }
}

// Before 3.19 it was possible for an unprivileged user to enter an user namespace,
// become root and then call setgroups in order to drop membership in supplementary
// groups. This allowed access to files which blocked access based on being a member
// of these groups (see CVE-2014-8989)
//
// This leaves us with three scenarios:
//
// Unprivileged user starting a rootless container: The main process is running as an
// unprivileged user and therefore cannot write the mapping until "deny" has been written
// to /proc/{pid}/setgroups. Once written /proc/{pid}/setgroups cannot be reset and the
// setgroups system call will be disabled for all processes in this user namespace. This
// also means that we should detect if the user is unprivileged and additional gids have
// been specified and bail out early as this can never work. This is not handled here,
// but during the validation for rootless containers.
//
// Privileged user starting a rootless container: It is not necessary to write "deny" to
// /proc/setgroups in order to create the gid mapping and therefore we don't. This means
// that setgroups could be used to drop groups, but this is fine as the user is privileged
// and could do so anyway.
// We already have checked during validation if the specified supplemental groups fall into
// the range that are specified in the gid mapping and bail out early if they do not.
//
// Privileged user starting a normal container: Just add the supplementary groups.
//
#[cfg(test)]
fn set_supplementary_gids(
    user: &User,
    user_ns_config: &Option<UserNamespaceConfig>,
    syscall: &dyn Syscall,
) -> Result<()> {
    if let Some(additional_gids) = user.additional_gids() {
        if additional_gids.is_empty() {
            return Ok(());
        }

        let mut setgroups = String::new();
        ProcfsHandle::new()?
            .open(ProcfsBase::ProcSelf, "setgroups", OpenFlags::O_RDONLY)?
            .read_to_string(&mut setgroups)
            .map_err(|err| {
                tracing::error!(?err, "failed to read setgroups");
                InitProcessError::Io(err)
            })?;

        if setgroups.trim() == "deny" {
            tracing::error!("cannot set supplementary gids, setgroup is disabled");
            return Err(InitProcessError::SetGroupDisabled);
        }

        let gids: Vec<Gid> = additional_gids
            .iter()
            .map(|gid| Gid::from_raw(*gid))
            .collect();

        match user_ns_config {
            Some(r) if r.privileged => {
                syscall.set_groups(&gids).map_err(|err| {
                    tracing::error!(?err, ?gids, "failed to set privileged supplementary gids");
                    InitProcessError::SyscallOther(err)
                })?;
            }
            None => {
                syscall.set_groups(&gids).map_err(|err| {
                    tracing::error!(?err, ?gids, "failed to set unprivileged supplementary gids");
                    InitProcessError::SyscallOther(err)
                })?;
            }
            // this should have been detected during validation
            _ => unreachable!(
                "unprivileged users cannot set supplementary gids in containers with new user namespace"
            ),
        }
    }

    Ok(())
}

/// set_io_priority set io priority
fn set_io_priority(syscall: &dyn Syscall, io_priority_op: &Option<LinuxIOPriority>) -> Result<()> {
    if let Some(io_priority) = io_priority_op {
        let io_prio_class_mapping: HashMap<_, _> = [
            (IOPriorityClass::IoprioClassRt, 1i64),
            (IOPriorityClass::IoprioClassBe, 2i64),
            (IOPriorityClass::IoprioClassIdle, 3i64),
        ]
        .iter()
        .filter_map(|(class, num)| match serde_json::to_string(&class) {
            Ok(class_str) => Some((class_str, *num)),
            Err(err) => {
                tracing::error!(?err, "failed to parse io priority class");
                None
            }
        })
        .collect();

        let iop_class = serde_json::to_string(&io_priority.class())
            .map_err(|err| InitProcessError::IoPriorityClass(err.to_string()))?;

        match io_prio_class_mapping.get(&iop_class) {
            Some(value) => {
                syscall
                    .set_io_priority(*value, io_priority.priority())
                    .map_err(|err| {
                        tracing::error!(?err, ?io_priority, "failed to set io_priority");
                        InitProcessError::SyscallOther(err)
                    })?;
            }
            None => {
                return Err(InitProcessError::IoPriorityClass(iop_class));
            }
        }
    }
    Ok(())
}

/// Set the RT priority of a thread
fn setup_scheduler(sc_op: &Option<Scheduler>) -> Result<()> {
    if let Some(sc) = sc_op {
        let policy: u32 = match *sc.policy() {
            LinuxSchedulerPolicy::SchedOther => 0,
            LinuxSchedulerPolicy::SchedFifo => 1,
            LinuxSchedulerPolicy::SchedRr => 2,
            LinuxSchedulerPolicy::SchedBatch => 3,
            LinuxSchedulerPolicy::SchedIso => 4,
            LinuxSchedulerPolicy::SchedIdle => 5,
            LinuxSchedulerPolicy::SchedDeadline => 6,
        };
        let mut flags_value: u64 = 0;
        if let Some(flags) = sc.flags() {
            for flag in flags {
                match *flag {
                    LinuxSchedulerFlag::SchedResetOnFork => flags_value |= 0x01,
                    LinuxSchedulerFlag::SchedFlagReclaim => flags_value |= 0x02,
                    LinuxSchedulerFlag::SchedFlagDLOverrun => flags_value |= 0x04,
                    LinuxSchedulerFlag::SchedFlagKeepPolicy => flags_value |= 0x08,
                    LinuxSchedulerFlag::SchedFlagKeepParams => flags_value |= 0x10,
                    LinuxSchedulerFlag::SchedFlagUtilClampMin => flags_value |= 0x20,
                    LinuxSchedulerFlag::SchedFlagUtilClampMax => flags_value |= 0x40,
                }
            }
        }
        let attributes = SchedulerAttributes {
            size: mem::size_of::<SchedulerAttributes>() as u32,
            sched_policy: policy,
            sched_flags: flags_value,
            sched_nice: sc.nice().unwrap_or(0),
            sched_priority: sc.priority().unwrap_or(0) as u32,
            sched_runtime: sc.runtime().unwrap_or(0),
            sched_deadline: sc.deadline().unwrap_or(0),
            sched_period: sc.period().unwrap_or(0),
            sched_util_min: 0,
            sched_util_max: 0,
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_sched_setattr,
                0 as libc::pid_t,
                &attributes as *const SchedulerAttributes,
                0u32,
            )
        };
        if result == -1 {
            let err = std::io::Error::last_os_error();
            tracing::error!(?err, "error setting scheduler");
            return Err(InitProcessError::SchedSetattr(err.to_string()));
        }
    }
    Ok(())
}

#[cfg(feature = "libseccomp")]
fn sync_seccomp(
    fd: Option<i32>,
    main_sender: &mut channel::MainSender,
    init_receiver: &mut channel::InitReceiver,
) -> Result<()> {
    if let Some(fd) = fd {
        tracing::debug!("init process sync seccomp, notify fd: {}", fd);
        main_sender.seccomp_notify_request(fd).map_err(|err| {
            tracing::error!(?err, "failed to send seccomp notify request");
            InitProcessError::Channel(err)
        })?;
        init_receiver
            .wait_for_seccomp_request_done()
            .map_err(|err| {
                tracing::error!(?err, "failed to wait for seccomp request done");
                InitProcessError::Channel(err)
            })?;
        // Once we are sure the seccomp notify fd is sent, we can safely close
        // it. The fd is now duplicated to the main process and sent to seccomp
        // listener.
        let _ = unistd::close(fd);
    }

    Ok(())
}

fn configure_container_network_devices(
    net_device: &HashMap<String, LinuxNetDevice>,
    main_sender: &mut channel::MainSender,
    init_receiver: &mut channel::InitReceiver,
) -> Result<()> {
    if net_device.is_empty() {
        return Ok(());
    }

    main_sender.network_setup_ready()?;

    let addrs_map = init_receiver.wait_for_move_network_device()?;
    for (name, net_dev) in net_device {
        if let Some(cidr_addrs) = addrs_map.get(name) {
            // Get the device's final name (use configured name if provided, otherwise use original name)
            let new_name = resolve_device_name(net_dev, name.as_str());

            // Create network clients
            let mut link_client = LinkClient::new(create_network_client()).map_err(|err| {
                tracing::error!(?err, "failed to create link client");
                err
            })?;
            let mut addr_client = AddressClient::new(create_network_client()).map_err(|err| {
                tracing::error!(?err, "failed to create address client");
                err
            })?;

            // Get the device index
            let ns_link = link_client.get_by_name(new_name).map_err(|err| {
                tracing::error!(?err, "failed to get device by name: {}", new_name);
                err
            })?;

            // Assign IP addresses to the device
            setup_addresses_in_network_namespace(
                cidr_addrs,
                ns_link.header.index,
                new_name,
                &mut addr_client,
            )
            .map_err(|err| {
                tracing::error!(?err, "failed to setup addresses for device: {}", new_name);
                err
            })?;

            // Bring the device up
            link_client.set_up(ns_link.header.index).map_err(|err| {
                tracing::error!(?err, "failed to bring up device: {}", new_name);
                err
            })?;
        }
    }

    Ok(())
}

// verifyCwd ensures that the current directory is actually inside the mount
// namespace root of the current process.
// Please refer to https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv for more details.
fn verify_cwd() -> Result<()> {
    let cwd = unistd::getcwd().map_err(|err| {
        if let nix::errno::Errno::ENOENT = err {
            // https://man7.org/linux/man-pages/man2/getcwd.2.html
            // ENOENT The current working directory has been unlinked.
            InitProcessError::InvalidCwd(err)
        } else {
            InitProcessError::NixOther(err)
        }
    })?;

    if !cwd.is_absolute() {
        // This should never happen, but just in case.
        return Err(InitProcessError::InvalidCwd(nix::errno::Errno::ENOENT));
    }

    Ok(())
}

/// Set the HOME environment variable if it is not already set or is empty.
#[cfg(test)]
fn set_home_env_if_not_exists(envs: &mut HashMap<String, String>, uid: Uid) {
    if envs.get("HOME").is_none_or(|v| v.is_empty()) {
        if let Some(dir_home) = utils::get_user_home(uid.into()) {
            set_home_from_path(envs, &dir_home);
        }
    }
}

/// Set the HOME environment variable if dir_home string is valid UTF-8
#[cfg(test)]
fn set_home_from_path(envs: &mut HashMap<String, String>, dir_home: &Path) {
    if let Some(home_str) = dir_home.to_str() {
        envs.insert("HOME".to_owned(), home_str.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::env;
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use anyhow::Result;
    use nix::sys::wait::{WaitStatus, waitpid};
    #[cfg(feature = "libseccomp")]
    use nix::unistd;
    use nix::unistd::{ForkResult, fork};
    use nix::unistd::{Uid, User as NixUser};
    use oci_spec::runtime::{
        Capability as SpecCapability, LinuxCapabilitiesBuilder, LinuxNamespaceBuilder,
        ProcessBuilder, SpecBuilder, UserBuilder,
    };
    #[cfg(feature = "libseccomp")]
    use serial_test::serial;

    use super::*;
    use crate::syscall::syscall::create_syscall;
    use crate::syscall::test::{
        ArgName, IoPriorityArgs, MountArgs, SecurityCall, TestHelperSyscall,
    };

    #[test]
    fn linyaps_ns_last_pid_writer_updates_existing_file_only() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("ns_last_pid");
        fs::write(&path, "0")?;

        set_ns_last_pid_at(&path, "8123")?;

        assert_eq!(fs::read_to_string(&path)?, "8123");
        set_ns_last_pid_at(&temporary.path().join("missing"), "9000")?;
        Ok(())
    }

    #[test]
    fn test_readonly_path() -> Result<()> {
        let syscall = create_syscall();
        readonly_path(Path::new("/proc/sys"), syscall.as_ref())?;

        let want = vec![
            MountArgs {
                source: Some(PathBuf::from("/proc/sys")),
                target: PathBuf::from("/proc/sys"),
                fstype: None,
                flags: MsFlags::MS_BIND | MsFlags::MS_REC,
                data: None,
            },
            MountArgs {
                source: Some(PathBuf::from("/proc/sys")),
                target: PathBuf::from("/proc/sys"),
                fstype: None,
                flags: MsFlags::MS_NOSUID
                    | MsFlags::MS_NODEV
                    | MsFlags::MS_NOEXEC
                    | MsFlags::MS_BIND
                    | MsFlags::MS_REMOUNT
                    | MsFlags::MS_RDONLY,
                data: None,
            },
        ];
        let got = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_mount_args();

        assert_eq!(want, *got);
        assert_eq!(got.len(), 2);
        Ok(())
    }

    #[test]
    fn test_apply_rest_namespaces() -> Result<()> {
        let syscall = create_syscall();
        let spec = SpecBuilder::default().build()?;
        let linux_spaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Uts)
                .build()?,
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Pid)
                .build()?,
        ];
        let namespaces = Namespaces::try_from(Some(&linux_spaces))?;

        apply_rest_namespaces(&namespaces, &spec, syscall.as_ref())?;

        let got_hostnames = syscall
            .as_ref()
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_hostname_args();
        assert_eq!(1, got_hostnames.len());
        assert_eq!("youki".to_string(), got_hostnames[0]);

        let got_domainnames = syscall
            .as_ref()
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_domainname_args();
        assert_eq!(0, got_domainnames.len());
        Ok(())
    }

    #[test]
    fn process_security_is_ignored_without_capabilities() -> Result<()> {
        let mut process = ProcessBuilder::default()
            .user(
                UserBuilder::default()
                    .uid(1001_u32)
                    .gid(1002_u32)
                    .additional_gids(vec![1003_u32])
                    .build()?,
            )
            .no_new_privileges(false)
            .build()?;
        process.set_capabilities(None);
        let syscall = TestHelperSyscall::default();

        set_process_security(&process, &syscall)?;

        assert!(syscall.get_security_calls().is_empty());
        Ok(())
    }

    #[test]
    fn process_security_matches_frozen_transition_order() -> Result<()> {
        let bounding = HashSet::from([SpecCapability::Chown, SpecCapability::Setgid]);
        let effective = HashSet::from([SpecCapability::Chown]);
        let permitted = HashSet::from([SpecCapability::Chown, SpecCapability::Setuid]);
        let inheritable = HashSet::from([SpecCapability::Setuid]);
        let ambient = HashSet::from([SpecCapability::Chown]);
        let process = ProcessBuilder::default()
            .user(
                UserBuilder::default()
                    .uid(1001_u32)
                    .gid(1002_u32)
                    .additional_gids(Vec::<u32>::new())
                    .build()?,
            )
            .capabilities(
                LinuxCapabilitiesBuilder::default()
                    .bounding(bounding.clone())
                    .effective(effective.clone())
                    .permitted(permitted.clone())
                    .inheritable(inheritable.clone())
                    .ambient(ambient.clone())
                    .build()?,
            )
            .no_new_privileges(false)
            .build()?;
        let syscall = TestHelperSyscall::default();

        set_process_security(&process, &syscall)?;

        assert_eq!(
            syscall.get_security_calls(),
            vec![
                SecurityCall::SetBounding(capabilities::to_set(&bounding)),
                SecurityCall::SetKeepCapabilities(true),
                SecurityCall::SetGid(Gid::from_raw(1002)),
                SecurityCall::SetGroups(Vec::new()),
                SecurityCall::SetUid(Uid::from_raw(1001)),
                SecurityCall::SetProcessCapabilities {
                    effective: capabilities::to_set(&effective),
                    permitted: capabilities::to_set(&permitted),
                    inheritable: capabilities::to_set(&inheritable),
                },
                SecurityCall::SetAmbient(capabilities::to_set(&ambient)),
                SecurityCall::SetNoNewPrivileges,
            ]
        );
        Ok(())
    }

    #[test]
    fn missing_capability_fields_clear_base_and_ambient_sets() -> Result<()> {
        let mut capability_sets = LinuxCapabilitiesBuilder::default().build()?;
        capability_sets
            .set_bounding(None)
            .set_effective(None)
            .set_permitted(None)
            .set_inheritable(None)
            .set_ambient(None);
        let mut process = ProcessBuilder::default()
            .user(UserBuilder::default().uid(7_u32).gid(8_u32).build()?)
            .capabilities(capability_sets)
            .build()?;
        process.set_no_new_privileges(None);
        let syscall = TestHelperSyscall::default();

        set_process_security(&process, &syscall)?;

        assert_eq!(
            syscall.get_security_calls(),
            vec![
                SecurityCall::SetKeepCapabilities(true),
                SecurityCall::SetGid(Gid::from_raw(8)),
                SecurityCall::SetUid(Uid::from_raw(7)),
                SecurityCall::SetProcessCapabilities {
                    effective: CapsHashSet::new(),
                    permitted: CapsHashSet::new(),
                    inheritable: CapsHashSet::new(),
                },
                SecurityCall::SetAmbient(CapsHashSet::new()),
            ]
        );
        Ok(())
    }

    #[test]
    fn payload_signals_are_unblocked_and_reset() -> Result<()> {
        match unsafe { fork()? } {
            ForkResult::Child => {
                let mut blocked = unsafe { mem::zeroed::<libc::sigset_t>() };
                unsafe {
                    libc::sigfillset(&mut blocked);
                    libc::sigprocmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut());
                }
                let mut ignored = unsafe { mem::zeroed::<libc::sigaction>() };
                ignored.sa_sigaction = libc::SIG_IGN;
                unsafe {
                    libc::sigemptyset(&mut ignored.sa_mask);
                    libc::sigaction(libc::SIGUSR1, &ignored, std::ptr::null_mut());
                }

                if reset_process_signals().is_err() {
                    unsafe { libc::_exit(1) };
                }

                let mut current_mask = unsafe { mem::zeroed::<libc::sigset_t>() };
                let mut current_action = unsafe { mem::zeroed::<libc::sigaction>() };
                let mask_result = unsafe {
                    libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut current_mask)
                };
                let action_result = unsafe {
                    libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut current_action)
                };
                let unblocked = unsafe { libc::sigismember(&current_mask, libc::SIGUSR1) } == 0;
                let reset = current_action.sa_sigaction == libc::SIG_DFL;
                unsafe {
                    libc::_exit(i32::from(
                        mask_result != 0 || action_result != 0 || !unblocked || !reset,
                    ));
                }
            }
            ForkResult::Parent { child } => {
                assert_eq!(waitpid(child, None)?, WaitStatus::Exited(child, 0));
            }
        }
        Ok(())
    }

    #[test]
    fn test_set_supplementary_gids() -> Result<()> {
        // gids additional gids is empty case
        let user = UserBuilder::default().build().unwrap();
        assert!(set_supplementary_gids(&user, &None, create_syscall().as_ref()).is_ok());

        let tests = vec![
            (
                UserBuilder::default()
                    .additional_gids(vec![33, 34])
                    .build()?,
                None::<UserNamespaceConfig>,
                vec![Gid::from_raw(33), Gid::from_raw(34)],
            ),
            // unreachable case
            (
                UserBuilder::default().build()?,
                Some(UserNamespaceConfig::default()),
                vec![],
            ),
            (
                UserBuilder::default()
                    .additional_gids(vec![37, 38])
                    .build()?,
                Some(UserNamespaceConfig {
                    privileged: true,
                    gid_mappings: None,
                    newgidmap: None,
                    newuidmap: None,
                    uid_mappings: None,
                    user_namespace: None,
                    ..Default::default()
                }),
                vec![Gid::from_raw(37), Gid::from_raw(38)],
            ),
            (
                UserBuilder::default()
                    .additional_gids(vec![33, 34, 34])
                    .build()?,
                None::<UserNamespaceConfig>,
                vec![Gid::from_raw(33), Gid::from_raw(34), Gid::from_raw(34)],
            ),
        ];
        for (user, ns_config, want) in tests.into_iter() {
            let syscall = create_syscall();
            let result = set_supplementary_gids(&user, &ns_config, syscall.as_ref());
            match fs::read_to_string("/proc/self/setgroups")?.trim() {
                "deny" => {
                    assert!(result.is_err());
                }
                "allow" => {
                    assert!(result.is_ok());
                    let got = syscall
                        .as_any()
                        .downcast_ref::<TestHelperSyscall>()
                        .unwrap()
                        .get_groups_args();
                    // set set_supplementary_gids uses hashset internally
                    // so we cannot be sure of the order, hence compare the
                    // length and includes
                    assert_eq!(want.len(), got.len());
                    for gid in &want {
                        assert!(got.contains(gid));
                    }
                }
                _ => unreachable!("setgroups value unknown"),
            }
        }
        Ok(())
    }

    #[test]
    #[serial]
    #[cfg(feature = "libseccomp")]
    fn test_sync_seccomp() -> Result<()> {
        use std::os::unix::io::IntoRawFd;
        use std::thread;

        let tmp_file = tempfile::tempfile()?;

        let (mut main_sender, mut main_receiver) = channel::main_channel()?;
        let (mut init_sender, mut init_receiver) = channel::init_channel()?;

        let fd = tmp_file.into_raw_fd();
        let th = thread::spawn(move || {
            assert!(main_receiver.wait_for_seccomp_request().is_ok());
            assert!(init_sender.seccomp_notify_done().is_ok());
        });

        // sync_seccomp close the fd,
        sync_seccomp(Some(fd), &mut main_sender, &mut init_receiver)?;
        // so expecting close the same fd again will causing EBADF error.
        assert_eq!(nix::errno::Errno::EBADF, unistd::close(fd).unwrap_err());
        assert!(th.join().is_ok());
        Ok(())
    }

    #[test]
    fn test_masked_path_does_not_exist() {
        let syscall = create_syscall();
        let mocks = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap();

        let paths = vec!["/doesnotexist".to_string()];
        assert!(super::masked_paths(&paths, &None, syscall.as_ref()).is_ok());
        let got = mocks.get_mount_from_fd_args();
        assert_eq!(0, got.len());
        let got = mocks.get_mount_args();
        assert_eq!(0, got.len());
    }

    #[test]
    fn test_masked_path_mounts_via_fd() -> Result<()> {
        let syscall = create_syscall();
        let paths = vec!["/proc/sys/kernel/core_pattern".to_string()];
        super::masked_paths(&paths, &None, syscall.as_ref()).map_err(anyhow::Error::from)?;

        let got = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_mount_from_fd_args();
        assert_eq!(1, got.len());
        let arg = &got[0];
        assert!(arg.fd >= 0);
        assert_eq!(PathBuf::from("/proc/sys/kernel/core_pattern"), arg.target);
        Ok(())
    }

    #[test]
    fn test_masked_path_is_file_with_no_label() {
        let syscall = create_syscall();
        let mocks = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap();
        mocks.set_ret_err(ArgName::MountFromFd, || {
            Err(SyscallError::Nix(nix::errno::Errno::ENOTDIR))
        });

        let paths = vec!["/proc/self".to_string()];
        assert!(super::masked_paths(&paths, &None, syscall.as_ref()).is_ok());

        let got = mocks.get_mount_args();
        let want = MountArgs {
            source: Some(PathBuf::from("tmpfs")),
            target: PathBuf::from("/proc/self"),
            fstype: Some("tmpfs".to_string()),
            flags: MsFlags::MS_RDONLY,
            data: Some("".to_string()),
        };
        assert_eq!(1, got.len());
        assert_eq!(want, got[0]);
    }

    #[test]
    fn test_masked_path_is_file_with_label() {
        let syscall = create_syscall();
        let mocks = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap();
        mocks.set_ret_err(ArgName::MountFromFd, || {
            Err(SyscallError::Nix(nix::errno::Errno::ENOTDIR))
        });

        let paths = vec!["/proc/self".to_string()];
        assert!(
            super::masked_paths(&paths, &Some("default".to_string()), syscall.as_ref()).is_ok()
        );

        let got = mocks.get_mount_args();
        let want = MountArgs {
            source: Some(PathBuf::from("tmpfs")),
            target: PathBuf::from("/proc/self"),
            fstype: Some("tmpfs".to_string()),
            flags: MsFlags::MS_RDONLY,
            data: Some("context=\"default\"".to_string()),
        };
        assert_eq!(1, got.len());
        assert_eq!(want, got[0]);
    }

    #[test]
    fn test_masked_path_with_unknown_error() {
        let syscall = create_syscall();
        let mocks = syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap();
        mocks.set_ret_err(ArgName::MountFromFd, || {
            Err(SyscallError::Nix(nix::errno::Errno::UnknownErrno))
        });

        let paths = vec!["/proc/self/exe".to_string()];
        assert!(super::masked_paths(&paths, &None, syscall.as_ref()).is_err());
        let got = mocks.get_mount_args();
        assert_eq!(0, got.len());

        mocks.set_ret_err(ArgName::Mount, || {
            Err(SyscallError::Nix(nix::errno::Errno::UnknownErrno))
        });
        let paths = vec!["/proc/self".to_string()];
        assert!(super::masked_paths(&paths, &None, syscall.as_ref()).is_err());
        let got = mocks.get_mount_args();
        assert_eq!(0, got.len());
    }

    #[test]
    fn test_set_io_priority() {
        let test_command = TestHelperSyscall::default();
        let io_priority_op = None;
        assert!(set_io_priority(&test_command, &io_priority_op).is_ok());

        let data = "{\"class\":\"IOPRIO_CLASS_RT\",\"priority\":1}";
        let iop: LinuxIOPriority = serde_json::from_str(data).unwrap();
        let io_priority_op = Some(iop);
        assert!(set_io_priority(&test_command, &io_priority_op).is_ok());

        let want_io_priority = IoPriorityArgs {
            class: 1,
            priority: 1,
        };
        let set_io_prioritys = test_command.get_io_priority_args();
        assert_eq!(set_io_prioritys[0], want_io_priority);
    }

    #[test]
    fn test_set_home_env_if_not_exists_already_exists() {
        let mut envs = HashMap::new();
        envs.insert("HOME".to_owned(), "/existing/home".to_owned());

        set_home_env_if_not_exists(&mut envs, Uid::from_raw(0));
        assert_eq!(envs.get("HOME"), Some(&"/existing/home".to_string()));
    }

    #[test]
    fn test_set_home_env_if_not_exists_already_exists_non_root() {
        let mut envs = HashMap::new();
        envs.insert("HOME".to_owned(), "/existing/home".to_owned());

        set_home_env_if_not_exists(&mut envs, Uid::current());
        assert_eq!(envs.get("HOME"), Some(&"/existing/home".to_string()));
    }

    #[test]
    fn test_set_home_env_if_not_exists_already_exists_but_empty_value() {
        let mut envs = HashMap::new();
        envs.insert("HOME".to_owned(), "".to_owned());

        set_home_env_if_not_exists(&mut envs, Uid::from_raw(0));
        assert_eq!(envs.get("HOME"), Some(&"/root".to_string()));
    }

    #[test]
    fn test_set_home_env_if_not_exists_already_exists_but_empty_value_non_root() {
        let mut envs = HashMap::new();
        envs.insert("HOME".to_owned(), "".to_owned());

        // Make TEST_NON_ROOT_UID configurable to run tests on GitHub Actions runners.
        let test_uid = env::var("TEST_NON_ROOT_UID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .map(Uid::from_raw)
            .unwrap_or_else(Uid::current);
        let expected = NixUser::from_uid(test_uid)
            .ok()
            .flatten()
            .and_then(|user| user.dir.to_str().map(|s| s.to_owned()))
            .unwrap_or_default();

        set_home_env_if_not_exists(&mut envs, test_uid);
        assert_eq!(envs.get("HOME"), Some(&expected));
    }

    #[test]
    fn test_set_home_env_if_not_exists_not_set() {
        let mut envs = HashMap::new();

        set_home_env_if_not_exists(&mut envs, Uid::from_raw(0));
        assert_eq!(envs.get("HOME"), Some(&"/root".to_string()));
    }

    #[test]
    fn test_set_home_env_if_not_exists_not_set_non_root() {
        let mut envs = HashMap::new();

        // Make TEST_NON_ROOT_UID configurable to run tests on GitHub Actions runners.
        let test_uid = env::var("TEST_NON_ROOT_UID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .map(Uid::from_raw)
            .unwrap_or_else(Uid::current);
        let expected = NixUser::from_uid(test_uid)
            .ok()
            .flatten()
            .and_then(|user| user.dir.to_str().map(|s| s.to_owned()))
            .unwrap_or_default();

        set_home_env_if_not_exists(&mut envs, test_uid);
        assert_eq!(envs.get("HOME"), Some(&expected));
    }

    #[test]
    fn test_set_home_from_path_valid_utf8() {
        let mut envs = HashMap::new();
        let valid_path = PathBuf::from("/home/user");

        set_home_from_path(&mut envs, &valid_path);
        assert_eq!(envs.get("HOME"), Some(&"/home/user".to_string()));
    }

    #[test]
    fn test_set_home_from_path_invalid_utf8() {
        let mut envs = HashMap::new();

        let invalid_bytes = b"/home/user/\xFF\xFE";
        let invalid_path = PathBuf::from(OsStr::from_bytes(invalid_bytes));
        assert!(invalid_path.to_str().is_none());

        set_home_from_path(&mut envs, &invalid_path);
        assert_eq!(envs.get("HOME"), None);
    }
}
