use std::error::Error;
use std::os::fd::FromRawFd;

use libcgroups::common::CgroupManager;
use nix::unistd::{Gid, Pid, Uid, close, getpid, write};
use oci_spec::runtime::{LinuxIdMapping, LinuxNamespace, LinuxNamespaceType, LinuxResources};

use super::args::{ContainerArgs, ContainerType};
use super::channel::{IntermediateReceiver, MainSender};
use super::fork::CloneCb;
use super::init::error::InitProcessError;
use super::init::process as init_process;
use crate::error::MissingSpecError;
use crate::namespaces::Namespaces;
use crate::process::{channel, cpu_affinity, fork};
use crate::utils::rootless_required;

#[derive(Debug, thiserror::Error)]
pub enum IntermediateProcessError {
    #[error(transparent)]
    Channel(#[from] channel::ChannelError),
    #[error(transparent)]
    Namespace(#[from] crate::namespaces::NamespaceError),
    #[error(transparent)]
    Syscall(#[from] crate::syscall::SyscallError),
    #[error("failed to launch init process")]
    InitProcess(#[source] fork::CloneError),
    #[error("cgroup error: {0}")]
    Cgroup(String),
    #[error(transparent)]
    Procfs(#[from] procfs::ProcError),
    #[error("exec notify failed")]
    ExecNotify(#[source] nix::Error),
    #[error(transparent)]
    MissingSpec(#[from] crate::error::MissingSpecError),
    #[error("CPU affinity error {0}")]
    CpuAffinity(#[from] cpu_affinity::CPUAffinityError),
    #[error("other error")]
    Other(String),
}

type Result<T> = std::result::Result<T, IntermediateProcessError>;

pub fn container_intermediate_process(
    args: &ContainerArgs,
    intermediate_chan: &mut (channel::IntermediateSender, channel::IntermediateReceiver),
    init_chan: &mut (channel::InitSender, channel::InitReceiver),
    intermediate_main_sender: &mut channel::MainSender,
    init_main_sender: &mut channel::MainSender,
) -> Result<()> {
    let (inter_sender, inter_receiver) = intermediate_chan;
    let (init_sender, init_receiver) = init_chan;
    let command = args.syscall.create_syscall();
    let spec = &args.spec;
    let linux = spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;
    let namespaces = Namespaces::try_from(linux.namespaces().as_ref())?;
    let creates_user_namespace = namespaces
        .get(LinuxNamespaceType::User)?
        .is_some_and(|namespace| namespace.path().is_none());
    let current_pid = Pid::this();
    // setting CPU affinity for tenant container before cgroup move
    if matches!(args.container_type, ContainerType::TenantContainer { .. }) {
        if let Some(exec_cpu_affinity) = spec
            .process()
            .as_ref()
            .and_then(|p| p.exec_cpu_affinity().as_ref())
        {
            if let Some(initial) = exec_cpu_affinity.initial() {
                cpu_affinity::set_cpuset_affinity_from_string(current_pid, initial)?;
            }
        }
    }
    let _ = cpu_affinity::log_cpu_affinity();

    // this needs to be done before we create the init process, so that the init
    // process will already be captured by the cgroup. It also needs to be done
    // before we enter the user namespace because if a privileged user starts a
    // rootless container on a cgroup v1 system we can still fulfill resource
    // restrictions through the cgroup fs support (delegation through systemd is
    // not supported for v1 by us). This only works if the user has not yet been
    // mapped to an unprivileged user by the user namespace however.
    // In addition this needs to be done before we enter the cgroup namespace as
    // the cgroup of the process will form the root of the cgroup hierarchy in
    // the cgroup namespace.
    if !args.cgroups_disabled {
        let rootless = rootless_required(command.as_ref()).unwrap_or(false);
        let cgroup_manager =
            libcgroups::common::create_cgroup_manager(args.cgroup_config.to_owned())
                .map_err(|e| IntermediateProcessError::Cgroup(e.to_string()))?
                .with_rootless(rootless);
        apply_cgroups(
            &cgroup_manager,
            linux.resources().as_ref(),
            matches!(args.container_type, ContainerType::InitContainer),
        )?;
    }

    // setting CPU affinity for tenant container after cgroup move
    if matches!(args.container_type, ContainerType::TenantContainer { .. }) {
        if let Some(exec_cpu_affinity) = spec
            .process()
            .as_ref()
            .and_then(|p| p.exec_cpu_affinity().as_ref())
        {
            if let Some(cpu_affinity_final) = exec_cpu_affinity.cpu_affinity_final() {
                cpu_affinity::set_cpuset_affinity_from_string(current_pid, cpu_affinity_final)?;
            }
        }
    }

    // if new user is specified in specification, this will be true and new
    // namespace will be created, check
    // https://man7.org/linux/man-pages/man7/user_namespaces.7.html for more
    // information
    if let Some(user_namespace) = namespaces.get(LinuxNamespaceType::User)? {
        setup_userns(
            &namespaces,
            user_namespace,
            intermediate_main_sender,
            inter_receiver,
        )?;

        // After UID and GID mapping is configured correctly in the Youki main
        // process, We want to make sure continue as the root user inside the
        // new user namespace. This is required because the process of
        // configuring the container process will require root, even though the
        // root in the user namespace likely is mapped to an non-privileged user
        // on the parent user namespace.
        if maps_container_root(linux.uid_mappings().as_ref())
            && maps_container_root(linux.gid_mappings().as_ref())
        {
            command.set_id(Uid::from_raw(0), Gid::from_raw(0))?;
        }
    }

    set_oom_score_adj(args, creates_user_namespace)?;

    if let Some(time_namespace) = namespaces.get(LinuxNamespaceType::Time)? {
        namespaces.unshare_or_setns(time_namespace)?;
        if time_namespace.path().is_none()
            && linux
                .time_offsets()
                .as_ref()
                .is_some_and(|offsets| !offsets.is_empty())
        {
            setup_time_offsets(intermediate_main_sender, inter_receiver)?;
        }
    }

    // Pid namespace requires an extra fork to enter, so we enter pid namespace now.
    if let Some(pid_namespace) = namespaces.get(LinuxNamespaceType::Pid)? {
        namespaces.unshare_or_setns(pid_namespace)?;
    }

    let cb: CloneCb = {
        Box::new(|| {
            if let Err(ret) = prctl::set_name("youki:[2:INIT]") {
                tracing::error!(?ret, "failed to set name for child process");
                return ret;
            }

            // We are inside the forked process here. The first thing we have to do
            // is to close any unused senders, since fork will make a dup for all
            // the socket.
            if let Err(err) = init_sender.close() {
                tracing::error!(?err, "failed to close receiver in init process");
                return -1;
            }
            if let Err(err) = inter_sender.close() {
                tracing::error!(?err, "failed to close sender in the intermediate process");
                return -1;
            }
            if let Err(err) = intermediate_main_sender.close() {
                tracing::error!(
                    ?err,
                    "failed to close intermediate main sender in init process"
                );
                return -1;
            }
            match init_process::container_init_process(args, init_main_sender, init_receiver) {
                Ok(_) => 0,
                Err(e) => {
                    report_init_error(args.error_fd, &e);
                    if let Err(err) = init_main_sender.exec_failed(e.to_string()) {
                        tracing::error!(?err, "failed sending error to main sender");
                    }
                    if let ContainerType::TenantContainer { exec_notify_fd } = args.container_type {
                        let buf = format!("{e}");
                        let exec_notify_fd =
                            unsafe { std::os::fd::OwnedFd::from_raw_fd(exec_notify_fd) };
                        if let Err(err) = write(&exec_notify_fd, buf.as_bytes()) {
                            tracing::error!(?err, "failed to write to exec notify fd");
                        }

                        // After sending the error through the exec_notify_fd,
                        // we need to explicitly close the pipe.
                        drop(exec_notify_fd);
                    }
                    libc::EXIT_FAILURE
                }
            }
        })
    };

    // We have to record the pid of the init process. The init process will be
    // inside the pid namespace, so we can't rely on the init process to send us
    // the correct pid. We also want to clone the init process as a sibling
    // process to the intermediate process. The intermediate process is only
    // used as a jumping board to set the init process to the correct
    // configuration. The youki main process can decide what to do with the init
    // process and the intermediate process can just exit safely after the job
    // is done.
    let pid = fork::container_clone_sibling(cb).map_err(|err| {
        tracing::error!("failed to fork init process: {}", err);
        IntermediateProcessError::InitProcess(err)
    })?;

    // Close the exec_notify_fd in this process
    if let ContainerType::TenantContainer { exec_notify_fd } = args.container_type {
        close(exec_notify_fd).map_err(|err| {
            tracing::error!("failed to close exec notify fd: {}", err);
            IntermediateProcessError::ExecNotify(err)
        })?;
    }

    intermediate_main_sender
        .intermediate_ready(pid)
        .map_err(|err| {
            tracing::error!("failed to wait on intermediate process: {}", err);
            err
        })?;

    // Close unused senders here so we don't have lingering socket around.
    intermediate_main_sender.close().map_err(|err| {
        tracing::error!("failed to close unused main sender: {}", err);
        err
    })?;
    init_main_sender.close().map_err(|err| {
        tracing::error!("failed to close unused init main sender: {}", err);
        err
    })?;
    inter_sender.close().map_err(|err| {
        tracing::error!(
            "failed to close sender in the intermediate process: {}",
            err
        );
        err
    })?;
    init_sender.close().map_err(|err| {
        tracing::error!("failed to close unused init sender: {}", err);
        err
    })?;

    Ok(())
}

fn report_init_error(error_fd: Option<i32>, error: &InitProcessError) {
    let Some(error_fd) = error_fd else {
        return;
    };
    let message = compatibility_error_message(error);
    let message = message.as_bytes().get(..4091).unwrap_or(message.as_bytes());
    let mut payload = Vec::with_capacity(5 + message.len());
    payload.extend_from_slice(&getpid().as_raw().to_ne_bytes());
    payload.push(compatibility_error_stage(error));
    payload.extend_from_slice(message);
    let mut written = 0;
    while written < payload.len() {
        let result = unsafe {
            libc::write(
                error_fd,
                payload[written..].as_ptr().cast(),
                payload.len() - written,
            )
        };
        if result > 0 {
            written += result as usize;
        } else if result == -1 && nix::errno::Errno::last() == nix::errno::Errno::EINTR {
            continue;
        } else {
            break;
        }
    }
}

fn compatibility_error_stage(error: &InitProcessError) -> u8 {
    match error {
        InitProcessError::RootfsCanonicalize(_) | InitProcessError::Namespaces(_) => b'N',
        InitProcessError::RootfsAccess(_) => b'M',
        InitProcessError::Hooks(_) => b'C',
        InitProcessError::StartContainerHooks(_) => b'R',
        InitProcessError::Workload(_) | InitProcessError::Chdir(_) => b'X',
        _ => b'R',
    }
}

fn compatibility_error_message(error: &InitProcessError) -> String {
    if matches!(error, InitProcessError::RootFS(_)) {
        let mut current = error.source();
        while let Some(cause) = current {
            if let Some(error) = cause.downcast_ref::<std::io::Error>() {
                if let Some(errno) = error.raw_os_error() {
                    return errno_message(errno);
                }
                return error.to_string();
            }
            if let Some(errno) = cause.downcast_ref::<nix::errno::Errno>() {
                return errno_message(*errno as i32);
            }
            current = cause.source();
        }
    }
    error.to_string()
}

fn errno_message(errno: i32) -> String {
    let pointer = unsafe { libc::strerror(errno) };
    if pointer.is_null() {
        return std::io::Error::from_raw_os_error(errno).to_string();
    }
    unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

fn set_oom_score_adj(args: &ContainerArgs, restore_dumpable: bool) -> Result<()> {
    if !matches!(args.container_type, ContainerType::InitContainer) {
        return Ok(());
    }
    let Some(score) = args
        .spec
        .process()
        .as_ref()
        .and_then(|process| process.oom_score_adj())
    else {
        return Ok(());
    };
    if restore_dumpable {
        prctl::set_dumpable(true).map_err(|error| {
            IntermediateProcessError::Other(format!(
                "error in setting dumpable to true for oom score: {}",
                nix::errno::Errno::from_raw(error)
            ))
        })?;
    }
    let write_result = std::fs::write("/proc/self/oom_score_adj", score.to_string())
        .map_err(|error| IntermediateProcessError::Other(error.to_string()));
    if restore_dumpable {
        prctl::set_dumpable(false).map_err(|error| {
            IntermediateProcessError::Other(format!(
                "error in setting dumpable to false after oom score: {}",
                nix::errno::Errno::from_raw(error)
            ))
        })?;
    }
    write_result
}

fn maps_container_root(mappings: Option<&Vec<LinuxIdMapping>>) -> bool {
    mappings.is_some_and(|mappings| {
        mappings
            .iter()
            .any(|mapping| mapping.container_id() == 0 && mapping.size() > 0)
    })
}

fn setup_userns(
    namespaces: &Namespaces,
    user_namespace: &LinuxNamespace,
    sender: &mut MainSender,
    receiver: &mut IntermediateReceiver,
) -> Result<()> {
    namespaces.unshare_or_setns(user_namespace)?;
    if user_namespace.path().is_some() {
        return Ok(());
    }

    tracing::debug!("creating new user namespace");
    // child needs to be dumpable, otherwise the non root parent is not
    // allowed to write the uid/gid maps
    prctl::set_dumpable(true).map_err(|e| {
        IntermediateProcessError::Other(format!(
            "error in setting dumpable to true : {}",
            nix::errno::Errno::from_raw(e)
        ))
    })?;
    sender.identifier_mapping_request().map_err(|err| {
        tracing::error!("failed to send id mapping request: {}", err);
        err
    })?;
    receiver.wait_for_mapping_ack().map_err(|err| {
        tracing::error!("failed to receive id mapping ack: {}", err);
        err
    })?;
    prctl::set_dumpable(false).map_err(|e| {
        IntermediateProcessError::Other(format!(
            "error in setting dumplable to false : {}",
            nix::errno::Errno::from_raw(e)
        ))
    })?;
    Ok(())
}

fn setup_time_offsets(sender: &mut MainSender, receiver: &mut IntermediateReceiver) -> Result<()> {
    tracing::debug!("requesting parent to write time namespace offsets");

    prctl::set_dumpable(true).map_err(|e| {
        IntermediateProcessError::Other(format!(
            "error in setting dumpable to true for time offsets: {}",
            nix::errno::Errno::from_raw(e)
        ))
    })?;

    sender.time_offset_request().map_err(|err| {
        tracing::error!("failed to send time offset request: {}", err);
        err
    })?;

    receiver.wait_for_time_offsets_ack().map_err(|err| {
        tracing::error!("failed to receive time offsets ack: {}", err);
        err
    })?;

    prctl::set_dumpable(false).map_err(|e| {
        IntermediateProcessError::Other(format!(
            "error in setting dumpable to false after time offsets: {}",
            nix::errno::Errno::from_raw(e)
        ))
    })?;

    Ok(())
}

fn apply_cgroups<
    C: CgroupManager<Error = E> + ?Sized,
    E: std::error::Error + Send + Sync + 'static,
>(
    cmanager: &C,
    resources: Option<&LinuxResources>,
    init: bool,
) -> Result<()> {
    let pid = getpid();
    cmanager.add_task(pid).map_err(|err| {
        tracing::error!(?pid, ?err, ?init, "failed to add task to cgroup");
        IntermediateProcessError::Cgroup(err.to_string())
    })?;

    if init && let Some(resources) = resources {
        let controller_opt = libcgroups::common::ControllerOpt {
            resources,
            freezer_state: None,
            oom_score_adj: None,
            disable_oom_killer: false,
        };

        cmanager.apply(&controller_opt).map_err(|err| {
            tracing::error!(?pid, ?err, ?init, "failed to apply cgroup");
            IntermediateProcessError::Cgroup(err.to_string())
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use libcgroups::test_manager::TestManager;
    use nix::unistd::Pid;
    use oci_spec::runtime::{LinuxIdMappingBuilder, LinuxResources};
    use procfs::process::Process;

    use super::*;

    #[test]
    fn detects_whether_container_root_is_mapped() -> Result<()> {
        let root_mapping = LinuxIdMappingBuilder::default()
            .container_id(0_u32)
            .host_id(1000_u32)
            .size(1_u32)
            .build()?;
        let equivalent_mapping = LinuxIdMappingBuilder::default()
            .container_id(1000_u32)
            .host_id(1000_u32)
            .size(1_u32)
            .build()?;

        assert!(maps_container_root(Some(&vec![root_mapping])));
        assert!(!maps_container_root(Some(&vec![equivalent_mapping])));
        assert!(!maps_container_root(None));
        Ok(())
    }

    #[test]
    fn apply_cgroup_init() -> Result<()> {
        // arrange
        let cmanager = TestManager::default();
        let resources = LinuxResources::default();

        // act
        apply_cgroups(&cmanager, Some(&resources), true)?;

        // assert
        assert!(cmanager.get_add_task_args().len() == 1);
        assert_eq!(
            cmanager.get_add_task_args()[0],
            Pid::from_raw(Process::myself()?.pid())
        );
        assert!(cmanager.apply_called());
        Ok(())
    }

    #[test]
    fn apply_cgroup_tenant() -> Result<()> {
        // arrange
        let cmanager = TestManager::default();
        let resources = LinuxResources::default();

        // act
        apply_cgroups(&cmanager, Some(&resources), false)?;

        // assert
        assert_eq!(
            cmanager.get_add_task_args()[0],
            Pid::from_raw(Process::myself()?.pid())
        );
        assert!(!cmanager.apply_called());
        Ok(())
    }

    #[test]
    fn apply_cgroup_no_resources() -> Result<()> {
        // arrange
        let cmanager = TestManager::default();

        // act
        apply_cgroups(&cmanager, None, true)?;
        // assert
        assert_eq!(
            cmanager.get_add_task_args()[0],
            Pid::from_raw(Process::myself()?.pid())
        );
        assert!(!cmanager.apply_called());
        Ok(())
    }
}
