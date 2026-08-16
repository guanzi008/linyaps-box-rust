use std::fs::{self, File};
use std::io::{IoSliceMut, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::signal::Signal;
use libcontainer::syscall::syscall::SyscallType;
use nix::fcntl::OFlag;
use nix::sys::signal::{self, SigSet};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
use nix::sys::termios::{self, SetArg, Termios};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, pipe2};

use crate::cli::{CgroupManager, ExecOptions, GlobalOptions, KillOptions, ListOptions, RunOptions};
use crate::config::{PreparedBundle, process_console_size, process_uses_terminal};
use crate::exec::{ExecChildError, spawn};
use crate::status::{
    RuntimeStatus, Status, list_statuses, load_status, print_statuses, remove_status_directory,
    save_config, validate_id, write_status,
};

const INTERNAL_RUNTIME_DIRECTORY: &str = ".runtime";

pub fn list(options: &ListOptions, global: &GlobalOptions) -> Result<i32> {
    let statuses = list_statuses(&global.root)?;
    print_statuses(&statuses, options.format)?;
    Ok(0)
}

pub fn run(options: &RunOptions, global: &GlobalOptions) -> Result<i32> {
    validate_id(&options.container)?;
    fs::create_dir_all(&global.root)?;
    let runtime_root = runtime_root(&global.root);
    fs::create_dir_all(&runtime_root)?;
    let scratch = global.root.join(".bundles");
    let mut prepared = PreparedBundle::new(&options.bundle, &options.config, &scratch)?;
    let prepared_config = prepared.path().join("config.json");
    let terminal = process_uses_terminal(&prepared_config)?;
    let console_size = process_console_size(&prepared_config)?;
    let internal_console = (terminal && options.console_socket.is_none())
        .then(|| InternalConsole::new(&global.root))
        .transpose()?;
    let console_socket = terminal
        .then(|| {
            options
                .console_socket
                .as_ref()
                .or_else(|| internal_console.as_ref().map(InternalConsole::path))
        })
        .flatten();
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_nanos()
        .to_string();
    let mut compatibility_status = Status::creating(
        options.container.clone(),
        prepared.original_bundle().to_path_buf(),
        created,
    )?;
    prepared.set_hook_state_metadata(&compatibility_status.created, &compatibility_status.owner)?;
    write_status(&global.root, &compatibility_status)?;
    save_config(
        &global.root,
        &options.container,
        prepared.original_config_path(),
    )?;
    ensure_supported_cgroup_manager(global.cgroup_manager)?;
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error()).context("set child subreaper");
    }
    let mut signal_set = SigSet::all();
    signal_set.remove(signal::SIGUSR1);
    signal_set.thread_block()?;
    unsafe {
        libc::umask(0);
    }
    let (error_read, error_write) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)?;
    let container = ContainerBuilder::new(options.container.clone(), SyscallType::default())
        .with_root_path(&runtime_root)?
        .with_console_socket(console_socket)
        .with_preserved_fds(options.preserve_fds)
        .with_error_fd(error_write)
        .validate_id()?
        .as_init(prepared.path())
        .with_systemd(false)
        .with_cgroups_disabled(true)
        .with_detach(console_socket.is_some())
        .with_canonicalize_rootfs(prepared.canonicalize_rootfs())
        .build();
    let mut container = match container {
        Ok(container) => container,
        Err(error) => {
            if let Some(child_error) = read_child_error(error_read)? {
                tracing::error!(
                    target: crate::logging::FATAL_TARGET,
                    function = "clone_fn",
                    compat_pid = child_error.pid,
                    "child process error: {}",
                    child_error.message
                );
                tracing::error!(
                    function = "run",
                    "failed to run a container, caused by: {}",
                    child_error.stage.parent_message()
                );
            } else {
                let message = compatibility_build_error(&error);
                tracing::error!(
                    function = "run",
                    "failed to run a container, caused by: {message}"
                );
            }
            let status_cleanup = remove_status_directory(&global.root, &options.container);
            let _ = fs::remove_dir_all(&scratch);
            status_cleanup?;
            return Ok(1);
        }
    };
    let result = (|| -> Result<i32> {
        compatibility_status.pid = container
            .pid()
            .context("container state did not record an init pid")?
            .as_raw();
        compatibility_status.status = RuntimeStatus::Created;
        write_status(&global.root, &compatibility_status)?;
        prepared.validate_namespace_paths()?;
        let console = internal_console.map(InternalConsole::receive).transpose()?;
        let console_forwarder = console
            .map(|console| ConsoleForwarder::start(console, console_size))
            .transpose()?;
        container
            .start()
            .with_context(|| format!("failed to start container {}", options.container))?;
        container.refresh_state()?;
        compatibility_status.pid = container
            .pid()
            .context("container state did not record an init pid")?
            .as_raw();
        compatibility_status.status = RuntimeStatus::Running;
        write_status(&global.root, &compatibility_status)?;
        let mut code = wait_foreground(
            Pid::from_raw(compatibility_status.pid),
            &signal_set,
            console_forwarder.as_ref(),
        )?;
        let child_error = read_child_error(error_read)?;
        if let Some(console) = console_forwarder {
            console.finish()?;
        }
        if let Some(error) = child_error {
            tracing::error!(
                target: crate::logging::FATAL_TARGET,
                function = "clone_fn",
                compat_pid = error.pid,
                "child process error: {}",
                error.message
            );
            tracing::error!(
                function = "run",
                "failed to run a container, caused by: {}",
                error.stage.parent_message()
            );
            code = libc::EXIT_FAILURE;
        }
        compatibility_status.status = RuntimeStatus::Stopped;
        write_status(&global.root, &compatibility_status)?;
        Ok(code)
    })();

    let cleanup = if result.is_ok() {
        container.delete(true)
    } else {
        container.delete_without_poststop(true)
    }
    .map_err(anyhow::Error::from);
    let status_cleanup = remove_status_directory(&global.root, &options.container);
    let _ = fs::remove_dir_all(scratch);
    match (result, cleanup, status_cleanup) {
        (Ok(code), Ok(()), Ok(())) => Ok(code),
        (Err(error), cleanup, status_cleanup) => {
            let message =
                compatibility_hook_error(error.as_ref()).unwrap_or_else(|| format!("{error:#}"));
            tracing::error!(
                function = "run",
                "failed to run a container, caused by: {message}"
            );
            if let Err(cleanup_error) = cleanup {
                tracing::error!(
                    function = "run",
                    "failed to clean up container: {cleanup_error}"
                );
            }
            status_cleanup?;
            Ok(1)
        }
        (Ok(code), Err(error), Ok(()))
            if error
                .downcast_ref::<libcontainer::error::LibcontainerError>()
                .is_some_and(|error| {
                    matches!(error, libcontainer::error::LibcontainerError::Hook(_))
                }) =>
        {
            tracing::error!(function = "run", "failed to run post stop hooks: {error}");
            Ok(code)
        }
        (Ok(_), Err(error), _) => Err(error.context("failed to delete container")),
        (Ok(_), Ok(()), Err(error)) => Err(error),
    }
}

fn compatibility_build_error(error: &(dyn std::error::Error + 'static)) -> String {
    if let Some(message) = compatibility_hook_error(error) {
        return message;
    }
    let mut current = Some(error);
    while let Some(cause) = current {
        if let Some(message) = cause
            .downcast_ref::<libcontainer::error::LibcontainerError>()
            .and_then(libcontainer::error::LibcontainerError::compatibility_message)
        {
            return message;
        }
        if let Some(libcontainer::syscall::SyscallError::Nix(errno)) =
            cause.downcast_ref::<libcontainer::syscall::SyscallError>()
        {
            return format!("setrlimit: {}", errno_message(*errno as i32));
        }
        if let Some(errno) = cause.downcast_ref::<nix::errno::Errno>() {
            return format!("setrlimit: {}", errno_message(*errno as i32));
        }
        current = cause.source();
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

fn compatibility_hook_error(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut current = Some(error);
    while let Some(cause) = current {
        let message = cause.to_string();
        if message.starts_with("hook ") {
            return Some(message);
        }
        if let Some(hook_error) = cause.downcast_ref::<libcontainer::hooks::HookError>() {
            return Some(hook_error.to_string());
        }
        current = cause.source();
    }
    None
}

#[derive(Debug)]
struct ChildErrorReport {
    pid: i32,
    stage: ChildErrorStage,
    message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildErrorStage {
    NamespaceReady,
    ExpectedMessage,
    CreateContainerDone,
    ExecReady,
    ExecFailure,
}

impl ChildErrorStage {
    fn parse(value: u8) -> Result<Self> {
        match value {
            b'N' => Ok(Self::NamespaceReady),
            b'M' => Ok(Self::ExpectedMessage),
            b'C' => Ok(Self::CreateContainerDone),
            b'R' => Ok(Self::ExecReady),
            b'X' => Ok(Self::ExecFailure),
            _ => bail!("unknown child error stage"),
        }
    }

    fn parent_message(self) -> &'static str {
        match self {
            Self::NamespaceReady => {
                "container process exited before reaching expected stage namespace_ready"
            }
            Self::ExpectedMessage => "child process exited before sending expected message",
            Self::CreateContainerDone => {
                "container process exited before reaching expected stage createcontainer_done"
            }
            Self::ExecReady => "container process exited before reaching expected stage exec_ready",
            Self::ExecFailure => "container process failed during exec: Success",
        }
    }
}

fn read_child_error(error_read: OwnedFd) -> Result<Option<ChildErrorReport>> {
    let mut file = File::from(error_read);
    let mut payload = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(length) => payload.extend_from_slice(&buffer[..length]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        }
    }
    if payload.is_empty() {
        return Ok(None);
    }
    if payload.len() < std::mem::size_of::<i32>() + 1 {
        bail!("truncated child error report");
    }
    let pid = i32::from_ne_bytes(payload[..4].try_into().unwrap());
    let stage = ChildErrorStage::parse(payload[4])?;
    let message = String::from_utf8_lossy(&payload[5..]).into_owned();
    Ok(Some(ChildErrorReport {
        pid,
        stage,
        message,
    }))
}

pub fn exec(options: &ExecOptions, global: &GlobalOptions) -> Result<i32> {
    if validate_id(&options.container).is_err() {
        bail!("container not found");
    }
    let status_directory = global.root.join(&options.container);
    if !status_directory.join("status.json").exists() {
        bail!("container not found");
    }
    let status = load_status(&status_directory.join("status.json"))?;
    let spawned = spawn(status.pid, &status_directory.join("config.json"), options)?;
    let console_forwarder = spawned
        .console
        .map(|console| ConsoleForwarder::start(console, None))
        .transpose()?;
    let code = wait_foreground(spawned.pid, &spawned.signal_set, console_forwarder.as_ref())?;
    if let Some(console) = console_forwarder {
        console.finish()?;
    }
    Ok(code)
}

pub fn kill(options: &KillOptions, global: &GlobalOptions) -> Result<i32> {
    if validate_id(&options.container).is_err() {
        bail!("container not found");
    }
    let directory = global.root.join(&options.container);
    if !directory.join("status.json").exists() {
        bail!("container not found");
    }
    let status = load_status(&directory.join("status.json"))?;
    let signal = Signal::try_from(options.signal.as_str())?;
    if unsafe { libc::kill(status.pid, signal.into_raw()) } == -1 {
        let error = std::io::Error::last_os_error();
        let message = error
            .raw_os_error()
            .map(errno_message)
            .unwrap_or_else(|| error.to_string());
        bail!(
            "failed to kill process {} with signal {}: {message}",
            status.pid,
            signal.into_raw()
        );
    }
    Ok(0)
}

struct InternalConsole {
    _directory: tempfile::TempDir,
    listener: UnixListener,
    path: PathBuf,
}

impl InternalConsole {
    fn new(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        let directory = tempfile::Builder::new()
            .prefix(".console-")
            .tempdir_in(root)?;
        let path = directory.path().join("console.sock");
        let listener = UnixListener::bind(&path)
            .with_context(|| format!("failed to bind console socket {}", path.display()))?;
        Ok(Self {
            _directory: directory,
            listener,
            path,
        })
    }

    fn path(&self) -> &PathBuf {
        &self.path
    }

    fn receive(self) -> Result<OwnedFd> {
        let (stream, _) = self
            .listener
            .accept()
            .with_context(|| format!("failed to accept console socket {}", self.path.display()))?;
        let mut payload = [0_u8; 32];
        let mut slices = [IoSliceMut::new(&mut payload)];
        let mut control = nix::cmsg_space!([RawFd; 1]);
        let message = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut slices,
            Some(&mut control),
            MsgFlags::empty(),
        )?;
        if message
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
        {
            bail!("truncated console socket message");
        }
        for control in message.cmsgs()? {
            if let ControlMessageOwned::ScmRights(descriptors) = control {
                let mut descriptors = descriptors.into_iter();
                let descriptor = descriptors
                    .next()
                    .context("console socket did not contain a file descriptor")?;
                for extra in descriptors {
                    drop(unsafe { OwnedFd::from_raw_fd(extra) });
                }
                return Ok(unsafe { OwnedFd::from_raw_fd(descriptor) });
            }
        }
        bail!("console socket did not contain a file descriptor")
    }
}

struct TerminalGuard {
    original: Option<Termios>,
    descriptor: RawFd,
    _owned: Option<File>,
}

impl TerminalGuard {
    fn enter_raw_mode() -> Result<Self> {
        let (descriptor, owned) = detect_host_terminal()?;
        let Some(descriptor) = descriptor else {
            return Ok(Self {
                original: None,
                descriptor: -1,
                _owned: None,
            });
        };
        let borrowed = unsafe { BorrowedFd::borrow_raw(descriptor) };
        let original = termios::tcgetattr(borrowed)?;
        let mut raw = original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(borrowed, SetArg::TCSANOW, &raw)?;
        Ok(Self {
            original: Some(original),
            descriptor,
            _owned: owned,
        })
    }

    fn descriptor(&self) -> Option<RawFd> {
        self.original.as_ref().map(|_| self.descriptor)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Some(original) = self.original.as_ref() {
            let descriptor = unsafe { BorrowedFd::borrow_raw(self.descriptor) };
            let _ = termios::tcsetattr(descriptor, SetArg::TCSANOW, original);
        }
    }
}

fn detect_host_terminal() -> Result<(Option<RawFd>, Option<File>)> {
    for descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if unsafe { libc::isatty(descriptor) } == 1 {
            return Ok((Some(descriptor), None));
        }
    }
    let path = std::ffi::CString::new("/dev/tty").unwrap();
    let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if descriptor == -1 {
        return Ok((None, None));
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    if unsafe { libc::isatty(file.as_raw_fd()) } == 1 {
        Ok((Some(file.as_raw_fd()), Some(file)))
    } else {
        Ok((None, None))
    }
}

struct ConsoleForwarder {
    master: File,
    output: JoinHandle<Result<()>>,
    _terminal: TerminalGuard,
}

impl ConsoleForwarder {
    fn start(master: OwnedFd, configured_size: Option<(u16, u16)>) -> Result<Self> {
        let master = File::from(master);
        if let Some((height, width)) = configured_size {
            set_console_size(master.as_raw_fd(), height, width)?;
        }
        let mut input_master = master.try_clone()?;
        let mut output_master = master.try_clone()?;
        let terminal = TerminalGuard::enter_raw_mode()?;
        let _input = thread::spawn(move || {
            let _ = std::io::copy(&mut std::io::stdin(), &mut input_master);
        });
        let output = thread::spawn(move || -> Result<()> {
            let mut stdout = std::io::stdout().lock();
            let mut buffer = [0_u8; 8192];
            loop {
                match output_master.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(length) => {
                        stdout.write_all(&buffer[..length])?;
                        stdout.flush()?;
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        });
        let forwarder = Self {
            master,
            output,
            _terminal: terminal,
        };
        forwarder.resize();
        Ok(forwarder)
    }

    fn resize(&self) {
        let Some(descriptor) = self._terminal.descriptor() else {
            return;
        };
        let mut size = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if unsafe { libc::ioctl(descriptor, libc::TIOCGWINSZ, &mut size) } == 0 {
            let _ = unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &size) };
        }
    }

    fn finish(self) -> Result<()> {
        drop(self.master);
        self.output
            .join()
            .map_err(|_| anyhow::anyhow!("console forwarding thread panicked"))??;
        Ok(())
    }
}

fn set_console_size(descriptor: RawFd, height: u16, width: u16) -> Result<()> {
    let size = libc::winsize {
        ws_row: height,
        ws_col: width,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(descriptor, libc::TIOCSWINSZ, &size) } == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn wait_foreground(
    init_pid: Pid,
    signal_set: &SigSet,
    console: Option<&ConsoleForwarder>,
) -> Result<i32> {
    loop {
        match signal_set.wait()? {
            signal::SIGCHLD => loop {
                match waitpid(None, Some(WaitPidFlag::WNOHANG))? {
                    WaitStatus::Exited(pid, status) if pid == init_pid => return Ok(status),
                    WaitStatus::Signaled(pid, signal, _) if pid == init_pid => {
                        return Ok(128 + signal as i32);
                    }
                    WaitStatus::StillAlive => break,
                    _ => {}
                }
            },
            signal::SIGWINCH => {
                if let Some(console) = console {
                    console.resize();
                }
            }
            caught => {
                let _ = signal::kill(init_pid, caught);
            }
        }
    }
}

fn ensure_supported_cgroup_manager(manager: CgroupManager) -> Result<()> {
    if manager == CgroupManager::Disabled {
        Ok(())
    } else {
        bail!("unsupported cgroup manager")
    }
}

pub fn dispatch(command: &crate::cli::Command, global: &GlobalOptions) -> Result<i32> {
    match command {
        crate::cli::Command::List(options) => list(options, global),
        crate::cli::Command::Run(options) => run(options, global),
        crate::cli::Command::Exec(options) => match exec(options, global) {
            Ok(code) => Ok(code),
            Err(error) => {
                if let Some(child_error) = error.downcast_ref::<ExecChildError>() {
                    tracing::error!(
                        target: crate::logging::FATAL_TARGET,
                        function = "exec_child_process",
                        compat_pid = child_error.pid,
                        "child process error: {}",
                        child_error.message
                    );
                    tracing::error!(
                        function = "exec",
                        "failed to exec: {}",
                        child_error.parent_message
                    );
                } else {
                    tracing::error!(function = "exec", "failed to exec: {error:#}");
                }
                Ok(1)
            }
        },
        crate::cli::Command::Kill(options) => kill(options, global),
    }
}

pub fn state_exists(root: &Path, id: &str) -> bool {
    runtime_root(root).join(id).join("state.json").exists()
}

fn runtime_root(root: &Path) -> std::path::PathBuf {
    root.join(INTERNAL_RUNTIME_DIRECTORY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_runtime_only_supports_disabled_cgroups() {
        ensure_supported_cgroup_manager(CgroupManager::Disabled).unwrap();
        assert!(ensure_supported_cgroup_manager(CgroupManager::Cgroupfs).is_err());
        assert!(ensure_supported_cgroup_manager(CgroupManager::Systemd).is_err());
    }

    #[test]
    fn child_error_pipe_preserves_pid_and_message() {
        let (error_read, error_write) = pipe2(OFlag::O_CLOEXEC).unwrap();
        let mut writer = File::from(error_write);
        writer.write_all(&7_i32.to_ne_bytes()).unwrap();
        writer.write_all(b"X").unwrap();
        writer.write_all(b"execvpe: Permission denied").unwrap();
        drop(writer);

        let report = read_child_error(error_read).unwrap().unwrap();
        assert_eq!(report.pid, 7);
        assert_eq!(report.stage, ChildErrorStage::ExecFailure);
        assert_eq!(report.message, "execvpe: Permission denied");
    }

    #[test]
    fn child_error_pipe_rejects_truncated_reports() {
        let (error_read, error_write) = pipe2(OFlag::O_CLOEXEC).unwrap();
        let mut writer = File::from(error_write);
        writer.write_all(&[1, 2, 3]).unwrap();
        drop(writer);

        assert_eq!(
            read_child_error(error_read).unwrap_err().to_string(),
            "truncated child error report"
        );
    }

    #[test]
    fn child_error_pipe_does_not_block_while_writer_is_open() {
        let (error_read, _error_write) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).unwrap();
        assert!(read_child_error(error_read).unwrap().is_none());
    }
}
