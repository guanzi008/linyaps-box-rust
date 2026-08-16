use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{IoSlice, IoSliceMut, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use libcontainer::syscall::syscall::create_syscall;
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::pty::openpty;
use nix::sys::signal::SigSet;
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
    connect, recvmsg, sendmsg, socket, socketpair,
};
use nix::unistd::{ForkResult, Pid, fork};
use serde_json::Value;

use crate::capability;
use crate::cli::ExecOptions;

const MESSAGE_PID: u8 = b'P';
const MESSAGE_PROCEED: u8 = b'G';
const MESSAGE_CONSOLE: u8 = b'T';
const MESSAGE_READY: u8 = b'R';
const MESSAGE_ERROR: u8 = b'E';

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ExecUser {
    uid: u32,
    gid: u32,
    umask: Option<u32>,
    additional_gids: Option<Vec<u32>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ExecCapabilities {
    effective: Option<Vec<String>>,
    bounding: Option<Vec<String>>,
    inheritable: Option<Vec<String>>,
    permitted: Option<Vec<String>>,
    ambient: Option<Vec<String>>,
}

impl ExecCapabilities {
    fn is_empty(&self) -> bool {
        [
            self.effective.as_ref(),
            self.bounding.as_ref(),
            self.inheritable.as_ref(),
            self.permitted.as_ref(),
            self.ambient.as_ref(),
        ]
        .into_iter()
        .all(|set| set.is_none_or(Vec::is_empty))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecRlimit {
    resource: libc::__rlimit_resource_t,
    soft: u64,
    hard: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ExecProcess {
    terminal: Option<bool>,
    console_size: Option<(u16, u16)>,
    cwd: PathBuf,
    env: Option<Vec<String>>,
    args: Vec<String>,
    rlimits: Option<Vec<ExecRlimit>>,
    capabilities: Option<ExecCapabilities>,
    no_new_privileges: Option<bool>,
    user: ExecUser,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamespaceType {
    Ipc,
    Uts,
    Mount,
    Pid,
    Network,
    User,
    Cgroup,
    Time,
}

impl NamespaceType {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "ipc" => Ok(Self::Ipc),
            "uts" => Ok(Self::Uts),
            "mount" => Ok(Self::Mount),
            "pid" => Ok(Self::Pid),
            "network" => Ok(Self::Network),
            "user" => Ok(Self::User),
            "cgroup" => Ok(Self::Cgroup),
            "time" => Ok(Self::Time),
            _ => bail!("unknown namespace type: {value}"),
        }
    }

    fn proc_name(self) -> &'static str {
        match self {
            Self::Ipc => "ipc",
            Self::Uts => "uts",
            Self::Mount => "mnt",
            Self::Pid => "pid",
            Self::Network => "net",
            Self::User => "user",
            Self::Cgroup => "cgroup",
            Self::Time => "time",
        }
    }

    fn config_name(self) -> &'static str {
        match self {
            Self::Ipc => "ipc",
            Self::Uts => "uts",
            Self::Mount => "mount",
            Self::Pid => "pid",
            Self::Network => "network",
            Self::User => "user",
            Self::Cgroup => "cgroup",
            Self::Time => "time",
        }
    }
}

pub(crate) struct SpawnedExec {
    pub(crate) pid: Pid,
    pub(crate) console: Option<OwnedFd>,
    pub(crate) signal_set: SigSet,
}

#[derive(Debug)]
pub(crate) struct ExecChildError {
    pub(crate) pid: i32,
    pub(crate) message: String,
    pub(crate) parent_message: &'static str,
}

impl std::fmt::Display for ExecChildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ExecChildError {}

pub(crate) fn spawn(
    target_pid: i32,
    config_path: &Path,
    options: &ExecOptions,
) -> Result<SpawnedExec> {
    let config: Value = serde_json::from_slice(
        &fs::read(config_path)
            .with_context(|| format!("failed to open config file: {}", config_path.display()))?,
    )
    .with_context(|| format!("failed to parse config file: {}", config_path.display()))?;
    let config_process = config
        .get("process")
        .filter(|value| !value.is_null())
        .map(parse_process)
        .transpose()?;
    let process_override = options
        .process
        .as_deref()
        .map(read_process_file)
        .transpose()?;
    let override_has_terminal = process_override
        .as_ref()
        .is_some_and(|process| process.terminal.is_some());
    let process = resolve_process(config_process.as_ref(), process_override, options);
    let namespaces = parse_namespaces(&config)?;
    let external_console =
        if options.console_socket.is_some() && (options.tty || override_has_terminal) {
            options
                .console_socket
                .as_deref()
                .map(connect_console_socket)
                .transpose()?
        } else {
            None
        };

    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error()).context("set child subreaper");
    }

    let (parent_channel, child_channel) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )?;

    match unsafe { fork() }? {
        ForkResult::Child => {
            drop(parent_channel);
            drop(external_console);
            child_entry(
                target_pid,
                &config_process,
                &process,
                &namespaces,
                options.preserve_fds,
                child_channel,
            );
        }
        ForkResult::Parent { .. } => drop(child_channel),
    }

    let result = parent_handshake(
        parent_channel,
        process.terminal.unwrap_or(false),
        external_console.as_ref(),
    );
    match result {
        Ok(result) => Ok(result),
        Err((error, pid)) => {
            if let Some(pid) = pid {
                unsafe {
                    libc::kill(pid.as_raw(), libc::SIGKILL);
                    libc::waitpid(pid.as_raw(), std::ptr::null_mut(), 0);
                }
            }
            Err(error)
        }
    }
}

fn read_process_file(path: &Path) -> Result<ExecProcess> {
    let value: Value = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("cannot open process file: {}", path.display()))?,
    )
    .context("cannot parse process file")?;
    parse_process(&value)
}

fn resolve_process(
    config_process: Option<&ExecProcess>,
    process_override: Option<ExecProcess>,
    options: &ExecOptions,
) -> ExecProcess {
    let mut process = process_override
        .or_else(|| config_process.cloned())
        .unwrap_or_default();
    if let Some(cwd) = options.cwd.as_ref() {
        process.cwd = cwd.clone();
    }
    if process.cwd.as_os_str().is_empty() {
        process.cwd = PathBuf::from("/");
    }
    if options.tty {
        process.terminal = Some(true);
    }
    if options.no_new_privileges {
        process.no_new_privileges = Some(true);
    }
    if !options.env.is_empty() {
        process
            .env
            .get_or_insert_with(Vec::new)
            .extend(options.env.iter().cloned());
    }
    if !options.command.is_empty() {
        process.args.clone_from(&options.command);
    }
    if let Some(user) = options.user {
        process.user.uid = user.uid;
        process.user.gid = user.gid;
    }
    if !options.capabilities.is_empty() {
        let capabilities = process.capabilities.get_or_insert_with(Default::default);
        capabilities.effective = Some(options.capabilities.clone());
        capabilities.ambient = Some(options.capabilities.clone());
        capabilities.bounding = Some(options.capabilities.clone());
        capabilities.permitted = Some(options.capabilities.clone());
    }
    process
}

fn parse_process(value: &Value) -> Result<ExecProcess> {
    let object = value.as_object().context("process must be an object")?;
    let terminal = optional_bool(object.get("terminal"), "process.terminal")?;
    let console_size = if terminal == Some(true) {
        object
            .get("consoleSize")
            .filter(|value| !value.is_null())
            .map(parse_console_size)
            .transpose()?
    } else {
        None
    };
    let cwd = PathBuf::from(
        object
            .get("cwd")
            .and_then(Value::as_str)
            .context("process.cwd is required")?,
    );
    let env = optional_string_array(object.get("env"), "process.env")?;
    let args = string_array(
        object.get("args").context("process.args is required")?,
        "process.args",
    )?;
    let rlimits = object
        .get("rlimits")
        .filter(|value| !value.is_null())
        .map(parse_rlimits)
        .transpose()?;
    let capabilities = object
        .get("capabilities")
        .filter(|value| !value.is_null())
        .map(parse_capabilities)
        .transpose()?;
    let no_new_privileges =
        optional_bool(object.get("noNewPrivileges"), "process.noNewPrivileges")?;
    let user = object
        .get("user")
        .filter(|value| !value.is_null())
        .map(parse_user)
        .transpose()?
        .unwrap_or_default();

    validate_ignored_process_fields(object)?;
    Ok(ExecProcess {
        terminal,
        console_size,
        cwd,
        env,
        args,
        rlimits,
        capabilities,
        no_new_privileges,
        user,
    })
}

fn validate_ignored_process_fields(object: &serde_json::Map<String, Value>) -> Result<()> {
    for field in ["apparmorProfile", "selinuxLabel"] {
        if let Some(value) = object.get(field).filter(|value| !value.is_null()) {
            value
                .as_str()
                .with_context(|| format!("process.{field} must be a string"))?;
        }
    }
    if let Some(value) = object.get("oomScoreAdj").filter(|value| !value.is_null()) {
        let value = value
            .as_i64()
            .context("process.oomScoreAdj must be an integer")?;
        i32::try_from(value).context("process.oomScoreAdj is out of range")?;
    }
    if let Some(value) = object.get("scheduler").filter(|value| !value.is_null()) {
        parse_scheduler(value)?;
    }
    if let Some(value) = object.get("ioPriority").filter(|value| !value.is_null()) {
        parse_io_priority(value)?;
    }
    if let Some(value) = object
        .get("execCPUAffinity")
        .filter(|value| !value.is_null())
    {
        parse_exec_cpu_affinity(value)?;
    }
    Ok(())
}

fn parse_scheduler(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .context("process.scheduler must be an object")?;
    let policy = object
        .get("policy")
        .and_then(Value::as_str)
        .context("scheduler.policy is required")?;
    if !matches!(
        policy,
        "SCHED_OTHER"
            | "SCHED_FIFO"
            | "SCHED_RR"
            | "SCHED_BATCH"
            | "SCHED_ISO"
            | "SCHED_IDLE"
            | "SCHED_DEADLINE"
    ) {
        bail!("unknown value: {policy}");
    }
    for field in ["nice", "priority"] {
        if let Some(value) = object.get(field).filter(|value| !value.is_null()) {
            let value = value
                .as_i64()
                .with_context(|| format!("scheduler.{field} must be an integer"))?;
            i32::try_from(value).with_context(|| format!("scheduler.{field} is out of range"))?;
        }
    }
    if let Some(flags) = object.get("flags").filter(|value| !value.is_null()) {
        for flag in flags
            .as_array()
            .context("scheduler.flags must be an array")?
        {
            let flag = flag
                .as_str()
                .context("scheduler.flags entries must be strings")?;
            if !matches!(
                flag,
                "SCHED_FLAG_RESET_ON_FORK"
                    | "SCHED_FLAG_RECLAIM"
                    | "SCHED_FLAG_DL_OVERRUN"
                    | "SCHED_FLAG_KEEP_POLICY"
                    | "SCHED_FLAG_KEEP_PARAMS"
                    | "SCHED_FLAG_UTIL_CLAMP_MIN"
                    | "SCHED_FLAG_UTIL_CLAMP_MAX"
            ) {
                bail!("unknown value: {flag}");
            }
        }
    }
    for field in ["runtime", "deadline", "period"] {
        if let Some(value) = object.get(field).filter(|value| !value.is_null()) {
            value
                .as_u64()
                .with_context(|| format!("scheduler.{field} must be an unsigned integer"))?;
        }
    }
    Ok(())
}

fn parse_io_priority(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .context("process.ioPriority must be an object")?;
    let class = object
        .get("class")
        .and_then(Value::as_str)
        .context("ioPriority.class is required")?;
    if !matches!(
        class,
        "IOPRIO_CLASS_RT" | "IOPRIO_CLASS_BE" | "IOPRIO_CLASS_IDLE"
    ) {
        bail!("unknown value: {class}");
    }
    if let Some(priority) = object.get("priority") {
        let priority = priority
            .as_i64()
            .context("ioPriority.priority must be an integer")?;
        i32::try_from(priority).context("ioPriority.priority is out of range")?;
    }
    Ok(())
}

fn parse_exec_cpu_affinity(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .context("process.execCPUAffinity must be an object")?;
    for field in ["initial", "final"] {
        if let Some(value) = object.get(field).filter(|value| !value.is_null()) {
            value
                .as_str()
                .with_context(|| format!("execCPUAffinity.{field} must be a string"))?;
        }
    }
    Ok(())
}

fn parse_console_size(value: &Value) -> Result<(u16, u16)> {
    let object = value
        .as_object()
        .context("process.consoleSize must be an object")?;
    let height = required_u32(object.get("height"), "process.consoleSize.height")?;
    let width = required_u32(object.get("width"), "process.consoleSize.width")?;
    Ok((
        u16::try_from(height).context("process.consoleSize.height is out of range")?,
        u16::try_from(width).context("process.consoleSize.width is out of range")?,
    ))
}

fn parse_user(value: &Value) -> Result<ExecUser> {
    let object = value
        .as_object()
        .context("process.user must be an object")?;
    let additional_gids = object
        .get("additionalGids")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_array()
                .context("process.user.additionalGids must be an array")?
                .iter()
                .map(|value| {
                    let value = value
                        .as_u64()
                        .context("process.user.additionalGids entries must be unsigned integers")?;
                    u32::try_from(value)
                        .context("process.user.additionalGids entry is out of range")
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    let umask = object
        .get("umask")
        .filter(|value| !value.is_null())
        .map(|value| {
            let value = value
                .as_u64()
                .context("process.user.umask must be an unsigned integer")?;
            u32::try_from(value).context("process.user.umask is out of range")
        })
        .transpose()?;
    Ok(ExecUser {
        uid: required_u32(object.get("uid"), "process.user.uid")?,
        gid: required_u32(object.get("gid"), "process.user.gid")?,
        umask,
        additional_gids,
    })
}

fn parse_capabilities(value: &Value) -> Result<ExecCapabilities> {
    let object = value
        .as_object()
        .context("process.capabilities must be an object")?;
    Ok(ExecCapabilities {
        effective: optional_string_array(object.get("effective"), "capabilities.effective")?,
        bounding: optional_string_array(object.get("bounding"), "capabilities.bounding")?,
        inheritable: optional_string_array(object.get("inheritable"), "capabilities.inheritable")?,
        permitted: optional_string_array(object.get("permitted"), "capabilities.permitted")?,
        ambient: optional_string_array(object.get("ambient"), "capabilities.ambient")?,
    })
}

fn parse_rlimits(value: &Value) -> Result<Vec<ExecRlimit>> {
    value
        .as_array()
        .context("process.rlimits must be an array")?
        .iter()
        .map(|entry| {
            let object = entry.as_object().context("rlimit must be an object")?;
            let kind = object
                .get("type")
                .and_then(Value::as_str)
                .context("rlimit.type is required")?;
            Ok(ExecRlimit {
                resource: rlimit_resource(kind)?,
                soft: required_u64(object.get("soft"), "rlimit.soft")?,
                hard: required_u64(object.get("hard"), "rlimit.hard")?,
            })
        })
        .collect()
}

fn rlimit_resource(kind: &str) -> Result<libc::__rlimit_resource_t> {
    match kind {
        "RLIMIT_AS" => Ok(libc::RLIMIT_AS),
        "RLIMIT_CORE" => Ok(libc::RLIMIT_CORE),
        "RLIMIT_CPU" => Ok(libc::RLIMIT_CPU),
        "RLIMIT_DATA" => Ok(libc::RLIMIT_DATA),
        "RLIMIT_FSIZE" => Ok(libc::RLIMIT_FSIZE),
        "RLIMIT_LOCKS" => Ok(libc::RLIMIT_LOCKS),
        "RLIMIT_MEMLOCK" => Ok(libc::RLIMIT_MEMLOCK),
        "RLIMIT_MSGQUEUE" => Ok(libc::RLIMIT_MSGQUEUE),
        "RLIMIT_NICE" => Ok(libc::RLIMIT_NICE),
        "RLIMIT_NOFILE" => Ok(libc::RLIMIT_NOFILE),
        "RLIMIT_NPROC" => Ok(libc::RLIMIT_NPROC),
        "RLIMIT_RSS" => Ok(libc::RLIMIT_RSS),
        "RLIMIT_RTPRIO" => Ok(libc::RLIMIT_RTPRIO),
        "RLIMIT_RTTIME" => Ok(libc::RLIMIT_RTTIME),
        "RLIMIT_SIGPENDING" => Ok(libc::RLIMIT_SIGPENDING),
        "RLIMIT_STACK" => Ok(libc::RLIMIT_STACK),
        _ => bail!("unknown value: {kind}"),
    }
}

fn optional_bool(value: Option<&Value>, field: &str) -> Result<Option<bool>> {
    value
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_bool()
                .with_context(|| format!("{field} must be a boolean"))
        })
        .transpose()
}

fn optional_string_array(value: Option<&Value>, field: &str) -> Result<Option<Vec<String>>> {
    value
        .filter(|value| !value.is_null())
        .map(|value| string_array(value, field))
        .transpose()
}

fn string_array(value: &Value, field: &str) -> Result<Vec<String>> {
    value
        .as_array()
        .with_context(|| format!("{field} must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .with_context(|| format!("{field} entries must be strings"))
        })
        .collect()
}

fn required_u32(value: Option<&Value>, field: &str) -> Result<u32> {
    let value = required_u64(value, field)?;
    u32::try_from(value).with_context(|| format!("{field} is out of range"))
}

fn required_u64(value: Option<&Value>, field: &str) -> Result<u64> {
    value
        .and_then(Value::as_u64)
        .with_context(|| format!("{field} is required"))
}

fn parse_namespaces(config: &Value) -> Result<Vec<NamespaceType>> {
    let Some(namespaces) = config
        .pointer("/linux/namespaces")
        .filter(|value| !value.is_null())
    else {
        return Ok(Vec::new());
    };
    namespaces
        .as_array()
        .context("linux.namespaces must be an array")?
        .iter()
        .map(|namespace| {
            let object = namespace
                .as_object()
                .context("linux namespace must be an object")?;
            NamespaceType::parse(
                object
                    .get("type")
                    .and_then(Value::as_str)
                    .context("linux namespace type is required")?,
            )
        })
        .collect()
}

fn connect_console_socket(path: &Path) -> Result<OwnedFd> {
    let socket_fd = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    let address = UnixAddr::new(path)
        .with_context(|| format!("invalid console socket path: {}", path.display()))?;
    connect(socket_fd.as_raw_fd(), &address)
        .with_context(|| format!("failed to connect console socket: {}", path.display()))?;
    Ok(socket_fd)
}

fn child_entry(
    target_pid: i32,
    config_process: &Option<ExecProcess>,
    process: &ExecProcess,
    namespaces: &[NamespaceType],
    preserve_fds: i32,
    channel: OwnedFd,
) -> ! {
    let result = (|| -> Result<()> {
        join_namespaces(target_pid, namespaces)?;
        if namespaces.contains(&NamespaceType::Pid) {
            match unsafe { fork() }? {
                ForkResult::Parent { child } => {
                    send_pid(channel.as_raw_fd(), child)?;
                    unsafe { libc::_exit(0) }
                }
                ForkResult::Child => {}
            }
        } else {
            send_pid(channel.as_raw_fd(), Pid::this())?;
        }

        expect_proceed(channel.as_raw_fd())?;
        if unsafe { libc::setsid() } == -1 {
            return Err(std::io::Error::last_os_error()).context("setsid");
        }
        if process.terminal.is_some() {
            setup_terminal(channel.as_raw_fd(), process.console_size)?;
        }
        apply_environment(process, config_process.as_ref())?;
        apply_rlimits(process)?;
        create_syscall()
            .close_range(preserve_fds)
            .context("close_range")?;
        apply_credentials(process)?;
        if process.no_new_privileges.is_some()
            && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1
        {
            return Err(std::io::Error::last_os_error()).context("set no new privileges");
        }
        apply_capabilities(process, config_process.as_ref())?;
        let cwd = c_string(process.cwd.as_os_str().as_bytes());
        if unsafe { libc::chdir(cwd.as_ptr()) } == -1 {
            return Err(std::io::Error::last_os_error()).context("chdir");
        }
        send_packet(channel.as_raw_fd(), &[MESSAGE_READY], None)?;
        exec_process(process)?;
        Ok(())
    })();
    if let Err(error) = result {
        let text = compatibility_child_error(&error);
        let mut message = Vec::with_capacity(5 + text.len());
        message.push(MESSAGE_ERROR);
        message.extend_from_slice(&Pid::this().as_raw().to_ne_bytes());
        message.extend_from_slice(text.as_bytes());
        let _ = send_packet(channel.as_raw_fd(), &message, None);
    }
    unsafe { libc::_exit(1) }
}

fn compatibility_child_error(error: &anyhow::Error) -> String {
    let Some(errno) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .and_then(std::io::Error::raw_os_error)
    else {
        return format!("{error:#}");
    };
    let pointer = unsafe { libc::strerror(errno) };
    let description = if pointer.is_null() {
        std::io::Error::from_raw_os_error(errno).to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    };
    let error = error.to_string();
    if matches!(
        error.as_str(),
        "set keep capabilities"
            | "clear ambient capabilities"
            | "raise ambient capability"
            | "set no new privileges"
    ) {
        return description;
    }
    format!("{error}: {description}")
}

fn join_namespaces(target_pid: i32, namespaces: &[NamespaceType]) -> Result<()> {
    let descriptors = namespaces
        .iter()
        .copied()
        .map(|kind| {
            let path = format!("/proc/{target_pid}/ns/{}", kind.proc_name());
            let path = CString::new(path).expect("proc namespace path has no NUL");
            let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if descriptor == -1 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("open namespace {}", kind.proc_name()));
            }
            Ok((kind, unsafe { OwnedFd::from_raw_fd(descriptor) }))
        })
        .collect::<Result<Vec<_>>>()?;

    if let Some((kind, descriptor)) = descriptors
        .iter()
        .find(|(kind, _)| *kind == NamespaceType::User)
    {
        set_namespace(descriptor.as_raw_fd(), *kind, false)?;
    }
    for (kind, descriptor) in &descriptors {
        if *kind != NamespaceType::User {
            set_namespace(descriptor.as_raw_fd(), *kind, true)?;
        }
    }
    Ok(())
}

fn set_namespace(descriptor: RawFd, kind: NamespaceType, ignore_unsupported: bool) -> Result<()> {
    if unsafe { libc::setns(descriptor, 0) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if ignore_unsupported && error.raw_os_error() == Some(libc::EINVAL) {
        tracing::warn!(
            function = "join_container_namespaces",
            "setns for {} not supported",
            kind.config_name()
        );
        return Ok(());
    }
    Err(error).with_context(|| format!("setns for {}", kind.proc_name()))
}

fn setup_terminal(channel: RawFd, console_size: Option<(u16, u16)>) -> Result<()> {
    let pty = openpty(None, None)?;
    set_cloexec(pty.master.as_raw_fd())?;
    set_cloexec(pty.slave.as_raw_fd())?;
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if unsafe { libc::dup2(pty.slave.as_raw_fd(), target) } == -1 {
            return Err(std::io::Error::last_os_error()).context("set up terminal stdio");
        }
    }
    unsafe {
        libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCSCTTY, 0);
    }
    if let Some((height, width)) = console_size {
        let mut size = libc::winsize {
            ws_row: height,
            ws_col: width,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if height == 0 || width == 0 {
            let tty = CString::new("/dev/tty").unwrap();
            let descriptor = unsafe { libc::open(tty.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
            if descriptor == -1 {
                return Err(std::io::Error::last_os_error()).context("open /dev/tty");
            }
            let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
            unsafe {
                libc::ioctl(descriptor.as_raw_fd(), libc::TIOCGWINSZ, &mut size);
            }
        }
        unsafe {
            libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCSWINSZ, &size);
        }
    }
    send_packet(channel, &[MESSAGE_CONSOLE], Some(pty.master.as_raw_fd()))
}

fn set_cloexec(descriptor: RawFd) -> Result<()> {
    let flags = FdFlag::from_bits_truncate(fcntl(descriptor, FcntlArg::F_GETFD)?);
    fcntl(descriptor, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
    Ok(())
}

fn apply_environment(process: &ExecProcess, config_process: Option<&ExecProcess>) -> Result<()> {
    if unsafe { libc::clearenv() } != 0 {
        return Err(std::io::Error::last_os_error()).context("clearenv");
    }
    for environment in [
        config_process.and_then(|process| process.env.as_ref()),
        process.env.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        for entry in environment {
            if invalid_environment(entry) {
                continue;
            }
            let (key, value) = entry.split_once('=').expect("validated environment entry");
            let key = c_string(key.as_bytes());
            let value = c_string(value.as_bytes());
            unsafe {
                libc::setenv(key.as_ptr(), value.as_ptr(), 1);
            }
        }
    }
    Ok(())
}

fn invalid_environment(value: &str) -> bool {
    value.as_bytes().contains(&0) || value.split_once('=').is_none_or(|(key, _)| key.is_empty())
}

fn apply_rlimits(process: &ExecProcess) -> Result<()> {
    let Some(rlimits) = process.rlimits.as_ref() else {
        return Ok(());
    };
    for rlimit in rlimits {
        let limit = libc::rlimit {
            rlim_cur: rlimit.soft as libc::rlim_t,
            rlim_max: rlimit.hard as libc::rlim_t,
        };
        if unsafe { libc::setrlimit(rlimit.resource, &limit) } == -1 {
            return Err(std::io::Error::last_os_error()).context("setrlimit");
        }
    }
    Ok(())
}

fn apply_credentials(process: &ExecProcess) -> Result<()> {
    if let Some(mask) = process.user.umask {
        unsafe {
            libc::umask(mask as libc::mode_t);
        }
    }
    if process.user.uid == 0 && process.user.gid == 0 && process.user.additional_gids.is_none() {
        return Ok(());
    }
    if unsafe { libc::setresgid(process.user.gid, process.user.gid, process.user.gid) } == -1 {
        return Err(std::io::Error::last_os_error()).context("setresgid");
    }
    if let Some(groups) = process.user.additional_gids.as_ref()
        && unsafe { libc::setgroups(groups.len(), groups.as_ptr()) } == -1
    {
        return Err(std::io::Error::last_os_error()).context("setgroups");
    }
    if unsafe { libc::setresuid(process.user.uid, process.user.uid, process.user.uid) } == -1 {
        return Err(std::io::Error::last_os_error()).context("setresuid");
    }
    for descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if unsafe { libc::fchown(descriptor, process.user.uid, process.user.gid) } == -1 {
            let error = std::io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS)) {
                return Err(error).context("fchown stdio");
            }
        }
    }
    Ok(())
}

fn apply_capabilities(process: &ExecProcess, config_process: Option<&ExecProcess>) -> Result<()> {
    let capabilities = match process.capabilities.as_ref() {
        None => config_process.and_then(|process| process.capabilities.as_ref()),
        Some(capabilities) if capabilities.is_empty() => {
            config_process.and_then(|process| process.capabilities.as_ref())
        }
        Some(capabilities) => Some(capabilities),
    };
    let Some(capabilities) = capabilities.filter(|capabilities| !capabilities.is_empty()) else {
        return Ok(());
    };

    if let Some(bounding) = capabilities.bounding.as_ref() {
        let bounding = parse_capability_set(bounding)?;
        let mut last_capability = String::new();
        File::open("/proc/sys/kernel/cap_last_cap")
            .and_then(|mut file| file.read_to_string(&mut last_capability))
            .ok();
        let last_capability = last_capability.trim().parse::<u32>().unwrap_or(0);
        for capability in 0..last_capability {
            if !bounding.contains(&(capability as u8))
                && unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } == -1
            {
                return Err(std::io::Error::last_os_error()).context("cap_drop_bound");
            }
        }
    }

    let effective = capability_mask(capabilities.effective.as_deref().unwrap_or_default())?;
    let permitted = capability_mask(capabilities.permitted.as_deref().unwrap_or_default())?;
    let inheritable = capability_mask(capabilities.inheritable.as_deref().unwrap_or_default())?;
    set_base_capabilities(effective, permitted, inheritable)?;
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error()).context("set keep capabilities");
    }
    set_base_capabilities(effective, permitted, inheritable)?;
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error()).context("clear ambient capabilities");
    }
    for capability in capabilities.ambient.as_deref().unwrap_or_default() {
        let capability = parse_capability(capability)?;
        if unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_RAISE,
                capability as libc::c_uint,
                0,
                0,
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error()).context("raise ambient capability");
        }
    }
    Ok(())
}

fn parse_capability_set(values: &[String]) -> Result<HashSet<u8>> {
    values.iter().map(|value| parse_capability(value)).collect()
}

fn capability_mask(values: &[String]) -> Result<u64> {
    values.iter().try_fold(0_u64, |mask, value| {
        Ok(mask | (1_u64 << parse_capability(value)?))
    })
}

fn parse_capability(value: &str) -> Result<u8> {
    capability::parse_index(value).with_context(|| format!("unknown capability: {value}"))
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn set_base_capabilities(effective: u64, permitted: u64, inheritable: u64) -> Result<()> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapabilityData {
            effective: effective as u32,
            permitted: permitted as u32,
            inheritable: inheritable as u32,
        },
        CapabilityData {
            effective: (effective >> 32) as u32,
            permitted: (permitted >> 32) as u32,
            inheritable: (inheritable >> 32) as u32,
        },
    ];
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error()).context("cap_set_proc");
    }
    Ok(())
}

fn exec_process(process: &ExecProcess) -> Result<()> {
    let executable = process
        .args
        .first()
        .context("process.args must not be empty")?;
    let arguments = process
        .args
        .iter()
        .map(|argument| c_string(argument.as_bytes()))
        .collect::<Vec<_>>();
    let mut argument_pointers = arguments
        .iter()
        .map(|argument| argument.as_ptr())
        .collect::<Vec<_>>();
    argument_pointers.push(std::ptr::null());
    let environment = process
        .env
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|entry| c_string(entry.as_bytes()))
        .collect::<Vec<_>>();
    let mut environment_pointers = environment
        .iter()
        .map(|entry| entry.as_ptr())
        .collect::<Vec<_>>();
    environment_pointers.push(std::ptr::null());
    let executable = c_string(executable.as_bytes());
    unsafe {
        libc::execvpe(
            executable.as_ptr(),
            argument_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        );
    }
    Err(std::io::Error::last_os_error()).context("execvpe")
}

fn c_string(bytes: &[u8]) -> CString {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    CString::new(&bytes[..end]).expect("truncated byte string has no NUL")
}

fn send_pid(channel: RawFd, pid: Pid) -> Result<()> {
    let mut message = [0_u8; 5];
    message[0] = MESSAGE_PID;
    message[1..].copy_from_slice(&pid.as_raw().to_ne_bytes());
    send_packet(channel, &message, None)
}

fn expect_proceed(channel: RawFd) -> Result<()> {
    let message = receive_packet(channel)?.context("socket closed before receiving proceed")?;
    if message.payload == [MESSAGE_PROCEED] && message.descriptor.is_none() {
        Ok(())
    } else {
        bail!("unexpected message while waiting for proceed")
    }
}

fn parent_handshake(
    channel: OwnedFd,
    expect_console: bool,
    external_console: Option<&OwnedFd>,
) -> std::result::Result<SpawnedExec, (anyhow::Error, Option<Pid>)> {
    let pid = match receive_packet(channel.as_raw_fd()) {
        Ok(Some(message)) if message.payload.len() == 5 && message.payload[0] == MESSAGE_PID => {
            Pid::from_raw(i32::from_ne_bytes(
                message.payload[1..5].try_into().unwrap(),
            ))
        }
        Ok(Some(message)) => {
            return Err((
                message_error(
                    message,
                    "expected pid_report during exec",
                    "child process exited before sending expected message",
                ),
                None,
            ));
        }
        Ok(None) => {
            return Err((
                anyhow!("child process exited before sending expected message"),
                None,
            ));
        }
        Err(error) => return Err((error, None)),
    };

    let signal_set = SigSet::all();
    if let Err(error) = signal_set.thread_block() {
        return Err((error.into(), Some(pid)));
    }
    if let Err(error) = send_packet(channel.as_raw_fd(), &[MESSAGE_PROCEED], None) {
        return Err((error, Some(pid)));
    }

    let mut console = None;
    if expect_console {
        match receive_packet(channel.as_raw_fd()) {
            Ok(Some(message))
                if message.payload == [MESSAGE_CONSOLE] && message.descriptor.is_some() =>
            {
                let descriptor = message.descriptor.unwrap();
                if let Some(external_console) = external_console {
                    if let Err(error) = send_packet(
                        external_console.as_raw_fd(),
                        &[0],
                        Some(descriptor.as_raw_fd()),
                    ) {
                        return Err((error, Some(pid)));
                    }
                } else {
                    console = Some(descriptor);
                }
            }
            Ok(Some(message)) => {
                return Err((
                    message_error(
                        message,
                        "expected console_fd during exec",
                        "child process exited before sending expected message",
                    ),
                    Some(pid),
                ));
            }
            Ok(None) => {
                return Err((
                    anyhow!("child process exited before sending expected message"),
                    Some(pid),
                ));
            }
            Err(error) => return Err((error, Some(pid))),
        }
    }

    match receive_packet(channel.as_raw_fd()) {
        Ok(Some(message)) if message.payload == [MESSAGE_READY] && message.descriptor.is_none() => {
        }
        Ok(Some(message)) => {
            return Err((
                message_error(
                    message,
                    "unexpected message during wait_for_stage",
                    "container process exited before reaching expected stage exec_ready",
                ),
                Some(pid),
            ));
        }
        Ok(None) => {
            return Err((
                anyhow!("container process exited before reaching expected stage exec_ready"),
                Some(pid),
            ));
        }
        Err(error) => return Err((error, Some(pid))),
    }
    match receive_packet(channel.as_raw_fd()) {
        Ok(None) => Ok(SpawnedExec {
            pid,
            console,
            signal_set,
        }),
        Ok(Some(message)) => Err((
            message_error(
                message,
                "unexpected message after exec_ready",
                "container process failed during exec: Success",
            ),
            Some(pid),
        )),
        Err(error) => Err((error, Some(pid))),
    }
}

fn message_error(
    message: Packet,
    unexpected: &'static str,
    child_parent_message: &'static str,
) -> anyhow::Error {
    if message.payload.first() == Some(&MESSAGE_ERROR) && message.payload.len() >= 5 {
        let pid = i32::from_ne_bytes(message.payload[1..5].try_into().unwrap());
        let text = String::from_utf8_lossy(&message.payload[5..]);
        anyhow!(ExecChildError {
            pid,
            message: text.into_owned(),
            parent_message: child_parent_message,
        })
    } else {
        anyhow!(unexpected)
    }
}

struct Packet {
    payload: Vec<u8>,
    descriptor: Option<OwnedFd>,
}

fn send_packet(channel: RawFd, payload: &[u8], descriptor: Option<RawFd>) -> Result<()> {
    let slices = [IoSlice::new(payload)];
    let descriptors = descriptor.into_iter().collect::<Vec<_>>();
    let controls = if descriptors.is_empty() {
        Vec::new()
    } else {
        vec![ControlMessage::ScmRights(&descriptors)]
    };
    let sent = sendmsg::<()>(channel, &slices, &controls, MsgFlags::empty(), None)?;
    if sent != payload.len() {
        bail!("short write on message channel")
    }
    Ok(())
}

fn receive_packet(channel: RawFd) -> Result<Option<Packet>> {
    let length = unsafe {
        libc::recv(
            channel,
            std::ptr::null_mut(),
            0,
            libc::MSG_PEEK | libc::MSG_TRUNC,
        )
    };
    if length == 0 {
        return Ok(None);
    }
    if length == -1 {
        let error = Errno::last();
        if matches!(error, Errno::ECONNRESET | Errno::ENOTCONN | Errno::EPIPE) {
            return Ok(None);
        }
        return Err(error.into());
    }
    let mut payload = vec![0_u8; length as usize];
    let mut slices = [IoSliceMut::new(&mut payload)];
    let mut control = nix::cmsg_space!([RawFd; 1]);
    let (bytes, descriptor) = {
        let message = recvmsg::<()>(
            channel,
            &mut slices,
            Some(&mut control),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )?;
        if message
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
        {
            bail!("truncated message channel packet")
        }
        let mut descriptor = None;
        for control in message.cmsgs()? {
            if let ControlMessageOwned::ScmRights(descriptors) = control {
                for raw in descriptors {
                    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                    if descriptor.is_none() {
                        descriptor = Some(owned);
                    }
                }
            }
        }
        (message.bytes, descriptor)
    };
    payload.truncate(bytes);
    Ok(Some(Packet {
        payload,
        descriptor,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::UserSpec;

    fn options() -> ExecOptions {
        ExecOptions {
            user: None,
            cwd: None,
            env: Vec::new(),
            console_socket: None,
            tty: false,
            preserve_fds: 0,
            capabilities: Vec::new(),
            no_new_privileges: false,
            process: None,
            container: "demo".to_string(),
            command: Vec::new(),
        }
    }

    #[test]
    fn process_parser_preserves_optional_boolean_presence() {
        let process = parse_process(&serde_json::json!({
            "terminal": false,
            "consoleSize": {"height": "ignored"},
            "cwd": "/",
            "args": ["true"],
            "noNewPrivileges": false
        }))
        .unwrap();
        assert_eq!(process.terminal, Some(false));
        assert_eq!(process.console_size, None);
        assert_eq!(process.no_new_privileges, Some(false));
    }

    #[test]
    fn process_file_parses_but_does_not_validate_noop_fields() {
        parse_process(&serde_json::json!({
            "cwd": "relative",
            "args": [],
            "scheduler": {"policy": "SCHED_OTHER", "priority": 7},
            "execCPUAffinity": {"initial": "not-a-cpu-list"}
        }))
        .unwrap();
        assert!(
            parse_process(&serde_json::json!({
                "cwd": "/",
                "args": ["true"],
                "scheduler": {"policy": "UNKNOWN"}
            }))
            .is_err()
        );
    }

    #[test]
    fn command_overrides_keep_inheritable_capabilities() {
        let base = parse_process(&serde_json::json!({
            "cwd": "/old",
            "args": ["old"],
            "capabilities": {"inheritable": ["CAP_CHOWN"]},
            "user": {"uid": 1, "gid": 2}
        }))
        .unwrap();
        let mut options = options();
        options.command = vec!["new".to_string()];
        options.capabilities = vec!["CAP_NET_RAW".to_string()];
        options.user = Some(UserSpec { uid: 3, gid: 4 });
        let process = resolve_process(Some(&base), None, &options);
        let capabilities = process.capabilities.unwrap();
        assert_eq!(capabilities.inheritable.unwrap(), ["CAP_CHOWN"]);
        assert_eq!(capabilities.effective.unwrap(), ["CAP_NET_RAW"]);
        assert_eq!(process.user.uid, 3);
        assert_eq!(process.user.gid, 4);
        assert_eq!(process.args, ["new"]);
    }

    #[test]
    fn process_environment_is_not_merged_for_execve() {
        let config = parse_process(&serde_json::json!({
            "cwd": "/",
            "args": ["base"],
            "env": ["BASE=1", "PATH=/base"]
        }))
        .unwrap();
        let override_process = parse_process(&serde_json::json!({
            "cwd": "/",
            "args": ["exec"],
            "env": ["EXEC=1"]
        }))
        .unwrap();
        let process = resolve_process(Some(&config), Some(override_process), &options());
        assert_eq!(process.env.unwrap(), ["EXEC=1"]);
    }

    #[test]
    fn message_channel_transfers_one_descriptor() {
        let (left, right) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        let file = File::open("/dev/null").unwrap();
        send_packet(left.as_raw_fd(), b"x", Some(file.as_raw_fd())).unwrap();
        let packet = receive_packet(right.as_raw_fd()).unwrap().unwrap();
        assert_eq!(packet.payload, b"x");
        assert!(packet.descriptor.is_some());
    }

    #[test]
    fn compatibility_child_error_matches_execvpe_errno_text() {
        let error = Err::<(), _>(std::io::Error::from_raw_os_error(libc::ENOENT))
            .context("execvpe")
            .unwrap_err();
        assert_eq!(
            compatibility_child_error(&error),
            "execvpe: No such file or directory"
        );
    }

    #[test]
    fn compatibility_child_error_omits_context_for_plain_prctl_errors() {
        let error = Err::<(), _>(std::io::Error::from_raw_os_error(libc::EPERM))
            .context("raise ambient capability")
            .unwrap_err();

        assert_eq!(compatibility_child_error(&error), "Operation not permitted");
    }

    #[test]
    fn child_error_packet_preserves_pid_and_message() {
        let mut payload = vec![MESSAGE_ERROR];
        payload.extend_from_slice(&2_i32.to_ne_bytes());
        payload.extend_from_slice(b"execvpe: No such file or directory");
        let error = message_error(
            Packet {
                payload,
                descriptor: None,
            },
            "unexpected message during wait_for_stage",
            "container process failed during exec: Success",
        );
        let child_error = error.downcast_ref::<ExecChildError>().unwrap();
        assert_eq!(child_error.pid, 2);
        assert_eq!(child_error.message, "execvpe: No such file or directory");
        assert_eq!(
            child_error.parent_message,
            "container process failed during exec: Success"
        );
    }

    #[test]
    fn unexpected_packet_uses_handshake_stage_message() {
        let error = message_error(
            Packet {
                payload: vec![MESSAGE_CONSOLE],
                descriptor: None,
            },
            "unexpected message during wait_for_stage",
            "unused",
        );
        assert_eq!(
            error.to_string(),
            "unexpected message during wait_for_stage"
        );
    }
}
