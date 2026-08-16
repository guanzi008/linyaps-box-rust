use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use libc::c_char;
use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, send, socketpair};
use nix::unistd::Pid;
use oci_spec::runtime::{ContainerState as OciContainerState, Hook, State as OciState};

use crate::container::{State, StateConversionError};

const HOOK_ORIGINAL_BUNDLE_ANNOTATION: &str = "cn.org.linyaps.internal.hook-state.original-bundle";
const HOOK_CREATED_ANNOTATION: &str = "cn.org.linyaps.internal.hook-state.created";
const HOOK_OWNER_ANNOTATION: &str = "cn.org.linyaps.internal.hook-state.owner";
const LINYAPS_OCI_VERSION: &str = "1.3.0";

#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("hook {} {source}", path.display())]
    Hook {
        path: PathBuf,
        #[source]
        source: Box<HookError>,
    },
    #[error("failed to execute hook command")]
    CommandExecute(#[source] std::io::Error),
    #[error("failed to encode container state")]
    EncodeContainerState(#[source] serde_json::Error),
    #[error("failed with exit code {0}")]
    NonZeroExitCode(i32),
    #[error("terminated by signal {0}")]
    Killed(i32),
    #[error("container state is required to run hook")]
    MissingContainerState,
    #[error("failed to convert state to OCI format")]
    StateConversion(#[from] StateConversionError),
}

type Result<T> = std::result::Result<T, HookError>;

pub fn run_hooks(
    hooks: Option<&Vec<Hook>>,
    state: Option<&State>,
    _cwd: Option<&Path>,
    pid: Option<Pid>,
    _default_env: Option<&HashMap<String, String>>,
) -> Result<()> {
    let base_state = state.ok_or(HookError::MissingContainerState)?;
    let mut oci_state = OciState::try_from(base_state)?;
    oci_state.set_version(LINYAPS_OCI_VERSION.to_string());
    if *oci_state.status() == OciContainerState::Creating {
        oci_state.set_status(OciContainerState::Created);
    }

    let metadata = base_state.annotations.as_ref();
    if let Some(bundle) = metadata.and_then(|values| values.get(HOOK_ORIGINAL_BUNDLE_ANNOTATION)) {
        oci_state.set_bundle(bundle.into());
    }
    oci_state.set_annotations(Some(HashMap::new()));
    if let Some(override_pid) = pid {
        oci_state.set_pid(Some(override_pid.as_raw()));
    } else if oci_state.pid().is_none()
        && let Some(outermost_pid) = current_outermost_pid()
    {
        oci_state.set_pid(Some(outermost_pid));
    }

    let created = metadata
        .and_then(|values| values.get(HOOK_CREATED_ANNOTATION))
        .cloned()
        .unwrap_or_default();
    let owner = metadata
        .and_then(|values| values.get(HOOK_OWNER_ANNOTATION))
        .cloned()
        .unwrap_or_default();
    let mut hook_state =
        serde_json::to_value(&oci_state).map_err(HookError::EncodeContainerState)?;
    let hook_state = hook_state
        .as_object_mut()
        .expect("OCI state serializes as an object");
    hook_state.insert("created".to_string(), serde_json::Value::String(created));
    hook_state.insert("owner".to_string(), serde_json::Value::String(owner));
    let encoded_state = serde_json::to_vec(&hook_state).map_err(HookError::EncodeContainerState)?;

    if let Some(hooks) = hooks {
        for hook in hooks {
            execute_hook(hook, &encoded_state).map_err(|source| HookError::Hook {
                path: hook.path().to_path_buf(),
                source: Box::new(source),
            })?;
        }
    }
    Ok(())
}

pub fn run_poststop_hooks(hooks: Option<&Vec<Hook>>, state: Option<&State>) {
    let Some(hooks) = hooks else {
        return;
    };
    for hook in hooks {
        if let Err(error) = run_hooks(Some(&vec![hook.clone()]), state, None, None, None) {
            tracing::error!(
                target: "linyaps_box::compat",
                function = "poststop_hooks",
                "execute poststop hook {} failed: {error}",
                hook.path().display()
            );
        }
    }
}

fn execute_hook(hook: &Hook, state: &[u8]) -> Result<()> {
    let executable = c_string_prefix(hook.path().as_os_str().as_bytes());
    let arguments = hook
        .args()
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|argument| c_string_prefix(argument.as_bytes()))
        .collect::<Vec<_>>();
    let environment = hook
        .env()
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|variable| c_string_prefix(variable.as_bytes()))
        .collect::<Vec<_>>();
    let argument_pointers = null_terminated_pointers(&arguments);
    let environment_pointers = null_terminated_pointers(&environment);
    let (hook_stdin, state_sender) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(nix_error)?;
    let (exec_error_reader, exec_error_writer) = exec_error_pipe()?;

    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(HookError::CommandExecute(std::io::Error::last_os_error()));
    }
    if pid == 0 {
        drop(exec_error_reader);
        drop(state_sender);
        let stdin_fd = hook_stdin.as_raw_fd();
        if unsafe { libc::dup2(stdin_fd, libc::STDIN_FILENO) } == -1 {
            unsafe { libc::_exit(libc::EXIT_FAILURE) };
        }
        drop(hook_stdin);
        unsafe {
            libc::execvpe(
                executable.as_ptr(),
                argument_pointers.as_ptr(),
                environment_pointers.as_ptr(),
            );
            let errno = *libc::__errno_location();
            libc::write(
                exec_error_writer.as_raw_fd(),
                (&errno as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>(),
            );
            libc::_exit(libc::EXIT_FAILURE);
        }
    }

    drop(exec_error_writer);
    drop(hook_stdin);
    if let Err(error) = send(state_sender.as_raw_fd(), state, MsgFlags::empty()) {
        tracing::warn!(?error, "failed to write state to hook stdin");
    }
    drop(state_sender);

    let status = wait_for_hook(pid, hook.timeout())?;
    if let Some(errno) = read_exec_error(exec_error_reader.as_raw_fd()) {
        tracing::error!(
            target: "linyaps_box::compat",
            function = "execute_hook",
            compat_pid = pid,
            errno,
            "execute hook {} failed",
            hook_command(hook)
        );
    }
    if libc::WIFEXITED(status) {
        let exit_code = libc::WEXITSTATUS(status);
        return if exit_code == 0 {
            Ok(())
        } else {
            Err(HookError::NonZeroExitCode(exit_code))
        };
    }
    if libc::WIFSIGNALED(status) {
        return Err(HookError::Killed(libc::WTERMSIG(status)));
    }
    Ok(())
}

fn exec_error_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(HookError::CommandExecute(std::io::Error::last_os_error()));
    }
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

fn read_exec_error(descriptor: RawFd) -> Option<libc::c_int> {
    let mut errno = 0;
    loop {
        let bytes_read = unsafe {
            libc::read(
                descriptor,
                (&mut errno as *mut libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>(),
            )
        };
        if bytes_read == std::mem::size_of::<libc::c_int>() as isize {
            return Some(errno);
        }
        if bytes_read == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return None;
    }
}

fn hook_command(hook: &Hook) -> String {
    std::iter::once(hook.path().to_string_lossy().into_owned())
        .chain(hook.args().as_deref().unwrap_or(&[]).iter().cloned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn wait_for_hook(pid: libc::pid_t, timeout: Option<i64>) -> Result<libc::c_int> {
    let mut status = 0;
    let Some(timeout) = timeout else {
        loop {
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result >= 0 {
                return Ok(status);
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR | libc::EAGAIN) => continue,
                _ => {
                    return Err(HookError::CommandExecute(std::io::Error::last_os_error()));
                }
            }
        }
    };

    let mut signal_mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut signal_mask);
        libc::sigaddset(&mut signal_mask, libc::SIGCHLD);
    }
    let duration = libc::timespec {
        tv_sec: timeout,
        tv_nsec: 0,
    };
    loop {
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let signal = unsafe { libc::sigtimedwait(&signal_mask, &mut info, &duration) };
        if signal >= 0 {
            if unsafe { info.si_pid() } != pid {
                continue;
            }
            if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
                return Err(HookError::CommandExecute(std::io::Error::last_os_error()));
            }
            return Ok(status);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EAGAIN) => {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, &mut status, 0);
                }
                return Ok(status);
            }
            Some(libc::EINTR) => continue,
            _ => return Err(HookError::CommandExecute(std::io::Error::last_os_error())),
        }
    }
}

fn current_outermost_pid() -> Option<i32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn c_string_prefix(value: &[u8]) -> CString {
    let prefix = value
        .iter()
        .position(|byte| *byte == 0)
        .map_or(value, |index| &value[..index]);
    CString::new(prefix).expect("a NUL-free prefix always converts to CString")
}

fn null_terminated_pointers(values: &[CString]) -> Vec<*const c_char> {
    values
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

fn nix_error(error: nix::errno::Errno) -> HookError {
    HookError::CommandExecute(std::io::Error::from_raw_os_error(error as i32))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use nix::sys::signal::{SigSet, SigmaskHow, pthread_sigmask};
    use oci_spec::runtime::HookBuilder;
    use serial_test::serial;

    use super::*;
    use crate::container::Container;

    fn shell_hook(script: &str, arguments: &[&str], environment: Option<Vec<String>>) -> Hook {
        let mut args = vec![
            "sh".to_string(),
            "-c".to_string(),
            script.to_string(),
            "sh".to_string(),
        ];
        args.extend(arguments.iter().map(|argument| (*argument).to_string()));
        let mut builder = HookBuilder::default().path("/bin/sh").args(args);
        if let Some(environment) = environment {
            builder = builder.env(environment);
        }
        builder.build().expect("build hook")
    }

    #[test]
    #[serial]
    fn hook_receives_frozen_state_and_empty_default_environment() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let state_path = directory.path().join("state.json");
        let env_path = directory.path().join("env.txt");
        let hook = shell_hook(
            "cat > \"$1\"; if [ -z \"${TEST_ENV+x}\" ]; then printf empty > \"$2\"; fi",
            &[state_path.to_str().unwrap(), env_path.to_str().unwrap()],
            None,
        );
        let mut default_env = HashMap::new();
        default_env.insert("TEST_ENV".to_string(), "ignored".to_string());
        let container = Container::default();

        run_hooks(
            Some(&vec![hook]),
            Some(&container.state),
            None,
            Some(Pid::from_raw(1234)),
            Some(&default_env),
        )?;

        let state: serde_json::Value = serde_json::from_slice(&fs::read(state_path)?)?;
        assert_eq!(state["ociVersion"], LINYAPS_OCI_VERSION);
        assert_eq!(state["pid"], 1234);
        assert_eq!(state["created"], "");
        assert_eq!(state["owner"], "");
        assert_eq!(state["annotations"], serde_json::json!({}));
        assert_eq!(fs::read_to_string(env_path)?, "empty");
        Ok(())
    }

    #[test]
    #[serial]
    fn hook_ignores_requested_working_directory() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("cwd.txt");
        let requested = directory.path().join("requested");
        fs::create_dir(&requested)?;
        let hook = shell_hook("pwd > \"$1\"", &[output.to_str().unwrap()], None);
        let container = Container::default();
        let expected = std::env::current_dir()?;

        run_hooks(
            Some(&vec![hook]),
            Some(&container.state),
            Some(&requested),
            None,
            None,
        )?;

        assert_eq!(
            fs::read_to_string(output)?.trim(),
            expected.to_str().unwrap()
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn hook_timeout_reports_sigkill() -> Result<()> {
        let hook = HookBuilder::default()
            .path("/bin/sh")
            .args(vec!["sh".into(), "-c".into(), "sleep 30".into()])
            .timeout(1)
            .build()?;
        let container = Container::default();
        let mut old_mask = SigSet::empty();
        let mut child_mask = SigSet::empty();
        child_mask.add(nix::sys::signal::SIGCHLD);
        pthread_sigmask(
            SigmaskHow::SIG_BLOCK,
            Some(&child_mask),
            Some(&mut old_mask),
        )?;
        let result = run_hooks(Some(&vec![hook]), Some(&container.state), None, None, None);
        pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&old_mask), None)?;

        assert!(matches!(
            result,
            Err(HookError::Hook { source, .. })
                if matches!(*source, HookError::Killed(libc::SIGKILL))
        ));
        Ok(())
    }

    #[test]
    fn hook_vectors_preserve_order_duplicates_and_empty_argv() {
        let environment =
            ["DUP=first", "DUP=second", "EMPTY="].map(|value| c_string_prefix(value.as_bytes()));
        let pointers = null_terminated_pointers(&environment);
        assert_eq!(environment[0].to_bytes(), b"DUP=first");
        assert_eq!(environment[1].to_bytes(), b"DUP=second");
        assert!(pointers.last().is_some_and(|pointer| pointer.is_null()));
        assert_eq!(null_terminated_pointers(&[]), vec![std::ptr::null()]);
    }

    #[test]
    fn hook_command_matches_frozen_diagnostic() {
        let hook = HookBuilder::default()
            .path("/definitely-missing-hook")
            .args(vec!["missing-hook".into(), "arg".into()])
            .build()
            .unwrap();

        assert_eq!(
            hook_command(&hook),
            "/definitely-missing-hook missing-hook arg"
        );
    }
}
