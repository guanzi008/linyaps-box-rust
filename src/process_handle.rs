use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

static PIDFD_SUPPORTED: AtomicBool = AtomicBool::new(true);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Running,
    Sleeping,
    DiskSleep,
    Stopped,
    TracingStop,
    Dead,
    Zombie,
    Parked,
    Idle,
    Unknown,
}

impl ProcessState {
    fn from_byte(value: u8) -> Self {
        match value {
            b'R' => Self::Running,
            b'S' => Self::Sleeping,
            b'D' => Self::DiskSleep,
            b'T' => Self::Stopped,
            b't' => Self::TracingStop,
            b'X' => Self::Dead,
            b'Z' => Self::Zombie,
            b'P' => Self::Parked,
            b'I' => Self::Idle,
            _ => Self::Unknown,
        }
    }

    pub fn is_dead(self) -> bool {
        matches!(self, Self::Dead | Self::Zombie)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessStat {
    pub state: ProcessState,
    pub start_time: u64,
}

pub struct ProcessHandle {
    pid: i32,
    proc_fd: OwnedFd,
    pidfd: Option<OwnedFd>,
}

impl ProcessHandle {
    pub fn open(pid: i32) -> io::Result<Self> {
        if pid < 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let path = CString::new(format!("/proc/{pid}"))
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if descriptor == -1 {
            let error = io::Error::last_os_error();
            return Err(if error.raw_os_error() == Some(libc::ENOENT) {
                io::Error::from_raw_os_error(libc::ESRCH)
            } else {
                error
            });
        }
        let proc_fd = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let pidfd = if PIDFD_SUPPORTED.load(Ordering::Relaxed) {
            let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if descriptor >= 0 {
                Some(unsafe { OwnedFd::from_raw_fd(descriptor as i32) })
            } else {
                if io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
                    PIDFD_SUPPORTED.store(false, Ordering::Relaxed);
                }
                None
            }
        } else {
            None
        };
        Ok(Self {
            pid,
            proc_fd,
            pidfd,
        })
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn status(&self) -> io::Result<ProcessStat> {
        let descriptor = unsafe {
            libc::openat(
                self.proc_fd.as_raw_fd(),
                c"stat".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let mut content = Vec::with_capacity(1024);
        file.read_to_end(&mut content)?;
        parse_proc_stat(&content)
    }

    pub fn send_signal(&self, signal: i32) -> io::Result<()> {
        if let Some(pidfd) = self.pidfd.as_ref() {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if result == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(error)
            };
        }

        if self.status()?.state.is_dead() {
            return Err(io::Error::from_raw_os_error(libc::ESRCH));
        }
        if unsafe { libc::kill(self.pid, signal) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }
}

pub(crate) fn parse_proc_stat(content: &[u8]) -> io::Result<ProcessStat> {
    let closing_parenthesis = content
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    let remainder = &content[closing_parenthesis + 1..];
    let state_position = remainder
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    let state = ProcessState::from_byte(remainder[state_position]);
    let start_time = remainder[state_position + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .nth(18)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    let start_time = std::str::from_utf8(start_time)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    Ok(ProcessStat { state, start_time })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_state_and_start_time_after_complex_process_name() {
        let fields = (1..=19)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let content = format!("42 (name with ) parenthesis) Z {fields}\n");
        assert_eq!(
            parse_proc_stat(content.as_bytes()).unwrap(),
            ProcessStat {
                state: ProcessState::Zombie,
                start_time: 19,
            }
        );
    }

    #[test]
    fn rejects_incomplete_process_status() {
        assert_eq!(
            parse_proc_stat(b"42 (demo) R 1 2")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn reads_current_process_through_pinned_proc_directory() {
        let handle = ProcessHandle::open(std::process::id() as i32).unwrap();
        let status = handle.status().unwrap();
        assert!(!status.state.is_dead());
        assert_ne!(status.start_time, 0);
    }
}
