//! Converts OCI runtime signal arguments into Linux signal numbers.

use std::convert::TryFrom;

use nix::sys::signal::Signal as NixSignal;

/// Linux signal number, including signal 0 and real-time signals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signal(i32);

#[derive(Debug, thiserror::Error)]
pub enum SignalError<T> {
    #[error("invalid signal: {0}")]
    InvalidSignal(T),
    #[error("signal number out of range: {0}")]
    SignalNumberOutOfRange(T),
}

fn signal_limit() -> i32 {
    libc::SIGRTMAX() + 1
}

impl TryFrom<&str> for Signal {
    type Error = SignalError<String>;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'-')
        {
            if let Ok(number) = value.parse::<i32>() {
                return Signal::try_from(number).map_err(|error| match error {
                    SignalError::InvalidSignal(_) => SignalError::InvalidSignal(value.to_string()),
                    SignalError::SignalNumberOutOfRange(_) => {
                        SignalError::SignalNumberOutOfRange(value.to_string())
                    }
                });
            }
        }

        let name = value.strip_prefix("SIG").unwrap_or(value);
        let number = match name {
            "ABRT" | "IOT" => libc::SIGABRT,
            "ALRM" => libc::SIGALRM,
            "BUS" => libc::SIGBUS,
            "CHLD" | "CLD" => libc::SIGCHLD,
            "CONT" => libc::SIGCONT,
            "FPE" => libc::SIGFPE,
            "HUP" => libc::SIGHUP,
            "ILL" => libc::SIGILL,
            "INT" => libc::SIGINT,
            "IO" | "POLL" => libc::SIGIO,
            "KILL" => libc::SIGKILL,
            "PIPE" => libc::SIGPIPE,
            "PROF" => libc::SIGPROF,
            "PWR" => libc::SIGPWR,
            "QUIT" => libc::SIGQUIT,
            "SEGV" => libc::SIGSEGV,
            "STOP" => libc::SIGSTOP,
            "SYS" => libc::SIGSYS,
            "TERM" => libc::SIGTERM,
            "TRAP" => libc::SIGTRAP,
            "TSTP" => libc::SIGTSTP,
            "TTIN" => libc::SIGTTIN,
            "TTOU" => libc::SIGTTOU,
            "URG" => libc::SIGURG,
            "USR1" => libc::SIGUSR1,
            "USR2" => libc::SIGUSR2,
            "VTALRM" => libc::SIGVTALRM,
            "WINCH" => libc::SIGWINCH,
            "XCPU" => libc::SIGXCPU,
            "XFSZ" => libc::SIGXFSZ,
            _ => return Err(SignalError::InvalidSignal(value.to_string())),
        };
        Ok(Signal(number))
    }
}

impl TryFrom<i32> for Signal {
    type Error = SignalError<i32>;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        if (0..signal_limit()).contains(&value) {
            Ok(Signal(value))
        } else {
            Err(SignalError::SignalNumberOutOfRange(value))
        }
    }
}

impl From<NixSignal> for Signal {
    fn from(signal: NixSignal) -> Self {
        Signal(signal as i32)
    }
}

impl Signal {
    pub fn into_raw(self) -> i32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_frozen_upstream_signal_names() {
        let test_sets = [
            (libc::SIGABRT, &["ABRT", "IOT", "SIGABRT", "SIGIOT"][..]),
            (libc::SIGALRM, &["ALRM", "SIGALRM"]),
            (libc::SIGBUS, &["BUS", "SIGBUS"]),
            (libc::SIGCHLD, &["CHLD", "CLD", "SIGCHLD", "SIGCLD"]),
            (libc::SIGCONT, &["CONT", "SIGCONT"]),
            (libc::SIGFPE, &["FPE", "SIGFPE"]),
            (libc::SIGHUP, &["HUP", "SIGHUP"]),
            (libc::SIGILL, &["ILL", "SIGILL"]),
            (libc::SIGINT, &["INT", "SIGINT"]),
            (libc::SIGIO, &["IO", "POLL", "SIGIO", "SIGPOLL"]),
            (libc::SIGKILL, &["KILL", "SIGKILL"]),
            (libc::SIGPIPE, &["PIPE", "SIGPIPE"]),
            (libc::SIGPROF, &["PROF", "SIGPROF"]),
            (libc::SIGPWR, &["PWR", "SIGPWR"]),
            (libc::SIGQUIT, &["QUIT", "SIGQUIT"]),
            (libc::SIGSEGV, &["SEGV", "SIGSEGV"]),
            (libc::SIGSTOP, &["STOP", "SIGSTOP"]),
            (libc::SIGSYS, &["SYS", "SIGSYS"]),
            (libc::SIGTERM, &["TERM", "SIGTERM"]),
            (libc::SIGTRAP, &["TRAP", "SIGTRAP"]),
            (libc::SIGTSTP, &["TSTP", "SIGTSTP"]),
            (libc::SIGTTIN, &["TTIN", "SIGTTIN"]),
            (libc::SIGTTOU, &["TTOU", "SIGTTOU"]),
            (libc::SIGURG, &["URG", "SIGURG"]),
            (libc::SIGUSR1, &["USR1", "SIGUSR1"]),
            (libc::SIGUSR2, &["USR2", "SIGUSR2"]),
            (libc::SIGVTALRM, &["VTALRM", "SIGVTALRM"]),
            (libc::SIGWINCH, &["WINCH", "SIGWINCH"]),
            (libc::SIGXCPU, &["XCPU", "SIGXCPU"]),
            (libc::SIGXFSZ, &["XFSZ", "SIGXFSZ"]),
        ];

        for (expected, names) in test_sets {
            for name in names {
                assert_eq!(expected, Signal::try_from(*name).unwrap().into_raw());
            }
        }
    }

    #[test]
    fn preserves_numeric_signal_values() {
        for number in [0, 1, 5, 7, 31, libc::SIGRTMIN(), libc::SIGRTMAX()] {
            assert_eq!(
                number,
                Signal::try_from(number.to_string().as_str())
                    .unwrap()
                    .into_raw()
            );
        }
    }

    #[test]
    fn rejects_invalid_or_out_of_range_signals() {
        assert!(matches!(
            Signal::try_from("invalid"),
            Err(SignalError::InvalidSignal(_))
        ));
        assert!(matches!(
            Signal::try_from("sigterm"),
            Err(SignalError::InvalidSignal(_))
        ));
        assert!(matches!(
            Signal::try_from("+1"),
            Err(SignalError::InvalidSignal(_))
        ));
        assert!(matches!(
            Signal::try_from("-1"),
            Err(SignalError::SignalNumberOutOfRange(_))
        ));
        assert!(matches!(
            Signal::try_from(signal_limit().to_string().as_str()),
            Err(SignalError::SignalNumberOutOfRange(_))
        ));
    }
}
