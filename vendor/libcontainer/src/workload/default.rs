use std::collections::HashMap;
use std::ffi::CString;

use libc::c_char;
use oci_spec::runtime::Spec;

use super::{Executor, ExecutorError, ExecutorSetEnvsError, ExecutorValidationError};

#[derive(Clone)]
pub struct DefaultExecutor {}

impl Executor for DefaultExecutor {
    fn exec(&self, spec: &Spec) -> Result<(), ExecutorError> {
        tracing::debug!("executing workload with default handler");
        let process = spec.process().as_ref().ok_or(ExecutorError::InvalidArg)?;
        let args = process.args().as_ref().ok_or(ExecutorError::InvalidArg)?;
        let executable = args.first().ok_or(ExecutorError::InvalidArg)?;

        let executable = c_string_prefix(executable);
        let arguments = args
            .iter()
            .map(|argument| c_string_prefix(argument))
            .collect::<Vec<_>>();
        let environment = process
            .env()
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|variable| c_string_prefix(variable))
            .collect::<Vec<_>>();
        let argument_pointers = null_terminated_pointers(&arguments);
        let environment_pointers = null_terminated_pointers(&environment);

        unsafe {
            libc::execvpe(
                executable.as_ptr(),
                argument_pointers.as_ptr(),
                environment_pointers.as_ptr(),
            );
        }

        let error = std::io::Error::last_os_error();
        tracing::error!(?error, filename = ?executable, args = ?arguments, "failed to execvpe");
        let description = error.raw_os_error().map_or_else(
            || error.to_string(),
            |errno| {
                let pointer = unsafe { libc::strerror(errno) };
                if pointer.is_null() {
                    error.to_string()
                } else {
                    unsafe { std::ffi::CStr::from_ptr(pointer) }
                        .to_string_lossy()
                        .into_owned()
                }
            },
        );
        Err(ExecutorError::Other(format!("execvpe: {description}")))
    }

    fn validate(&self, _spec: &Spec) -> Result<(), ExecutorValidationError> {
        Ok(())
    }

    fn setup_envs(&self, _envs: HashMap<String, String>) -> Result<(), ExecutorSetEnvsError> {
        Ok(())
    }
}

pub fn get_executor() -> Box<dyn Executor> {
    Box::new(DefaultExecutor {})
}

fn c_string_prefix(value: &str) -> CString {
    let bytes = value.as_bytes();
    let prefix = bytes
        .iter()
        .position(|byte| *byte == 0)
        .map_or(bytes, |index| &bytes[..index]);
    CString::new(prefix).expect("a NUL-free prefix always converts to CString")
}

fn null_terminated_pointers(values: &[CString]) -> Vec<*const c_char> {
    values
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::env;

    use serial_test::serial;

    use super::*;

    #[test]
    fn c_strings_match_c_str_truncation() {
        assert_eq!(c_string_prefix("abc").to_bytes(), b"abc");
        assert_eq!(c_string_prefix("abc\0def").to_bytes(), b"abc");
        assert!(c_string_prefix("\0def").to_bytes().is_empty());
    }

    #[test]
    fn exec_vectors_preserve_order_and_duplicates() {
        let values = ["DUP=first", "DUP=second", "EMPTY="]
            .map(c_string_prefix)
            .to_vec();
        let pointers = null_terminated_pointers(&values);

        assert_eq!(values[0].to_bytes(), b"DUP=first");
        assert_eq!(values[1].to_bytes(), b"DUP=second");
        assert_eq!(values[2].to_bytes(), b"EMPTY=");
        assert!(pointers.last().is_some_and(|pointer| pointer.is_null()));
    }

    #[test]
    #[serial]
    fn setup_envs_does_not_modify_runtime_environment() {
        const NAME: &str = "LINYAPS_BOX_EXECUTOR_ENV_TEST";
        let original = env::var_os(NAME);
        unsafe { env::set_var(NAME, "host") };

        let executor = get_executor();
        executor
            .setup_envs(HashMap::from([(NAME.to_owned(), "container".to_owned())]))
            .expect("default executor setup is a no-op");
        assert_eq!(env::var(NAME).as_deref(), Ok("host"));

        match original {
            Some(value) => unsafe { env::set_var(NAME, value) },
            None => unsafe { env::remove_var(NAME) },
        }
    }
}
