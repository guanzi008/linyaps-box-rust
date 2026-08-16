use std::path::Path;

use crate::syscall::Syscall;
use crate::syscall::syscall::create_syscall;

#[derive(Debug, thiserror::Error)]
pub enum SymlinkError {
    #[error("syscall failed")]
    Syscall {
        source: crate::syscall::SyscallError,
    },
    #[error("failed symlink: {msg}")]
    Other { msg: String },
}

type Result<T> = std::result::Result<T, SymlinkError>;

pub struct Symlink {
    syscall: Box<dyn Syscall>,
}

impl Default for Symlink {
    fn default() -> Self {
        Self::new()
    }
}

impl Symlink {
    pub fn new() -> Symlink {
        Symlink::with_syscall(create_syscall())
    }

    fn with_syscall(syscall: Box<dyn Syscall>) -> Symlink {
        Symlink { syscall }
    }

    // Create symlinks for subsystems that have been comounted e.g. cpu -> cpu,cpuacct, cpuacct -> cpu,cpuacct
    #[cfg(feature = "v1")]
    pub fn setup_comount_symlinks(&self, cgroup_root: &Path, subsystem_name: &str) -> Result<()> {
        if !subsystem_name.contains(',') {
            return Ok(());
        }

        for comount in subsystem_name.split_terminator(',') {
            let link = cgroup_root.join(comount);
            self.syscall
                .symlink(Path::new(subsystem_name), &link)
                .map_err(|err| {
                    tracing::error!("failed to symlink {link:?} to {subsystem_name:?}");
                    SymlinkError::Syscall { source: err }
                })?;
        }

        Ok(())
    }

    pub fn setup_default_symlinks(&self, rootfs: &Path) -> Result<()> {
        let defaults = [
            ("/proc/self/fd", "dev/fd"),
            ("/proc/self/fd/0", "dev/stdin"),
            ("/proc/self/fd/1", "dev/stdout"),
            ("/proc/self/fd/2", "dev/stderr"),
        ];
        for (src, dst) in defaults {
            self.syscall
                .symlink(Path::new(src), &rootfs.join(dst))
                .map_err(|err| {
                    tracing::error!("failed to symlink defaults");
                    SymlinkError::Syscall { source: err }
                })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "v1")]
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    #[cfg(feature = "v1")]
    use crate::syscall::linux::LinuxSyscall;
    use crate::syscall::test::TestHelperSyscall;
    #[cfg(feature = "v1")]
    use anyhow::{Context, Result};

    #[test]
    fn test_setup_default_symlinks() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let symlink = Symlink::new();
        assert!(symlink.setup_default_symlinks(tmp_dir.path()).is_ok());
        let want = vec![
            (
                PathBuf::from("/proc/self/fd"),
                tmp_dir.path().join("dev/fd"),
            ),
            (
                PathBuf::from("/proc/self/fd/0"),
                tmp_dir.path().join("dev/stdin"),
            ),
            (
                PathBuf::from("/proc/self/fd/1"),
                tmp_dir.path().join("dev/stdout"),
            ),
            (
                PathBuf::from("/proc/self/fd/2"),
                tmp_dir.path().join("dev/stderr"),
            ),
        ];
        let got = symlink
            .syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
            .get_symlink_args();
        assert_eq!(want, got)
    }

    #[test]
    #[cfg(feature = "v1")]
    fn setup_comounted_symlinks_success() -> Result<()> {
        // arrange
        let tmp = tempfile::tempdir().unwrap();
        let cpu = tmp.path().join("cpu");
        let cpuacct = tmp.path().join("cpuacct");
        let cpu_cpuacct = tmp.path().join("cpu,cpuacct");
        fs::create_dir_all(cpu_cpuacct)?;
        let symlink = Symlink::with_syscall(Box::new(LinuxSyscall));

        // act
        symlink
            .setup_comount_symlinks(tmp.path(), "cpu,cpuacct")
            .context("failed to setup symlinks")?;

        // assert
        assert!(cpu.exists(), "cpu symlink does not exist");
        assert!(cpuacct.exists(), "cpuacct symlink does not exist");

        assert!(
            fs::symlink_metadata(&cpu)?.file_type().is_symlink(),
            "cpu is not a symlink"
        );
        assert!(
            fs::symlink_metadata(&cpuacct)?.file_type().is_symlink(),
            "cpuacct is not a symlink"
        );

        assert_eq!(
            fs::read_link(cpu)?,
            PathBuf::from("cpu,cpuacct"),
            "cpu does not link to cpu,cpuacct"
        );
        assert_eq!(
            fs::read_link(cpuacct)?,
            PathBuf::from("cpu,cpuacct"),
            "cpuacct does not link to cpu,cpuacct"
        );

        Ok(())
    }

    #[test]
    #[cfg(feature = "v1")]
    fn setup_comounted_symlinks_no_comounts() -> Result<()> {
        // arrange
        let tmp = tempfile::tempdir().unwrap();
        let symlink = Symlink::with_syscall(Box::new(LinuxSyscall));

        // act
        let result = symlink
            .setup_comount_symlinks(tmp.path(), "memory,task")
            .context("failed to setup symlinks");

        // assert
        assert!(result.is_ok());
        Ok(())
    }
}
