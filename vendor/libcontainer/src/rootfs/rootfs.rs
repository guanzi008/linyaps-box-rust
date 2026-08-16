use std::path::Path;

use nix::mount::MsFlags;
use oci_spec::runtime::{Linux, MountBuilder, Spec};

use super::mount::{Mount, MountError, MountOptions};
use super::symlink::Symlink;
use super::{Result, RootfsError};
use crate::error::MissingSpecError;
use crate::syscall::Syscall;
use crate::syscall::syscall::create_syscall;

/// Holds information about rootfs
pub struct RootFS {
    syscall: Box<dyn Syscall>,
}

impl Default for RootFS {
    fn default() -> Self {
        Self::new()
    }
}

impl RootFS {
    pub fn new() -> RootFS {
        RootFS {
            syscall: create_syscall(),
        }
    }

    pub fn mount_to_rootfs(
        &self,
        linux: &Linux,
        spec: &Spec,
        rootfs: &Path,
        cgroup_ns: bool,
        has_mount_namespace: bool,
    ) -> Result<Mount> {
        let mounter = Mount::new();
        let global_options = MountOptions {
            root: rootfs,
            label: linux.mount_label().as_deref(),
            cgroup_ns,
        };

        if has_mount_namespace {
            let flags = rootfs_propagation(linux)?;
            self.syscall
                .mount(None, Path::new("/"), None, flags, None)
                .map_err(|err| {
                    tracing::error!(
                        ?err,
                        ?flags,
                        "failed to change the mount propagation type of the root"
                    );
                    err
                })?;

            mounter.make_parent_mount_private(rootfs)?;
            let root_mount = MountBuilder::default()
                .source(rootfs)
                .destination(".")
                .options(vec!["rbind".to_string(), "rprivate".to_string()])
                .build()
                .map_err(MountError::SpecBuild)?;
            mounter.setup_mount(&root_mount, &global_options)?;

            if spec
                .root()
                .as_ref()
                .ok_or(MissingSpecError::Root)?
                .readonly()
                .unwrap_or(false)
            {
                mounter.queue_root_readonly(rootfs)?;
            }
        }

        if let Some(mounts) = spec.mounts() {
            for mount in mounts {
                mounter.setup_mount(mount, &global_options)?;
            }
        }
        Ok(mounter)
    }

    pub fn prepare_rootfs(
        &self,
        spec: &Spec,
        rootfs: &Path,
        cgroup_ns: bool,
        has_mount_namespace: bool,
    ) -> Result<bool> {
        tracing::debug!(?rootfs, "prepare rootfs");
        if spec.mounts().as_ref().is_none_or(Vec::is_empty) {
            return Ok(false);
        }
        let linux = spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;

        let mounter = self.mount_to_rootfs(linux, spec, rootfs, cgroup_ns, has_mount_namespace)?;
        let global_options = MountOptions {
            root: rootfs,
            label: linux.mount_label().as_deref(),
            cgroup_ns,
        };

        if let Some(paths) = linux.masked_paths() {
            mounter.setup_masked_paths(paths, &global_options)?;
        }
        if let Some(paths) = linux.readonly_paths() {
            mounter.setup_readonly_paths(paths, &global_options)?;
        }

        if !mounter.mount_dev_from_host() {
            mounter.create_default_devices(&global_options)?;
            let symlinker = Symlink::new();
            mounter.ensure_dev_ptmx(&global_options)?;
            symlinker.setup_default_symlinks(rootfs)?;
        }
        mounter.finalize()?;
        Ok(true)
    }

    /// Change propagation type of rootfs as specified in spec.
    pub fn adjust_root_mount_propagation(&self, linux: &Linux) -> Result<()> {
        let flags = rootfs_propagation(linux)?;
        self.syscall
            .mount(None, Path::new("/"), None, flags, None)
            .map_err(|err| {
                tracing::error!(
                    ?err,
                    ?flags,
                    "failed to adjust the mount propagation type of the root"
                );
                err
            })?;

        Ok(())
    }
}

fn rootfs_propagation(linux: &Linux) -> Result<MsFlags> {
    match linux.rootfs_propagation().as_deref() {
        None => Ok(MsFlags::MS_PRIVATE | MsFlags::MS_REC),
        Some("private") => Ok(MsFlags::MS_PRIVATE),
        Some("rprivate") => Ok(MsFlags::MS_PRIVATE | MsFlags::MS_REC),
        Some("shared") => Ok(MsFlags::MS_SHARED),
        Some("rshared") => Ok(MsFlags::MS_SHARED | MsFlags::MS_REC),
        Some("slave") => Ok(MsFlags::MS_SLAVE),
        Some("rslave") => Ok(MsFlags::MS_SLAVE | MsFlags::MS_REC),
        Some("unbindable") => Ok(MsFlags::MS_UNBINDABLE),
        Some("runbindable") => Ok(MsFlags::MS_UNBINDABLE | MsFlags::MS_REC),
        Some(unknown) => Err(RootfsError::UnknownRootfsPropagation(unknown.to_string())),
    }
}
