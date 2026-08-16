use std::cell::{Cell, RefCell};
use std::fs;
use std::fs::{Permissions, canonicalize};
use std::io::ErrorKind;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
#[cfg(feature = "v1")]
use std::{borrow::Cow, collections::HashMap};

use libcgroups::common::CgroupSetup::{Hybrid, Legacy, Unified};
#[cfg(feature = "v1")]
use libcgroups::common::DEFAULT_CGROUP_ROOT;
use nix::fcntl::{OFlag, open, openat};
use nix::mount::MsFlags;
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::sys::statfs::{PROC_SUPER_MAGIC, statfs};
use nix::unistd::{Gid, Uid};
use oci_spec::runtime::{Mount as SpecMount, MountBuilder as SpecMountBuilder};
use pathrs::flags::{OpenFlags, RenameFlags};
#[cfg(any(feature = "v1", feature = "v2"))]
use pathrs::procfs::{ProcfsBase, ProcfsHandle};
use pathrs::{InodeType, Root};
#[cfg(feature = "v1")]
use procfs::process::Process;
#[cfg(any(feature = "v1", feature = "v2"))]
use procfs::{FromRead, ProcessCGroups};

#[cfg(feature = "v1")]
use super::symlink::Symlink;
use super::symlink::SymlinkError;
use super::utils::{MountOptionConfig, default_devices, parse_mount, to_sflag};
use crate::rootfs::utils::is_bind;
use crate::syscall::syscall::create_syscall;
use crate::syscall::{Syscall, SyscallError};
use crate::utils::PathBufExt;

#[derive(Debug, thiserror::Error)]
pub enum MountError {
    #[error("no source in mount spec")]
    NoSource,
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("syscall")]
    Syscall(#[from] crate::syscall::SyscallError),
    #[error("nix error")]
    Nix(#[from] nix::Error),
    #[error("failed to build oci spec")]
    SpecBuild(#[from] oci_spec::OciSpecError),
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
    #[error("{0}")]
    Custom(String),
    #[error("symlink")]
    Symlink(#[from] SymlinkError),
    #[error("procfs failed")]
    Procfs(#[from] procfs::ProcError),
    #[error("unknown mount option: {0}")]
    UnsupportedMountOption(String),
    #[error(transparent)]
    Pathrs(#[from] pathrs::error::Error),
}

type Result<T> = std::result::Result<T, MountError>;

#[derive(Debug)]
pub struct MountOptions<'a> {
    pub root: &'a Path,
    pub label: Option<&'a str>,
    #[allow(dead_code)]
    pub cgroup_ns: bool,
}

pub struct Mount {
    syscall: Box<dyn Syscall>,
    saw_sys_recursive_bind: Cell<bool>,
    mount_dev_from_host: Cell<bool>,
    pending_remounts: RefCell<Vec<PendingRemount>>,
}

struct PendingRemount {
    destination: OwnedFd,
    flags: MsFlags,
}

impl Default for Mount {
    fn default() -> Self {
        Self::new()
    }
}

impl Mount {
    pub fn new() -> Mount {
        Mount {
            syscall: create_syscall(),
            saw_sys_recursive_bind: Cell::new(false),
            mount_dev_from_host: Cell::new(false),
            pending_remounts: RefCell::new(Vec::new()),
        }
    }

    pub fn setup_mount(&self, mount: &SpecMount, options: &MountOptions) -> Result<()> {
        tracing::debug!("mounting {:?}", mount);
        let mount_option_config = parse_mount(mount)?;

        if mount.destination() == Path::new("/sys")
            && mount_option_config
                .flags
                .contains(MsFlags::MS_BIND | MsFlags::MS_REC)
        {
            self.saw_sys_recursive_bind.set(true);
        }
        if mount
            .typ()
            .as_deref()
            .is_some_and(|typ| typ.starts_with("cgroup"))
        {
            if mount.destination() == Path::new("/sys/fs/cgroup")
                && self.saw_sys_recursive_bind.get()
            {
                return Ok(());
            }
            return Err(MountError::Custom(
                "mount cgroup: Not implemented".to_string(),
            ));
        }

        match mount.typ().as_deref() {
            Some("cgroup") => {
                let cgroup_setup = libcgroups::common::get_cgroup_setup().map_err(|err| {
                    tracing::error!("failed to determine cgroup setup: {}", err);
                    MountError::Other(err.into())
                })?;
                match cgroup_setup {
                    Legacy | Hybrid => {
                        #[cfg(not(feature = "v1"))]
                        panic!(
                            "libcontainer can't run in a Legacy or Hybrid cgroup setup without the v1 feature"
                        );
                        #[cfg(feature = "v1")]
                        self.mount_cgroup_v1(mount, options).map_err(|err| {
                            tracing::error!("failed to mount cgroup v1: {}", err);
                            err
                        })?
                    }
                    Unified => {
                        #[cfg(not(feature = "v2"))]
                        panic!(
                            "libcontainer can't run in a Unified cgroup setup without the v2 feature"
                        );
                        #[cfg(feature = "v2")]
                        self.mount_cgroup_v2(mount, options, &mount_option_config)
                            .map_err(|err| {
                                tracing::error!("failed to mount cgroup v2: {}", err);
                                err
                            })?
                    }
                }
            }
            // procfs and sysfs are special because we need to ensure they are actually
            // mounted on a specific path in a container without any funny business.
            // Ref: https://github.com/opencontainers/runc/security/advisories/GHSA-fh74-hm69-rqjw
            Some(typ @ ("proc" | "sysfs")) => {
                let dest_path = options
                    .root
                    .join_safely(Path::new(mount.destination()).normalize())
                    .map_err(|err| {
                        tracing::error!(
                            "could not join rootfs path with mount destination {:?}: {}",
                            mount.destination(),
                            err
                        );
                        MountError::Other(err.into())
                    })?;

                match fs::symlink_metadata(&dest_path) {
                    Ok(m) if !m.is_dir() => {
                        return Err(MountError::Other(
                            format!("filesystem {} must be mounted on ordinary directory", typ)
                                .into(),
                        ));
                    }
                    Err(e) if e.kind() != ErrorKind::NotFound => {
                        return Err(MountError::Other(
                            format!("symlink_metadata failed for {}: {}", dest_path.display(), e)
                                .into(),
                        ));
                    }
                    _ => {}
                }

                self.check_proc_mount(options.root, mount)?;

                self.mount_into_container(mount, options.root, &mount_option_config, options.label)
                    .map_err(|err| {
                        tracing::error!("failed to mount {:?}: {}", mount, err);
                        err
                    })?;
            }
            _ => {
                self.mount_into_container(mount, options.root, &mount_option_config, options.label)
                    .map_err(|err| {
                        tracing::error!("failed to mount {:?}: {}", mount, err);
                        err
                    })?;
            }
        }

        if mount.destination() == Path::new("/dev") && is_bind(mount) {
            self.mount_dev_from_host.set(true);
        }

        Ok(())
    }

    pub fn mount_dev_from_host(&self) -> bool {
        self.mount_dev_from_host.get()
    }

    #[cfg(feature = "v1")]
    fn mount_cgroup_v1(&self, cgroup_mount: &SpecMount, options: &MountOptions) -> Result<()> {
        tracing::debug!("mounting cgroup v1 filesystem");
        // create tmpfs into which the cgroup subsystems will be mounted
        let tmpfs = SpecMountBuilder::default()
            .source("tmpfs")
            .typ("tmpfs")
            .destination(cgroup_mount.destination())
            .options(
                ["noexec", "nosuid", "nodev", "mode=755"]
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<String>>(),
            )
            .build()
            .map_err(|err| {
                tracing::error!("failed to build tmpfs for cgroup: {}", err);
                err
            })?;

        self.setup_mount(&tmpfs, options).map_err(|err| {
            tracing::error!("failed to mount tmpfs for cgroup: {}", err);
            err
        })?;

        // get all cgroup mounts on the host system
        let host_mounts: Vec<PathBuf> = libcgroups::v1::util::list_subsystem_mount_points()
            .map_err(|err| {
                tracing::error!("failed to get subsystem mount points: {}", err);
                MountError::Other(err.into())
            })?
            .into_iter()
            .filter(|p| p.as_path().starts_with(DEFAULT_CGROUP_ROOT))
            .collect();
        tracing::debug!("cgroup mounts: {:?}", host_mounts);

        // get process cgroups
        let ppid = std::os::unix::process::parent_id();
        // The non-zero ppid means that the PID Namespace is not separated.
        let ppid = if ppid == 0 { std::process::id() } else { ppid };
        let root_cgroups = Process::new(ppid as i32)?.cgroups()?.0;
        let process_cgroups: HashMap<String, String> =
            ProcessCGroups::from_read(ProcfsHandle::new()?.open(
                ProcfsBase::ProcSelf,
                "cgroup",
                OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
            )?)?
            .into_iter()
            .map(|c| {
                let hierarchy = c.hierarchy;
                // When youki itself is running inside a container, the cgroup path
                // will include the path of pid-1, which needs to be stripped before
                // mounting.
                let root_pathname = root_cgroups
                    .iter()
                    .find(|c| c.hierarchy == hierarchy)
                    .map(|c| c.pathname.as_ref())
                    .unwrap_or("");
                let path = c
                    .pathname
                    .strip_prefix(root_pathname)
                    .unwrap_or(&c.pathname);
                (c.controllers.join(","), path.to_owned())
            })
            .collect();
        tracing::debug!("Process cgroups: {:?}", process_cgroups);

        let cgroup_root = options
            .root
            .join_safely(cgroup_mount.destination())
            .map_err(|err| {
                tracing::error!(
                    "could not join rootfs path with cgroup mount destination: {}",
                    err
                );
                MountError::Other(err.into())
            })?;
        tracing::debug!("cgroup root: {:?}", cgroup_root);

        let symlink = Symlink::new();

        // setup cgroup mounts for container
        for host_mount in &host_mounts {
            if let Some(subsystem_name) = host_mount.file_name().and_then(|n| n.to_str()) {
                if options.cgroup_ns {
                    self.setup_namespaced_subsystem(
                        cgroup_mount,
                        options,
                        subsystem_name,
                        subsystem_name == "systemd",
                    )?;
                } else {
                    self.setup_emulated_subsystem(
                        cgroup_mount,
                        options,
                        subsystem_name,
                        subsystem_name == "systemd",
                        host_mount,
                        &process_cgroups,
                    )?;
                }

                symlink.setup_comount_symlinks(&cgroup_root, subsystem_name)?;
            } else {
                tracing::warn!("could not get subsystem name from {:?}", host_mount);
            }
        }

        Ok(())
    }

    // On some distros cgroup subsystems are comounted e.g. cpu,cpuacct or net_cls,net_prio. These systems
    // have to be comounted in the container as well as the kernel will reject trying to mount them separately.
    #[cfg(feature = "v1")]
    fn setup_namespaced_subsystem(
        &self,
        cgroup_mount: &SpecMount,
        options: &MountOptions,
        subsystem_name: &str,
        named: bool,
    ) -> Result<()> {
        tracing::debug!(
            "Mounting (namespaced) {:?} cgroup subsystem",
            subsystem_name
        );
        let subsystem_mount = SpecMountBuilder::default()
            .source("cgroup")
            .typ("cgroup")
            .destination(cgroup_mount.destination().join(subsystem_name))
            .options(
                ["noexec", "nosuid", "nodev"]
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<String>>(),
            )
            .build()
            .map_err(|err| {
                tracing::error!("failed to build {subsystem_name} mount: {err}");
                err
            })?;

        let data: Cow<str> = if named {
            format!("name={subsystem_name}").into()
        } else {
            subsystem_name.into()
        };

        let mount_options_config = MountOptionConfig {
            flags: MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            propagation_flags: MsFlags::empty(),
            data: vec![data.into_owned()],
            rec_attr: None,
        };

        self.mount_into_container(
            &subsystem_mount,
            options.root,
            &mount_options_config,
            options.label,
        )
        .map_err(|err| {
            tracing::error!("failed to mount {subsystem_mount:?}: {err}");
            err
        })
    }

    #[cfg(feature = "v1")]
    fn setup_emulated_subsystem(
        &self,
        cgroup_mount: &SpecMount,
        options: &MountOptions,
        subsystem_name: &str,
        named: bool,
        host_mount: &Path,
        process_cgroups: &HashMap<String, String>,
    ) -> Result<()> {
        tracing::debug!("Mounting (emulated) {:?} cgroup subsystem", subsystem_name);
        let named_hierarchy: Cow<str> = if named {
            format!("name={subsystem_name}").into()
        } else {
            subsystem_name.into()
        };

        if let Some(proc_path) = process_cgroups.get(named_hierarchy.as_ref()) {
            let emulated = SpecMountBuilder::default()
                .source(
                    host_mount
                        .join_safely(proc_path.as_str())
                        .map_err(|err| {
                            tracing::error!(
                                "failed to join mount source for {subsystem_name} subsystem: {}",
                                err
                            );
                            MountError::Other(err.into())
                        })?,
                )
                .destination(
                    cgroup_mount
                        .destination()
                        .join_safely(subsystem_name)
                        .map_err(|err| {
                            tracing::error!(
                                "failed to join mount destination for {subsystem_name} subsystem: {}",
                                err
                            );
                            MountError::Other(err.into())
                        })?,
                )
                .typ("bind")
                .options(
                    ["rw", "rbind"]
                        .iter()
                        .map(|o| o.to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?;
            tracing::debug!("Mounting emulated cgroup subsystem: {:?}", emulated);

            self.setup_mount(&emulated, options).map_err(|err| {
                tracing::error!("failed to mount {subsystem_name} cgroup hierarchy: {}", err);
                err
            })?;
        } else {
            tracing::warn!("Could not mount {:?} cgroup subsystem", subsystem_name);
        }

        Ok(())
    }

    #[cfg(feature = "v2")]
    fn mount_cgroup_v2(
        &self,
        cgroup_mount: &SpecMount,
        options: &MountOptions,
        mount_option_config: &MountOptionConfig,
    ) -> Result<()> {
        tracing::debug!("Mounting cgroup v2 filesystem");

        let cgroup_mount = SpecMountBuilder::default()
            .typ("cgroup2")
            .source("cgroup")
            .destination(cgroup_mount.destination())
            .options(Vec::new())
            .build()?;
        tracing::debug!("{:?}", cgroup_mount);

        if self
            .mount_into_container(
                &cgroup_mount,
                options.root,
                mount_option_config,
                options.label,
            )
            .is_err()
        {
            let host_mount = libcgroups::v2::util::get_unified_mount_point().map_err(|err| {
                tracing::error!("failed to get unified mount point: {}", err);
                MountError::Other(err.into())
            })?;

            let process_cgroup = ProcessCGroups::from_read(ProcfsHandle::new()?.open(
                ProcfsBase::ProcSelf,
                "cgroup",
                OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
            )?)?
            .into_iter()
            .find(|c| c.hierarchy == 0)
            .map(|c| PathBuf::from(c.pathname))
            .ok_or_else(|| MountError::Custom("failed to find unified process cgroup".into()))?;

            let bind_mount = SpecMountBuilder::default()
                .typ("bind")
                .source(host_mount.join_safely(process_cgroup).map_err(|err| {
                    tracing::error!("failed to join host mount for cgroup hierarchy: {}", err);
                    MountError::Other(err.into())
                })?)
                .destination(cgroup_mount.destination())
                .options(Vec::new())
                .build()
                .map_err(|err| {
                    tracing::error!("failed to build cgroup bind mount: {}", err);
                    err
                })?;
            tracing::debug!("{:?}", bind_mount);

            let mut mount_option_config = (*mount_option_config).clone();
            mount_option_config.flags |= MsFlags::MS_BIND;
            self.mount_into_container(
                &bind_mount,
                options.root,
                &mount_option_config,
                options.label,
            )
            .map_err(|err| {
                tracing::error!("failed to bind mount cgroup hierarchy: {}", err);
                err
            })?;
        }

        Ok(())
    }

    pub fn make_parent_mount_private(&self, rootfs: &Path) -> Result<()> {
        let mut destination = unsafe {
            OwnedFd::from_raw_fd(open(
                rootfs,
                OFlag::O_PATH | OFlag::O_CLOEXEC,
                Mode::empty(),
            )?)
        };
        for _ in 0..rootfs.components().count() {
            let destination_path =
                PathBuf::from(format!("/proc/self/fd/{}", destination.as_raw_fd()));
            if self
                .syscall
                .mount(None, &destination_path, None, MsFlags::MS_PRIVATE, None)
                .is_ok()
            {
                return Ok(());
            }
            destination = unsafe {
                OwnedFd::from_raw_fd(openat(
                    Some(destination.as_raw_fd()),
                    "..",
                    OFlag::O_PATH | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )?)
            };
        }
        Err(MountError::Custom("make rootfs private failed".to_string()))
    }

    fn mount_into_container(
        &self,
        m: &SpecMount,
        rootfs: &Path,
        mount_option_config: &MountOptionConfig,
        _label: Option<&str>,
    ) -> Result<()> {
        let typ = m.typ().as_deref();
        let root = Root::open(rootfs)?;
        let container_dest = m.destination();
        let dir_perm = Permissions::from_mode(0o755);
        let bind_source = if is_bind(m) {
            let source = m.source().as_ref().ok_or(MountError::NoSource)?;
            let src = canonicalize(source).map_err(|err| {
                tracing::error!("failed to canonicalize {:?}: {}", source, err);
                err
            })?;

            if src.is_dir() {
                root.mkdir_all(container_dest, &dir_perm)?;
            } else {
                let parent = container_dest
                    .parent()
                    .ok_or(MountError::Custom("destination has no parent".to_string()))?;
                root.mkdir_all(parent, &dir_perm)?;

                match root.create_file(
                    container_dest,
                    OpenFlags::O_EXCL
                        | OpenFlags::O_CREAT
                        | OpenFlags::O_NOFOLLOW
                        | OpenFlags::O_CLOEXEC,
                    &Permissions::from_mode(0o644),
                ) {
                    Ok(_) => Ok(()),
                    // If we get here, the file is already present, so continue.
                    Err(create_err) => root
                        .resolve(container_dest)
                        .map(|_| ())
                        .map_err(|_| create_err),
                }?;
            };

            let source_fd = unsafe {
                OwnedFd::from_raw_fd(open(&src, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())?)
            };
            let source_path = PathBuf::from(format!("/proc/self/fd/{}", source_fd.as_raw_fd()));
            Some((source_fd, source_path))
        } else {
            root.mkdir_all(container_dest, &dir_perm)?;
            None
        };

        let initial_dest: OwnedFd = root.resolve(container_dest)?.into();
        let initial_dest_path = if container_dest == Path::new(".") {
            rootfs.to_path_buf()
        } else {
            PathBuf::from(format!("/proc/self/fd/{}", initial_dest.as_raw_fd()))
        };

        if is_bind(m) {
            let source_path = &bind_source
                .as_ref()
                .expect("bind source must remain open")
                .1;
            self.syscall.mount(
                Some(source_path),
                &initial_dest_path,
                None,
                mount_option_config.flags & !MsFlags::MS_RDONLY,
                None,
            )?;
        } else {
            let data = mount_option_config.data.join(",");
            self.syscall.mount(
                m.source().as_deref(),
                &initial_dest_path,
                typ,
                mount_option_config.flags,
                (!data.is_empty()).then_some(data.as_str()),
            )?;
        }

        let dest: OwnedFd = if container_dest == Path::new(".") {
            unsafe {
                OwnedFd::from_raw_fd(open(
                    rootfs,
                    OFlag::O_PATH | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )?)
            }
        } else {
            root.resolve(container_dest)?.into()
        };
        let dest_path = if container_dest == Path::new(".") {
            rootfs.to_path_buf()
        } else {
            PathBuf::from(format!("/proc/self/fd/{}", dest.as_raw_fd()))
        };

        if !mount_option_config.propagation_flags.is_empty() {
            self.syscall.mount(
                None,
                &dest_path,
                None,
                mount_option_config.propagation_flags,
                None,
            )?;
        }

        let needs_remount = mount_option_config
            .flags
            .intersects(MsFlags::MS_RDONLY | MsFlags::MS_BIND)
            || (typ == Some("proc") && !mount_option_config.data.is_empty());
        if needs_remount {
            let mut flags = mount_option_config.flags | MsFlags::MS_REMOUNT;
            if typ != Some("proc") {
                flags |= MsFlags::MS_BIND;
            }
            if flags.contains(MsFlags::MS_RDONLY) {
                self.pending_remounts.borrow_mut().push(PendingRemount {
                    destination: dest,
                    flags,
                });
            } else {
                self.remount(&dest_path, flags)?;
            }
        }

        Ok(())
    }

    pub fn queue_root_readonly(&self, rootfs: &Path) -> Result<()> {
        let destination = unsafe {
            OwnedFd::from_raw_fd(open(
                rootfs,
                OFlag::O_PATH | OFlag::O_CLOEXEC,
                Mode::empty(),
            )?)
        };
        self.pending_remounts.borrow_mut().push(PendingRemount {
            destination,
            flags: MsFlags::MS_RDONLY | MsFlags::MS_BIND | MsFlags::MS_REMOUNT,
        });
        Ok(())
    }

    pub fn setup_masked_paths(&self, paths: &[String], options: &MountOptions) -> Result<()> {
        let root = Root::open(options.root)?;
        for path in paths {
            let destination = match root.resolve(path) {
                Ok(destination) => destination,
                Err(error)
                    if matches!(
                        error.kind(),
                        pathrs::error::ErrorKind::OsError(Some(libc::ENOENT))
                            | pathrs::error::ErrorKind::OsError(Some(libc::EACCES))
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let destination: OwnedFd = destination.into();
            let destination_path =
                PathBuf::from(format!("/proc/self/fd/{}", destination.as_raw_fd()));
            let metadata = fs::metadata(&destination_path)?;
            let mount = if metadata.is_dir() {
                SpecMountBuilder::default()
                    .destination(PathBuf::from(path))
                    .source("tmpfs")
                    .typ("tmpfs")
                    .options(vec!["ro".to_string(), "size=0k".to_string()])
                    .build()?
            } else {
                SpecMountBuilder::default()
                    .destination(PathBuf::from(path))
                    .source("/dev/null")
                    .options(vec!["bind".to_string(), "ro".to_string()])
                    .build()?
            };
            self.setup_mount(&mount, options)?;
        }
        Ok(())
    }

    pub fn setup_readonly_paths(&self, paths: &[String], options: &MountOptions) -> Result<()> {
        let root = Root::open(options.root)?;
        for path in paths {
            let destination = match root.resolve(path) {
                Ok(destination) => destination,
                Err(error)
                    if matches!(
                        error.kind(),
                        pathrs::error::ErrorKind::OsError(Some(libc::ENOENT))
                            | pathrs::error::ErrorKind::OsError(Some(libc::EACCES))
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let destination: OwnedFd = destination.into();
            let source = PathBuf::from(format!("/proc/self/fd/{}", destination.as_raw_fd()));
            let inherited =
                MsFlags::from_bits_truncate(statfs(&source)?.flags().bits()) & !MsFlags::MS_REMOUNT;
            let mount = SpecMountBuilder::default()
                .destination(PathBuf::from(path))
                .source(&source)
                .options(vec!["rbind".to_string()])
                .build()?;
            let mount_options = MountOptionConfig {
                flags: inherited | MsFlags::MS_BIND | MsFlags::MS_RDONLY | MsFlags::MS_REC,
                propagation_flags: MsFlags::MS_PRIVATE | MsFlags::MS_REC,
                data: Vec::new(),
                rec_attr: None,
            };
            self.mount_into_container(&mount, options.root, &mount_options, options.label)?;
        }
        Ok(())
    }

    pub fn ensure_dev_ptmx(&self, options: &MountOptions) -> Result<()> {
        let root = Root::open(options.root)?;
        let ptmx = match root.resolve_nofollow("dev/ptmx") {
            Ok(ptmx) => ptmx,
            Err(error)
                if matches!(
                    error.kind(),
                    pathrs::error::ErrorKind::OsError(Some(libc::ENOENT))
                ) =>
            {
                root.create("dev/ptmx", &InodeType::Symlink(PathBuf::from("pts/ptmx")))?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let ptmx: OwnedFd = ptmx.into();
        let stat = fstat(ptmx.as_raw_fd())?;
        let file_type = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;

        if file_type == SFlag::S_IFREG {
            let mount = SpecMountBuilder::default()
                .source(options.root.join("dev/pts/ptmx"))
                .destination("/dev/ptmx")
                .typ("bind")
                .options(vec![
                    "bind".to_string(),
                    "noexec".to_string(),
                    "nosuid".to_string(),
                    "private".to_string(),
                ])
                .build()?;
            self.setup_mount(&mount, options)?;
            return Ok(());
        }

        if file_type == SFlag::S_IFLNK {
            let target = root.readlink("dev/ptmx")?;
            if target == Path::new("pts/ptmx") || target == Path::new("/dev/pts/ptmx") {
                return Ok(());
            }
            root.create(
                "dev/.ptmx.tmp",
                &InodeType::Symlink(PathBuf::from("pts/ptmx")),
            )?;
            root.rename("dev/.ptmx.tmp", "dev/ptmx", RenameFlags::empty())?;
            return Ok(());
        }

        Err(MountError::Custom(format!(
            "invalid /dev/ptmx type: {:#x}, expected a regular file or symlink",
            file_type.bits()
        )))
    }

    pub fn create_default_devices(&self, options: &MountOptions) -> Result<()> {
        Root::open(options.root)?.resolve("dev")?;
        let previous_umask = nix::sys::stat::umask(Mode::empty());
        let result = (|| {
            for device in default_devices() {
                let destination = options.root.join(
                    device
                        .path()
                        .strip_prefix("/")
                        .map_err(|error| MountError::Other(error.into()))?,
                );
                let device_number = libc::makedev(device.major() as u32, device.minor() as u32);
                match self.syscall.mknod(
                    &destination,
                    to_sflag(device.typ()),
                    Mode::from_bits_truncate(0o666),
                    device_number,
                ) {
                    Ok(()) => {
                        self.syscall.chown(
                            &destination,
                            Some(Uid::from_raw(0)),
                            Some(Gid::from_raw(0)),
                        )?;
                    }
                    Err(SyscallError::Nix(nix::errno::Errno::EEXIST)) => {}
                    Err(SyscallError::Nix(nix::errno::Errno::EPERM)) => {
                        let mount = SpecMountBuilder::default()
                            .source(device.path())
                            .destination(device.path())
                            .typ("bind")
                            .options(vec![
                                "bind".to_string(),
                                "noexec".to_string(),
                                "nosuid".to_string(),
                                "private".to_string(),
                            ])
                            .build()?;
                        self.setup_mount(&mount, options)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        })();
        nix::sys::stat::umask(previous_umask);
        result
    }

    pub fn finalize(&self) -> Result<()> {
        let pending = std::mem::take(&mut *self.pending_remounts.borrow_mut());
        for remount in pending.into_iter().rev() {
            let destination =
                PathBuf::from(format!("/proc/self/fd/{}", remount.destination.as_raw_fd()));
            self.remount(&destination, remount.flags)?;
        }
        Ok(())
    }

    fn remount(&self, destination: &Path, flags: MsFlags) -> Result<()> {
        if self
            .syscall
            .mount(None, destination, None, flags, None)
            .is_ok()
        {
            return Ok(());
        }

        let destination_flags = MsFlags::from_bits_truncate(statfs(destination)?.flags().bits());
        let inherited =
            destination_flags & (MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC);
        if (inherited | flags) != flags {
            if self
                .syscall
                .mount(None, destination, None, inherited | flags, None)
                .is_ok()
            {
                return Ok(());
            }
            if destination_flags.contains(MsFlags::MS_RDONLY) {
                let inherited = inherited | MsFlags::MS_RDONLY;
                self.syscall
                    .mount(None, destination, None, inherited | flags, None)?;
                return Ok(());
            }
        }

        Err(MountError::Custom(
            "remount failed after all fallbacks".to_string(),
        ))
    }

    /// check_proc_mount checks to ensure that the mount destination is not over the top of /proc.
    /// dest is required to be an abs path and have any symlinks resolved before calling this function.
    /// # Example  (a valid case where `/proc` is mounted with `proc` type.)
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use oci_spec::runtime::MountBuilder as SpecMountBuilder;
    /// use libcontainer::rootfs::Mount;
    ///
    /// let mounter = Mount::new();
    ///
    /// let rootfs = PathBuf::from("/var/lib/my-runtime/containers/abcd1234/rootfs");
    /// let destination = PathBuf::from("/proc");
    /// let source = PathBuf::from("proc");
    /// let typ = "proc";
    ///
    /// let mount = SpecMountBuilder::default()
    ///     .destination(destination)
    ///     .typ(typ)
    ///     .source(source)
    ///     .build()
    ///     .expect("failed to build SpecMount");
    ///
    /// assert!(mounter.check_proc_mount(rootfs.as_path(), &mount).is_ok());
    /// ```
    /// # Example (bind mount to `/proc` that should fail)
    /// ```
    /// use std::path::PathBuf;
    /// use oci_spec::runtime::MountBuilder as SpecMountBuilder;
    /// use libcontainer::rootfs::Mount;
    ///
    /// let mounter = Mount::new();
    ///
    /// let rootfs = PathBuf::from("/var/lib/my-runtime/containers/abcd1234/rootfs");
    /// let destination = PathBuf::from("/proc");
    /// let source = PathBuf::from("/tmp");
    /// let typ = "bind";
    ///
    /// let mount = SpecMountBuilder::default()
    ///     .destination(destination)
    ///     .typ(typ)
    ///     .source(source)
    ///     .build()
    ///     .expect("failed to build SpecMount");
    ///
    /// assert!(mounter.check_proc_mount(rootfs.as_path(), &mount).is_err());
    /// ```
    pub fn check_proc_mount(&self, rootfs: &Path, mount: &SpecMount) -> Result<()> {
        const PROC_ROOT_INO: u64 = 1;
        const VALID_PROC_MOUNTS: &[&str] = &[
            "/proc/cpuinfo",
            "/proc/diskstats",
            "/proc/meminfo",
            "/proc/stat",
            "/proc/swaps",
            "/proc/uptime",
            "/proc/loadavg",
            "/proc/slabinfo",
            "/proc/sys/kernel/ns_last_pid",
            "/proc/sys/crypto/fips_enabled",
        ];

        let dest = mount.destination();

        let container_proc_path = rootfs.join("proc");
        let dest_path = rootfs.join_safely(dest).map_err(|err| {
            tracing::error!(
                "could not join rootfs path with mount destination {:?}: {}",
                dest,
                err
            );
            MountError::Other(err.into())
        })?;

        // If path is Ok, it means dest_path is under /proc.
        // - Ok(p) with p.is_empty(): mount target is exactly /proc.
        //   In this case, check if the mount source is procfs.
        // - Ok(p) with !p.is_empty(): mount target is under /proc.
        //   Only allow if it matches a specific whitelist of proc entries.
        // - Err: not under /proc, so no further checks are needed
        let path = dest_path.strip_prefix(&container_proc_path);

        match path {
            Err(_) => Ok(()),
            Ok(p) if p.as_os_str().is_empty() => {
                if mount.typ().as_deref() == Some("proc") {
                    return Ok(());
                }

                if is_bind(mount) {
                    if let Some(source) = mount.source() {
                        let stat = statfs(source).map_err(MountError::from)?;
                        if stat.filesystem_type() == PROC_SUPER_MAGIC {
                            let meta = fs::metadata(source).map_err(MountError::from)?;
                            // Follow the behavior of runc's checkProcMount function.
                            if meta.ino() != PROC_ROOT_INO {
                                tracing::warn!(
                                    "bind-mount {} (source {:?}) is of type procfs but not the root (inode {}). \
                                    Future versions may reject this.",
                                    dest.display(),
                                    mount.source(),
                                    meta.ino()
                                );
                            }
                            return Ok(());
                        }
                    }
                }

                Err(MountError::Custom(format!(
                    "{} cannot be mounted because it is not type proc",
                    dest.display()
                )))
            }
            Ok(_) => {
                // Here dest is definitely under /proc. Do not allow those,
                // except for a few specific entries emulated by lxcfs.
                let is_allowed = VALID_PROC_MOUNTS.iter().any(|allowed_path| {
                    let container_allowed_path = rootfs.join(allowed_path.trim_start_matches('/'));
                    dest_path == container_allowed_path
                });

                if is_allowed {
                    Ok(())
                } else {
                    Err(MountError::Other(
                        format!("{} is not a valid mount under /proc", dest.display()).into(),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "v1")]
    use std::fs;
    use std::os::unix::fs::symlink;

    #[cfg(feature = "v2")]
    use anyhow::Context;
    use anyhow::{Ok, Result};

    use super::*;
    use crate::syscall::test::{ArgName, TestHelperSyscall};

    fn helper_syscall(m: &Mount) -> &TestHelperSyscall {
        m.syscall
            .as_any()
            .downcast_ref::<TestHelperSyscall>()
            .unwrap()
    }

    #[test]
    fn test_mount_into_container() -> Result<()> {
        let tmp_dir = tempfile::tempdir()?;
        {
            let m = Mount::new();
            let mount = &SpecMountBuilder::default()
                .destination(PathBuf::from("/dev/pts"))
                .typ("devpts")
                .source(PathBuf::from("devpts"))
                .options(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "newinstance".to_string(),
                    "ptmxmode=0666".to_string(),
                    "mode=0620".to_string(),
                    "gid=5".to_string(),
                ])
                .build()?;
            let mount_option_config = parse_mount(mount)?;

            assert!(
                m.mount_into_container(
                    mount,
                    tmp_dir.path(),
                    &mount_option_config,
                    Some("defaults")
                )
                .is_ok()
            );

            let calls = helper_syscall(&m).get_mount_args();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].source, Some(PathBuf::from("devpts")));
            assert_eq!(calls[0].fstype.as_deref(), Some("devpts"));
            assert_eq!(calls[0].flags, MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC);
            assert_eq!(
                calls[0].data.as_deref(),
                Some("newinstance,ptmxmode=0666,mode=0620,gid=5")
            );
            assert_eq!(calls[0].target, tmp_dir.path().join("dev/pts"));
        }
        {
            let m = Mount::new();
            let mount = &SpecMountBuilder::default()
                .destination(PathBuf::from("/dev/null"))
                .typ("bind")
                .source(tmp_dir.path().join("null"))
                .options(vec![
                    "bind".to_string(),
                    "ro".to_string(),
                    "nosuid".to_string(),
                    "rprivate".to_string(),
                ])
                .build()?;
            let mount_option_config = parse_mount(mount)?;
            std::fs::write(tmp_dir.path().join("null"), [])?;

            assert!(
                m.mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                    .is_ok()
            );
            m.finalize()?;

            let calls = helper_syscall(&m).get_mount_args();
            assert_eq!(calls.len(), 3);
            assert!(
                calls[0]
                    .source
                    .as_ref()
                    .is_some_and(|source| source.starts_with("/proc/self/fd"))
            );
            assert_eq!(calls[0].flags, MsFlags::MS_BIND | MsFlags::MS_NOSUID);
            assert_eq!(calls[1].flags, MsFlags::MS_PRIVATE | MsFlags::MS_REC);
            assert_eq!(
                calls[2].flags,
                MsFlags::MS_BIND | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_REMOUNT
            );
        }
        {
            let m = Mount::new();
            let mount = &SpecMountBuilder::default()
                .destination(PathBuf::from("/tmp.sock"))
                .typ("bind")
                .source(tmp_dir.path().join("source"))
                .options(vec!["bind".to_string()])
                .build()?;
            let mount_option_config = parse_mount(mount)?;
            std::fs::write(tmp_dir.path().join("source"), [])?;

            assert!(
                m.mount_into_container(mount, tmp_dir.path(), &mount_option_config, None)
                    .is_ok()
            );

            let calls = helper_syscall(&m).get_mount_args();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].flags, MsFlags::MS_BIND);
            assert_eq!(calls[1].flags, MsFlags::MS_BIND | MsFlags::MS_REMOUNT);
        }

        Ok(())
    }

    #[test]
    fn test_finalize_readonly_mounts_in_reverse_order() -> Result<()> {
        let rootfs = tempfile::tempdir()?;
        std::fs::write(rootfs.path().join("source-a"), [])?;
        std::fs::write(rootfs.path().join("source-b"), [])?;
        let mounter = Mount::new();

        for name in ["a", "b"] {
            let mount = SpecMountBuilder::default()
                .destination(PathBuf::from(format!("/{name}")))
                .source(rootfs.path().join(format!("source-{name}")))
                .options(vec!["bind".to_string(), "ro".to_string()])
                .build()?;
            let options = parse_mount(&mount)?;
            mounter.mount_into_container(&mount, rootfs.path(), &options, None)?;
        }

        assert_eq!(helper_syscall(&mounter).get_mount_args().len(), 2);
        mounter.finalize()?;
        let calls = helper_syscall(&mounter).get_mount_args();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[2].target, rootfs.path().join("b"));
        assert_eq!(calls[3].target, rootfs.path().join("a"));
        Ok(())
    }

    #[test]
    fn test_ensure_dev_ptmx_matches_frozen_runtime() -> Result<()> {
        let rootfs = tempfile::tempdir()?;
        std::fs::create_dir_all(rootfs.path().join("dev/pts"))?;
        let options = MountOptions {
            root: rootfs.path(),
            label: None,
            cgroup_ns: false,
        };
        let mounter = Mount::new();

        mounter.ensure_dev_ptmx(&options)?;
        assert_eq!(
            std::fs::read_link(rootfs.path().join("dev/ptmx"))?,
            PathBuf::from("pts/ptmx")
        );

        std::fs::remove_file(rootfs.path().join("dev/ptmx"))?;
        std::os::unix::fs::symlink("wrong", rootfs.path().join("dev/ptmx"))?;
        mounter.ensure_dev_ptmx(&options)?;
        assert_eq!(
            std::fs::read_link(rootfs.path().join("dev/ptmx"))?,
            PathBuf::from("pts/ptmx")
        );

        std::fs::remove_file(rootfs.path().join("dev/ptmx"))?;
        std::fs::write(rootfs.path().join("dev/ptmx"), [])?;
        std::fs::write(rootfs.path().join("dev/pts/ptmx"), [])?;
        mounter.ensure_dev_ptmx(&options)?;
        let calls = helper_syscall(&mounter).get_mount_args();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[0].flags,
            MsFlags::MS_BIND | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID
        );
        assert_eq!(calls[1].flags, MsFlags::MS_PRIVATE);
        assert_eq!(
            calls[2].flags,
            MsFlags::MS_BIND | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_REMOUNT
        );

        std::fs::remove_file(rootfs.path().join("dev/ptmx"))?;
        std::fs::create_dir(rootfs.path().join("dev/ptmx"))?;
        assert!(mounter.ensure_dev_ptmx(&options).is_err());
        Ok(())
    }

    #[test]
    fn test_host_dev_and_cgroup_mount_compatibility() -> Result<()> {
        let rootfs = tempfile::tempdir()?;
        let host_dev = tempfile::tempdir()?;
        std::fs::create_dir_all(rootfs.path().join("dev"))?;
        let options = MountOptions {
            root: rootfs.path(),
            label: None,
            cgroup_ns: false,
        };
        let mounter = Mount::new();
        let dev_mount = SpecMountBuilder::default()
            .destination("/dev")
            .source(host_dev.path())
            .options(vec!["rbind".to_string()])
            .build()?;
        mounter.setup_mount(&dev_mount, &options)?;
        assert!(mounter.mount_dev_from_host());

        let cgroup_mount = SpecMountBuilder::default()
            .destination("/sys/fs/cgroup")
            .source("cgroup")
            .typ("cgroup")
            .build()?;
        assert!(mounter.setup_mount(&cgroup_mount, &options).is_err());

        let sys_source = tempfile::tempdir()?;
        let sys_mount = SpecMountBuilder::default()
            .destination("/sys")
            .source(sys_source.path())
            .options(vec!["rbind".to_string()])
            .build()?;
        mounter.setup_mount(&sys_mount, &options)?;
        mounter.setup_mount(&cgroup_mount, &options)?;
        Ok(())
    }

    #[test]
    fn test_make_parent_mount_private() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let rootfs = temporary.path().join("parent/rootfs");
        std::fs::create_dir_all(&rootfs)?;
        let mounter = Mount::new();
        mounter.make_parent_mount_private(&rootfs)?;
        let calls = helper_syscall(&mounter).get_mount_args();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].target, rootfs);
        assert_eq!(calls[0].flags, MsFlags::MS_PRIVATE);
        Ok(())
    }

    #[test]
    fn test_make_parent_mount_private_walks_upward() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let parent = temporary.path().join("parent");
        let rootfs = parent.join("rootfs");
        std::fs::create_dir_all(&rootfs)?;
        let mounter = Mount::new();
        let syscall = helper_syscall(&mounter);
        syscall.set_ret_err(ArgName::Mount, || {
            Err(SyscallError::Nix(nix::errno::Errno::EINVAL))
        });
        syscall.set_ret_err_times(ArgName::Mount, 1);
        mounter.make_parent_mount_private(&rootfs)?;
        let calls = syscall.get_mount_args();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].target, parent);
        Ok(())
    }

    #[test]
    #[cfg(feature = "v2")]
    fn test_mount_cgroup_v2() -> Result<()> {
        // arrange
        let tmp = tempfile::tempdir().unwrap();
        let container_cgroup = PathBuf::from("/sys/fs/cgroup");

        let spec_cgroup_mount = SpecMountBuilder::default()
            .destination(&container_cgroup)
            .source("cgroup")
            .typ("cgroup")
            .build()
            .context("failed to build cgroup mount")?;

        let mount_opts = MountOptions {
            root: tmp.path(),
            label: None,
            cgroup_ns: true,
        };

        let mounter = Mount::new();
        let flags = MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV;

        // act
        let mount_option_config = MountOptionConfig {
            flags,
            propagation_flags: MsFlags::empty(),
            data: vec![],
            rec_attr: None,
        };
        mounter
            .mount_cgroup_v2(&spec_cgroup_mount, &mount_opts, &mount_option_config)
            .context("failed to mount cgroup v2")?;

        let calls = helper_syscall(&mounter).get_mount_args();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].source, Some(PathBuf::from("cgroup")));
        assert_eq!(calls[0].fstype.as_deref(), Some("cgroup2"));
        assert_eq!(calls[0].flags, flags);
        assert_eq!(calls[0].target, tmp.path().join("sys/fs/cgroup"));

        Ok(())
    }

    #[test]
    fn test_check_proc_mount_proc_ok() -> Result<()> {
        let rootfs = tempfile::tempdir()?;
        let mounter = Mount::new();

        let mount = SpecMountBuilder::default()
            .destination(PathBuf::from("/proc"))
            .typ("proc".to_string())
            .source(PathBuf::from("proc"))
            .build()?;

        assert!(mounter.check_proc_mount(rootfs.path(), &mount).is_ok());
        Ok(())
    }

    #[test]
    fn test_check_proc_mount_allowed_subpath() -> Result<()> {
        let rootfs = tempfile::tempdir()?;
        let uptime = rootfs.path().join("proc/uptime");
        std::fs::create_dir_all(uptime.parent().unwrap())?;

        let mounter = Mount::new();
        let mount = SpecMountBuilder::default()
            .destination(PathBuf::from("/proc/uptime"))
            .typ("bind".to_string())
            .source(uptime)
            .build()?;

        assert!(mounter.check_proc_mount(rootfs.path(), &mount).is_ok());
        Ok(())
    }

    #[test]
    fn test_check_proc_mount_denied_subpath() -> Result<()> {
        let rootfs = tempfile::tempdir()?;
        let custom = rootfs.path().join("proc/custom");
        std::fs::create_dir_all(custom.parent().unwrap())?;

        let mounter = Mount::new();
        let mount = SpecMountBuilder::default()
            .destination(PathBuf::from("/proc/custom"))
            .typ("bind".to_string())
            .source(custom)
            .build()?;

        assert!(mounter.check_proc_mount(rootfs.path(), &mount).is_err());
        Ok(())
    }

    #[test]
    fn setup_mount_proc_fails_if_destination_is_symlink() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let rootfs = tmp.path();

        let symlink_path = rootfs.join("symlink");
        fs::create_dir_all(&symlink_path)?;
        let proc_path = rootfs.join("proc");

        symlink(&symlink_path, &proc_path)?;

        let mount = SpecMountBuilder::default()
            .destination(PathBuf::from("/proc"))
            .typ("proc")
            .source(proc_path)
            .build()?;

        let options = MountOptions {
            root: rootfs,
            label: None,
            cgroup_ns: true,
        };

        let m = Mount::new();

        let res = m.setup_mount(&mount, &options);

        // proc destination symlink should be rejected
        assert!(res.is_err());
        let err = format!("{:?}", res.err().unwrap());
        assert!(err.contains("must be mounted on ordinary directory"));

        Ok(())
    }

    #[test]
    fn setup_mount_sys_fails_if_destination_is_symlink() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let rootfs = tmp.path();

        let symlink_path = rootfs.join("symlink");
        fs::create_dir_all(&symlink_path)?;
        let sys_path = rootfs.join("sys");

        symlink(&symlink_path, &sys_path)?;

        let mount = SpecMountBuilder::default()
            .destination(PathBuf::from("/sys"))
            .typ("sysfs")
            .source(sys_path)
            .build()?;

        let options = MountOptions {
            root: rootfs,
            label: None,
            cgroup_ns: true,
        };

        let m = Mount::new();

        let res = m.setup_mount(&mount, &options);

        // sys destination symlink should be rejected
        assert!(res.is_err());
        let err = format!("{:?}", res.err().unwrap());
        assert!(err.contains("must be mounted on ordinary directory"));

        Ok(())
    }
}
