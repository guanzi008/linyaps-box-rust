use std::path::Path;

use oci_spec::runtime;

use super::Result;
use crate::container::Container;
use crate::error::MissingSpecError;
use crate::namespaces::Namespaces;
use crate::notify_socket;
use crate::process::args::ContainerArgs;
use crate::syscall::Syscall;

pub(crate) struct InitContext<'a> {
    pub(crate) spec: &'a runtime::Spec,
    pub(crate) linux: &'a runtime::Linux,
    pub(crate) process: &'a runtime::Process,
    pub(crate) rootfs: &'a Path,
    pub(crate) ns: Namespaces,
    pub(crate) syscall: Box<dyn Syscall>,
    pub(crate) notify_listener: &'a notify_socket::NotifyListener,
    pub(crate) hooks: Option<&'a runtime::Hooks>,
    pub(crate) container: Option<&'a Container>,
}

impl<'a> InitContext<'a> {
    pub fn try_from(args: &'a ContainerArgs) -> Result<Self> {
        let spec = args.spec.as_ref();
        let linux = spec.linux().as_ref().ok_or(MissingSpecError::Linux)?;
        let process = spec.process().as_ref().ok_or(MissingSpecError::Process)?;
        spec.root().as_ref().ok_or(MissingSpecError::Root)?;

        Ok(Self {
            spec,
            linux,
            process,
            rootfs: &args.rootfs,
            ns: Namespaces::try_from(linux.namespaces().as_ref())?,
            syscall: args.syscall.create_syscall(),
            notify_listener: &args.notify_listener,
            hooks: spec.hooks().as_ref(),
            container: args.container.as_ref(),
        })
    }
}
