use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use nix::fcntl::{OFlag, open, openat, readlinkat};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::symlinkat;
use oci_spec::runtime::LinuxSeccomp;
use serde_json::Value;

use crate::OCI_VERSION;
use crate::capability;

const COPY_SYMLINK: &str = "copy-symlink";
const NS_LAST_PID_ANNOTATION: &str = "cn.org.linyaps.runtime.ns_last_pid";
const HOOK_ORIGINAL_BUNDLE_ANNOTATION: &str = "cn.org.linyaps.internal.hook-state.original-bundle";
const HOOK_CREATED_ANNOTATION: &str = "cn.org.linyaps.internal.hook-state.created";
const HOOK_OWNER_ANNOTATION: &str = "cn.org.linyaps.internal.hook-state.owner";
const CAPABILITY_ERROR_ANNOTATION: &str = "cn.org.linyaps.internal.compatibility.capability-error";
const IGNORED_MOUNT_OPTIONS: &[&str] = &[
    "tmpcopyup",
    "rro",
    "rrw",
    "rnosuid",
    "rsuid",
    "rnodev",
    "rdev",
    "rnoexec",
    "rexec",
    "rnodiratime",
    "rdiratime",
    "rnoatime",
    "ratime",
    "rstrictatime",
    "rnostrictatime",
    "rnosymfollow",
    "rsymfollow",
    "rrelatime",
    "rnorelatime",
];

pub struct PreparedBundle {
    directory: tempfile::TempDir,
    original_bundle: PathBuf,
    original_config_path: PathBuf,
    canonicalize_rootfs: bool,
    namespace_paths: Vec<NamespacePath>,
}

struct NamespacePath {
    kind: String,
    path: PathBuf,
}

impl PreparedBundle {
    pub fn new(bundle: &Path, config: &Path, scratch: &Path) -> Result<Self> {
        let original_bundle = bundle
            .canonicalize()
            .with_context(|| format!("failed to canonicalize bundle {}", bundle.display()))?;
        let config_path = if config.is_absolute() {
            config.to_path_buf()
        } else {
            original_bundle.join(config)
        };
        let original_config = fs::read(&config_path).map_err(|error| {
            anyhow::anyhow!(
                "filesystem error: failed to open oci_config file: {} [{}]",
                io_error_message(&error),
                config_path.display()
            )
        })?;
        let mut value: Value = serde_json::from_slice(&original_config)
            .with_context(|| format!("cannot parse config file: {}", config_path.display()))?;
        validate_required_fields(&value)?;
        validate_config(&value)?;
        let canonicalize_rootfs = value
            .pointer("/root/path")
            .and_then(Value::as_str)
            .is_some_and(|path| Path::new(path).is_relative());
        let namespace_paths = collect_namespace_paths(&value);
        let capability_error = collect_capability_error(&value);
        strip_upstream_noop_fields(&mut value);
        if let Some(capability_error) = capability_error {
            let annotations = value
                .as_object_mut()
                .expect("validated OCI config is an object")
                .entry("annotations")
                .or_insert_with(|| Value::Object(Default::default()));
            if annotations.is_null() {
                *annotations = Value::Object(Default::default());
            }
            annotations
                .as_object_mut()
                .expect("annotations are validated before normalization")
                .insert(
                    CAPABILITY_ERROR_ANNOTATION.to_string(),
                    Value::String(capability_error),
                );
        }
        normalize_paths(&mut value, &original_bundle)?;
        fs::create_dir_all(scratch)?;
        process_mount_extensions(&mut value)?;
        validate_runtime_extensions(&value)?;
        let directory = tempfile::Builder::new()
            .prefix("ll-box-bundle-")
            .tempdir_in(scratch)?;
        fs::write(
            directory.path().join("config.json"),
            serde_json::to_vec(&value)?,
        )?;
        Ok(Self {
            directory,
            original_bundle,
            original_config_path: config_path,
            canonicalize_rootfs,
            namespace_paths,
        })
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    pub fn original_bundle(&self) -> &Path {
        &self.original_bundle
    }

    pub fn original_config_path(&self) -> &Path {
        &self.original_config_path
    }

    pub fn canonicalize_rootfs(&self) -> bool {
        self.canonicalize_rootfs
    }

    pub fn validate_namespace_paths(&self) -> Result<()> {
        for namespace in &self.namespace_paths {
            let target = fs::read_link(&namespace.path).with_context(|| {
                format!(
                    "namespace path {} does not exist or is not accessible",
                    namespace.path.display()
                )
            })?;
            let target = target.as_os_str().as_bytes();
            let separator = target
                .iter()
                .position(|byte| *byte == b':')
                .with_context(|| {
                    format!(
                        "namespace path {} does not appear to be a namespace file",
                        namespace.path.display()
                    )
                })?;
            let actual = &target[..separator];
            if actual != namespace.kind.as_bytes() {
                bail!(
                    "namespace path {} is associated with '{}' namespace, not '{}'",
                    namespace.path.display(),
                    String::from_utf8_lossy(actual),
                    namespace.kind
                );
            }
        }
        Ok(())
    }

    pub fn set_hook_state_metadata(&mut self, created: &str, owner: &str) -> Result<()> {
        let path = self.directory.path().join("config.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let annotations = value
            .as_object_mut()
            .context("OCI config must be an object")?
            .entry("annotations")
            .or_insert_with(|| Value::Object(Default::default()));
        if annotations.is_null() {
            *annotations = Value::Object(Default::default());
        }
        let annotations = annotations
            .as_object_mut()
            .context("annotations must be an object")?;
        annotations.insert(
            HOOK_ORIGINAL_BUNDLE_ANNOTATION.to_string(),
            Value::String(self.original_bundle.to_string_lossy().into_owned()),
        );
        annotations.insert(
            HOOK_CREATED_ANNOTATION.to_string(),
            Value::String(created.to_string()),
        );
        annotations.insert(
            HOOK_OWNER_ANNOTATION.to_string(),
            Value::String(owner.to_string()),
        );
        fs::write(path, serde_json::to_vec(&value)?)?;
        Ok(())
    }
}

fn io_error_message(error: &std::io::Error) -> String {
    let Some(errno) = error.raw_os_error() else {
        return error.to_string();
    };
    let pointer = unsafe { libc::strerror(errno) };
    if pointer.is_null() {
        return error.to_string();
    }
    unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

fn validate_required_fields(value: &Value) -> Result<()> {
    if value.get("process").is_none_or(Value::is_null)
        || value.get("root").is_none_or(Value::is_null)
    {
        bail!("'process' and 'root' are required for run a container");
    }
    let version = value
        .get("ociVersion")
        .and_then(Value::as_str)
        .context("ociVersion is required")?;
    let requested = parse_oci_version(version)?;
    let supported = parse_oci_version(OCI_VERSION).expect("OCI_VERSION must be valid semver");
    if requested.0 != supported.0 || requested > supported {
        bail!("unsupported OCI version: {version}");
    }
    Ok(())
}

fn parse_oci_version(version: &str) -> Result<(u32, u32, u32)> {
    let core_end = version.find(['-', '+']).unwrap_or(version.len());
    let mut core = version[..core_end].split('.');
    let major = parse_oci_version_segment(version, core.next())?;
    let minor = parse_oci_version_segment(version, core.next())?;
    let patch = parse_oci_version_segment(version, core.next())?;
    if core.next().is_some() {
        bail!("invalid semver: {version}");
    }

    if core_end < version.len() {
        let suffix = &version[core_end..];
        if let Some(build) = suffix.strip_prefix('+') {
            validate_oci_version_identifiers(version, build)?;
        } else if let Some(prerelease_and_build) = suffix.strip_prefix('-') {
            let (prerelease, build) = prerelease_and_build
                .split_once('+')
                .map_or((prerelease_and_build, None), |(prerelease, build)| {
                    (prerelease, Some(build))
                });
            validate_oci_version_identifiers(version, prerelease)?;
            if let Some(build) = build {
                validate_oci_version_identifiers(version, build)?;
            }
        } else {
            bail!("invalid semver: {version}");
        }
    }

    Ok((major, minor, patch))
}

fn parse_oci_version_segment(version: &str, segment: Option<&str>) -> Result<u32> {
    let Some(segment) = segment else {
        bail!("invalid semver: {version}");
    };
    if segment.is_empty()
        || (segment.len() > 1 && segment.starts_with('0'))
        || !segment.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("invalid semver: {version}");
    }
    let value = segment
        .parse::<u32>()
        .with_context(|| format!("invalid semver: {version}"))?;
    if value > i32::MAX as u32 {
        bail!("invalid semver: {version}");
    }
    Ok(value)
}

fn validate_oci_version_identifiers(version: &str, identifiers: &str) -> Result<()> {
    if identifiers.is_empty() {
        bail!("invalid semver: {version}");
    }
    for identifier in identifiers.split('.') {
        if identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || (identifier.len() > 1
                && identifier.starts_with('0')
                && identifier.bytes().all(|byte| byte.is_ascii_digit()))
        {
            bail!("invalid semver: {version}");
        }
    }
    Ok(())
}

fn validate_config(value: &Value) -> Result<()> {
    value.as_object().context("OCI config must be an object")?;
    for field in ["hostname", "domainname"] {
        validate_optional_string(value, field, field)?;
    }
    if let Some(process) = value.get("process").filter(|value| !value.is_null()) {
        let process = process.as_object().context("process must be an object")?;
        validate_console_size(process)?;
        let cwd = process
            .get("cwd")
            .and_then(Value::as_str)
            .context("process.cwd is required")?;
        if !Path::new(cwd).is_absolute() {
            bail!("process.cwd must be an absolute path, got: {cwd}");
        }

        let args = process
            .get("args")
            .context("[json.exception.out_of_range.403] key 'args' not found")?
            .as_array()
            .context("process.args must be an array")?;
        if args.is_empty() {
            bail!("process.args must not be empty");
        }

        if let Some(environment) = process.get("env").and_then(Value::as_array) {
            for entry in environment {
                let entry = entry
                    .as_str()
                    .context("process.env entries must be strings")?;
                if invalid_environment(entry) {
                    bail!("process.env contains a invalid env: {entry}");
                }
            }
        }

        validate_rlimits(process)?;
        validate_capabilities(process)?;
        validate_user(process)?;
        validate_process_noop_fields(process)?;
    }

    if let Some(root) = value.get("root").filter(|value| !value.is_null()) {
        let root = root.as_object().context("root must be an object")?;
        root.get("path")
            .and_then(Value::as_str)
            .context("root.path must be a string")?;
        if let Some(readonly) = root.get("readonly")
            && !readonly.is_boolean()
        {
            bail!("root.readonly must be a boolean");
        }
    }
    if let Some(linux) = value.get("linux").filter(|value| !value.is_null())
        && let Some(linux) = linux.as_object()
    {
        validate_linux(linux)?;
    }
    if let Some(hooks) = value.get("hooks").filter(|value| !value.is_null())
        && let Some(hooks) = hooks.as_object()
    {
        for name in [
            "prestart",
            "createRuntime",
            "createContainer",
            "startContainer",
            "poststart",
            "poststop",
        ] {
            if let Some(entries) = hooks.get(name).filter(|value| !value.is_null()) {
                let entries = entries
                    .as_array()
                    .with_context(|| format!("hooks.{name} must be an array"))?;
                for hook in entries {
                    validate_hook(hook)?;
                }
            }
        }
    }
    if let Some(mounts) = value.get("mounts").filter(|value| !value.is_null()) {
        let mounts = mounts.as_array().context("mounts must be an array")?;
        for mount in mounts {
            validate_mount(mount)?;
        }
    }
    if let Some(annotations) = value.get("annotations").filter(|value| !value.is_null()) {
        let annotations = annotations
            .as_object()
            .context("annotations must be an object")?;
        if annotations.keys().any(String::is_empty) {
            bail!("annotations keys must not be empty");
        }
        if annotations.values().any(|value| !value.is_string()) {
            bail!("annotations values must be strings");
        }
    }
    Ok(())
}

fn validate_optional_string(value: &Value, field: &str, display: &str) -> Result<()> {
    if let Some(entry) = value.get(field)
        && !entry.is_null()
        && !entry.is_string()
    {
        bail!("{display} must be a string");
    }
    Ok(())
}

fn validate_process_noop_fields(process: &serde_json::Map<String, Value>) -> Result<()> {
    validate_scheduler(process)?;
    validate_io_priority(process)?;
    validate_exec_cpu_affinity(process)?;
    let process_value = Value::Object(process.clone());
    for field in ["apparmorProfile", "selinuxLabel"] {
        validate_optional_string(&process_value, field, &format!("process.{field}"))?;
    }
    Ok(())
}

fn validate_capabilities(process: &serde_json::Map<String, Value>) -> Result<()> {
    let Some(capabilities) = process.get("capabilities").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let Some(capabilities) = capabilities.as_object() else {
        return Ok(());
    };
    for set in [
        "effective",
        "bounding",
        "inheritable",
        "permitted",
        "ambient",
    ] {
        let Some(values) = capabilities.get(set).filter(|value| !value.is_null()) else {
            continue;
        };
        nlohmann_string_values(
            values,
            &format!("process.capabilities.{set} entries must be strings"),
        )?;
    }
    Ok(())
}

fn collect_capability_error(value: &Value) -> Option<String> {
    let capabilities = value
        .get("process")?
        .as_object()?
        .get("capabilities")?
        .as_object()?;
    for set in [
        "bounding",
        "effective",
        "permitted",
        "inheritable",
        "ambient",
    ] {
        let Some(values) = capabilities.get(set).filter(|value| !value.is_null()) else {
            continue;
        };
        let values = nlohmann_string_values(values, "capability values must be strings").ok()?;
        for name in values {
            match capability::parse_index(name) {
                None => return Some(format!("unknown capability: {name}")),
                Some(index) if capability::canonical_name(index).is_none() => {
                    return Some(format!("failed to set capability {name}: Invalid argument"));
                }
                Some(_) => {}
            }
        }
    }
    None
}

fn invalid_environment(value: &str) -> bool {
    value.as_bytes().contains(&0) || value.split_once('=').is_none_or(|(key, _)| key.is_empty())
}

fn nlohmann_string_values<'a>(value: &'a Value, display: &str) -> Result<Vec<&'a str>> {
    let values = match value {
        Value::Array(values) => values.iter().collect::<Vec<_>>(),
        Value::Object(values) => values.values().collect::<Vec<_>>(),
        _ => vec![value],
    };
    values
        .into_iter()
        .map(|value| value.as_str().with_context(|| display.to_string()))
        .collect()
}

fn validate_i32(value: &Value, display: &str) -> Result<i32> {
    cpp_number_as_i32(value).with_context(|| format!("{display} must be a number"))
}

fn cpp_number_as_u64(value: &Value) -> Option<u64> {
    let number = value.as_number()?;
    if let Some(value) = number.as_i64() {
        return Some(value as u64);
    }
    if let Some(value) = number.as_u64() {
        return Some(value);
    }
    let value = number.as_f64()?;
    if !value.is_finite() {
        return Some(0);
    }
    if value >= 0.0 {
        if value < 18_446_744_073_709_551_616.0 {
            Some(value.trunc() as u64)
        } else {
            Some(0)
        }
    } else if value >= -9_223_372_036_854_775_808.0 {
        Some((value.trunc() as i64) as u64)
    } else {
        Some(0)
    }
}

fn cpp_number_as_u32(value: &Value) -> Option<u32> {
    cpp_number_as_u64(value).map(|value| value as u32)
}

fn cpp_number_as_u16(value: &Value) -> Option<u16> {
    cpp_number_as_u64(value).map(|value| value as u16)
}

fn cpp_number_as_i64(value: &Value) -> Option<i64> {
    let number = value.as_number()?;
    if let Some(value) = number.as_i64() {
        return Some(value);
    }
    if let Some(value) = number.as_u64() {
        return Some(value as i64);
    }
    let value = number.as_f64()?;
    if value.is_finite()
        && (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&value)
    {
        Some(value.trunc() as i64)
    } else {
        Some(i64::MIN)
    }
}

fn cpp_number_as_i32(value: &Value) -> Option<i32> {
    let number = value.as_number()?;
    if let Some(value) = number.as_i64() {
        return Some(value as i32);
    }
    if let Some(value) = number.as_u64() {
        return Some(value as i32);
    }
    let value = number.as_f64()?;
    if value.is_finite() && (-2_147_483_648.0..2_147_483_648.0).contains(&value) {
        Some(value.trunc() as i32)
    } else {
        Some(i32::MIN)
    }
}

fn validate_console_size(process: &serde_json::Map<String, Value>) -> Result<()> {
    if !process
        .get("terminal")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(());
    }
    let Some(console) = process.get("consoleSize").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let console = console
        .as_object()
        .context("process.consoleSize must be an object")?;
    for field in ["height", "width"] {
        cpp_number_as_u16(
            console
                .get(field)
                .with_context(|| format!("process.consoleSize.{field} is required"))?,
        )
        .with_context(|| format!("process.consoleSize.{field} must be a number"))?;
    }
    Ok(())
}

fn validate_rlimits(process: &serde_json::Map<String, Value>) -> Result<()> {
    let Some(rlimits) = process.get("rlimits").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let rlimits = rlimits
        .as_array()
        .context("process.rlimits must be an array")?;
    let mut seen = std::collections::HashSet::new();
    for rlimit in rlimits {
        let rlimit = rlimit
            .as_object()
            .context("process.rlimits entries must be objects")?;
        let kind = rlimit
            .get("type")
            .and_then(Value::as_str)
            .context("rlimit.type is required")?;
        if !matches!(
            kind,
            "RLIMIT_AS"
                | "RLIMIT_CORE"
                | "RLIMIT_CPU"
                | "RLIMIT_DATA"
                | "RLIMIT_FSIZE"
                | "RLIMIT_LOCKS"
                | "RLIMIT_MEMLOCK"
                | "RLIMIT_MSGQUEUE"
                | "RLIMIT_NICE"
                | "RLIMIT_NOFILE"
                | "RLIMIT_NPROC"
                | "RLIMIT_RSS"
                | "RLIMIT_RTPRIO"
                | "RLIMIT_RTTIME"
                | "RLIMIT_SIGPENDING"
                | "RLIMIT_STACK"
        ) {
            bail!("unknown value: {kind}");
        }
        for field in ["soft", "hard"] {
            cpp_number_as_u64(
                rlimit
                    .get(field)
                    .with_context(|| format!("rlimit.{field} is required"))?,
            )
            .with_context(|| format!("rlimit.{field} must be an unsigned integer"))?;
        }
        if !seen.insert(kind) {
            bail!("duplicate rlimit type: {kind}");
        }
    }
    Ok(())
}

fn validate_user(process: &serde_json::Map<String, Value>) -> Result<()> {
    let Some(user) = process.get("user").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let user = user.as_object().context("process.user must be an object")?;
    for field in ["uid", "gid"] {
        cpp_number_as_u32(
            user.get(field)
                .with_context(|| format!("process.user.{field} is required"))?,
        )
        .with_context(|| format!("process.user.{field} must be a number"))?;
    }
    if let Some(umask) = user.get("umask").filter(|value| !value.is_null()) {
        cpp_number_as_u32(umask).context("process.user.umask must be a number")?;
    }
    if let Some(additional_gids) = user.get("additionalGids").filter(|value| !value.is_null()) {
        for gid in additional_gids
            .as_array()
            .context("process.user.additionalGids must be an array")?
        {
            cpp_number_as_u32(gid)
                .context("process.user.additionalGids entries must be numbers")?;
        }
    }
    Ok(())
}

fn validate_scheduler(process: &serde_json::Map<String, Value>) -> Result<()> {
    let Some(scheduler_value) = process.get("scheduler").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let scheduler = scheduler_value
        .as_object()
        .context("process.scheduler must be an object")?;
    let policy = scheduler
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
        if let Some(value) = scheduler.get(field).filter(|value| !value.is_null()) {
            validate_i32(value, &format!("scheduler.{field}"))?;
        }
    }
    if let Some(flags) = scheduler.get("flags").filter(|value| !value.is_null()) {
        for flag in nlohmann_string_values(flags, "scheduler.flags entries must be strings")? {
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
        if let Some(value) = scheduler.get(field).filter(|value| !value.is_null()) {
            cpp_number_as_u64(value)
                .with_context(|| format!("scheduler.{field} must be an unsigned integer"))?;
        }
    }
    if let Some(nice) = scheduler.get("nice").filter(|value| !value.is_null()) {
        let nice = cpp_number_as_i32(nice).context("scheduler.nice must be a number")?;
        if !(-20..=19).contains(&nice) {
            bail!("scheduler.nice must be in range [-20, 19]: got {nice}");
        }
    }
    if scheduler
        .get("priority")
        .filter(|value| !value.is_null())
        .and_then(cpp_number_as_i32)
        .is_some_and(|priority| priority != 0)
        && !matches!(policy, "SCHED_FIFO" | "SCHED_RR")
    {
        bail!("scheduler.priority can only be specified for SCHED_FIFO or SCHED_RR");
    }
    if ["runtime", "deadline", "period"]
        .iter()
        .any(|name| scheduler.get(*name).is_some_and(|entry| !entry.is_null()))
        && policy != "SCHED_DEADLINE"
    {
        bail!("scheduler runtime/deadline/period can only be specified for SCHED_DEADLINE");
    }
    Ok(())
}

fn validate_io_priority(process: &serde_json::Map<String, Value>) -> Result<()> {
    let Some(priority) = process.get("ioPriority") else {
        return Ok(());
    };
    if priority.is_null() {
        return Ok(());
    }
    let priority = priority
        .as_object()
        .context("process.ioPriority must be an object")?;
    let class = priority
        .get("class")
        .and_then(Value::as_str)
        .context("process.ioPriority.class is required")?;
    if !matches!(
        class,
        "IOPRIO_CLASS_RT" | "IOPRIO_CLASS_BE" | "IOPRIO_CLASS_IDLE"
    ) {
        bail!("unknown value: {class}");
    }
    let value = priority
        .get("priority")
        .map(|value| {
            cpp_number_as_i32(value)
                .map(i64::from)
                .context("process.ioPriority.priority must be an integer")
        })
        .transpose()?
        .unwrap_or(0);
    if !(0..=7).contains(&value) {
        bail!("io priority must be in range [0, 7], got: {value}");
    }
    Ok(())
}

fn validate_exec_cpu_affinity(process: &serde_json::Map<String, Value>) -> Result<()> {
    let Some(affinity) = process.get("execCPUAffinity") else {
        return Ok(());
    };
    if affinity.is_null() {
        return Ok(());
    }
    let Some(affinity) = affinity.as_object() else {
        return Ok(());
    };
    for field in ["initial", "final"] {
        if let Some(value) = affinity.get(field)
            && !value.is_null()
            && !value.is_string()
        {
            bail!("process.execCPUAffinity.{field} must be a string");
        }
    }
    Ok(())
}

fn validate_linux(linux: &serde_json::Map<String, Value>) -> Result<()> {
    validate_id_mappings(linux.get("uidMappings"), "linux.uidMappings")?;
    validate_id_mappings(linux.get("gidMappings"), "linux.gidMappings")?;
    if let Some(namespaces) = linux.get("namespaces").filter(|value| !value.is_null()) {
        let namespaces = namespaces
            .as_array()
            .context("linux.namespaces must be an array")?;
        let mut seen = std::collections::HashSet::new();
        for namespace in namespaces {
            let namespace = namespace
                .as_object()
                .context("linux.namespaces entries must be objects")?;
            let kind = namespace
                .get("type")
                .and_then(Value::as_str)
                .context("namespace.type is required")?;
            if !matches!(
                kind,
                "ipc" | "uts" | "mount" | "pid" | "network" | "user" | "cgroup" | "time"
            ) {
                bail!("unknown namespace type: {kind}");
            }
            if !seen.insert(kind) {
                bail!("duplicate namespace type: {kind}");
            }
            if let Some(path) = namespace.get("path").filter(|value| !value.is_null()) {
                let path = path.as_str().context("namespace path must be a string")?;
                if path.is_empty() {
                    bail!("namespace path must not be empty for type: {kind}");
                }
                if !Path::new(path).is_absolute() {
                    bail!("namespace path must be absolute for type: {kind}, got: {path}");
                }
            }
        }
    }
    for name in ["maskedPaths", "readonlyPaths"] {
        if let Some(paths) = linux.get(name).and_then(Value::as_array) {
            for path in paths {
                let path = path
                    .as_str()
                    .context("linux path entries must be strings")?;
                if !Path::new(path).is_absolute() {
                    bail!("{name} must be absolute paths, got: {path}");
                }
            }
        }
    }
    if let Some(swappiness) = linux
        .get("resources")
        .and_then(|resources| resources.pointer("/memory/swappiness"))
        .and_then(Value::as_u64)
        && swappiness > 100
    {
        bail!("memory.swappiness must be in range [0, 100], got: {swappiness}");
    }
    let quota = linux
        .get("resources")
        .and_then(|resources| resources.pointer("/cpu/quota"))
        .and_then(Value::as_i64);
    let burst = linux
        .get("resources")
        .and_then(|resources| resources.pointer("/cpu/burst"))
        .and_then(Value::as_u64);
    if quota.is_some_and(|quota| quota > 0)
        && burst.is_some_and(|burst| burst > quota.unwrap_or_default() as u64)
    {
        bail!("cpu.quota must be no smaller than cpu.burst");
    }
    validate_linux_devices(linux.get("devices"))?;
    validate_net_devices(linux.get("netDevices"))?;
    let linux_value = Value::Object(linux.clone());
    validate_optional_string(&linux_value, "cgroupsPath", "linux.cgroupsPath")?;
    if let Some(propagation) = linux
        .get("rootfsPropagation")
        .filter(|value| !value.is_null())
    {
        let propagation = propagation
            .as_str()
            .context("linux.rootfsPropagation must be a string")?;
        if !matches!(
            propagation,
            "private"
                | "rprivate"
                | "shared"
                | "rshared"
                | "slave"
                | "rslave"
                | "unbindable"
                | "runbindable"
        ) {
            bail!("unknown value: {propagation}");
        }
    }
    validate_string_map(linux.get("sysctl"), "linux.sysctl")?;
    validate_resources(linux.get("resources"))?;
    validate_personality(linux.get("personality"))?;
    validate_memory_policy(linux.get("memoryPolicy"))?;
    validate_time_offsets(linux.get("timeOffsets"))?;
    validate_intel_rdt(linux.get("intelRdt"))?;
    if let Some(label) = linux.get("mountLabel")
        && !label.is_null()
        && !label.is_string()
    {
        bail!("linux.mountLabel must be a string");
    }
    validate_seccomp(linux.get("seccomp"))
}

fn collect_namespace_paths(value: &Value) -> Vec<NamespacePath> {
    value
        .pointer("/linux/namespaces")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|namespace| {
            Some(NamespacePath {
                kind: namespace.get("type")?.as_str()?.to_string(),
                path: PathBuf::from(namespace.get("path")?.as_str()?),
            })
        })
        .collect()
}

fn validate_id_mappings(mappings: Option<&Value>, display: &str) -> Result<()> {
    let Some(mappings) = mappings.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    for mapping in mappings
        .as_array()
        .with_context(|| format!("{display} must be an array"))?
    {
        let mapping = mapping
            .as_object()
            .with_context(|| format!("{display} entries must be objects"))?;
        for field in ["hostID", "containerID"] {
            cpp_number_as_u32(
                mapping
                    .get(field)
                    .with_context(|| format!("{display}.{field} is required"))?,
            )
            .with_context(|| format!("{display}.{field} must be a number"))?;
        }
        cpp_number_as_u64(
            mapping
                .get("size")
                .with_context(|| format!("{display}.size is required"))?,
        )
        .with_context(|| format!("{display}.size must be a number"))?;
    }
    Ok(())
}

fn validate_linux_devices(devices: Option<&Value>) -> Result<()> {
    let Some(devices) = devices.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    for device in devices
        .as_array()
        .context("linux.devices must be an array")?
    {
        let device = device
            .as_object()
            .context("linux.devices entries must be objects")?;
        for field in ["type", "path"] {
            device
                .get(field)
                .and_then(Value::as_str)
                .with_context(|| format!("linux.devices.{field} must be a string"))?;
        }
        for field in ["major", "minor", "fileMode", "uid", "gid"] {
            if let Some(value) = device.get(field).filter(|value| !value.is_null()) {
                cpp_number_as_u32(value)
                    .with_context(|| format!("linux.devices.{field} must be a number"))?;
            }
        }
    }
    Ok(())
}

fn validate_net_devices(devices: Option<&Value>) -> Result<()> {
    let Some(devices) = devices.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    for device in devices
        .as_object()
        .context("linux.netDevices must be an object")?
        .values()
    {
        let Some(device) = device.as_object() else {
            continue;
        };
        if let Some(name) = device.get("name")
            && !name.is_null()
            && !name.is_string()
        {
            bail!("linux.netDevices.name must be a string");
        }
    }
    Ok(())
}

fn validate_string_map(value: Option<&Value>, display: &str) -> Result<()> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let entries = value
        .as_object()
        .with_context(|| format!("{display} must be an object"))?;
    if entries.values().any(|entry| !entry.is_string()) {
        bail!("{display} values must be strings");
    }
    Ok(())
}

fn validate_resources(resources: Option<&Value>) -> Result<()> {
    let Some(resources) = resources.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let Some(resources) = resources.as_object() else {
        return Ok(());
    };

    validate_string_map(resources.get("unified"), "linux.resources.unified")?;
    validate_resource_devices(resources.get("devices"))?;
    validate_resource_memory(resources.get("memory"))?;
    validate_resource_cpu(resources.get("cpu"))?;
    validate_resource_block_io(resources.get("blockIO"))?;
    validate_resource_hugepages(resources.get("hugepageLimits"))?;
    validate_resource_network(resources.get("network"))?;
    validate_resource_pids(resources.get("pids"))?;
    validate_resource_rdma(resources.get("rdma"))
}

fn validate_resource_devices(devices: Option<&Value>) -> Result<()> {
    let Some(devices) = devices.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    for device in devices
        .as_array()
        .context("linux.resources.devices must be an array")?
    {
        let device = device
            .as_object()
            .context("linux.resources.devices entries must be objects")?;
        device
            .get("allow")
            .and_then(Value::as_bool)
            .context("linux.resources.devices.allow must be a boolean")?;
        validate_optional_type(
            device,
            "type",
            "linux.resources.devices.type",
            Value::is_string,
        )?;
        validate_optional_type(device, "major", "linux.resources.devices.major", |value| {
            cpp_number_as_i64(value).is_some()
        })?;
        validate_optional_type(device, "minor", "linux.resources.devices.minor", |value| {
            cpp_number_as_i64(value).is_some()
        })?;
        validate_optional_type(
            device,
            "access",
            "linux.resources.devices.access",
            Value::is_string,
        )?;
    }
    Ok(())
}

fn validate_resource_memory(memory: Option<&Value>) -> Result<()> {
    let Some(memory) = memory.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let Some(memory) = memory.as_object() else {
        return Ok(());
    };
    for field in ["limit", "reservation", "swap", "kernel", "kernelTCP"] {
        validate_optional_type(
            memory,
            field,
            &format!("linux.resources.memory.{field}"),
            |value| cpp_number_as_i64(value).is_some(),
        )?;
    }
    if let Some(swappiness) = memory.get("swappiness").filter(|value| !value.is_null()) {
        let swappiness = cpp_number_as_u64(swappiness)
            .context("linux.resources.memory.swappiness must be an unsigned integer")?;
        if swappiness > 100 {
            bail!("memory.swappiness must be in range [0, 100], got: {swappiness}");
        }
    }
    for field in ["disableOOMKiller", "useHierarchy", "checkBeforeUpdate"] {
        validate_optional_type(
            memory,
            field,
            &format!("linux.resources.memory.{field}"),
            Value::is_boolean,
        )?;
    }
    Ok(())
}

fn validate_resource_cpu(cpu: Option<&Value>) -> Result<()> {
    let Some(cpu) = cpu.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let Some(cpu) = cpu.as_object() else {
        return Ok(());
    };
    for field in ["shares", "burst", "period", "realtimePeriod"] {
        validate_optional_type(
            cpu,
            field,
            &format!("linux.resources.cpu.{field}"),
            |value| cpp_number_as_u64(value).is_some(),
        )?;
    }
    for field in ["quota", "realtimeRuntime", "idle"] {
        validate_optional_type(
            cpu,
            field,
            &format!("linux.resources.cpu.{field}"),
            |value| cpp_number_as_i64(value).is_some(),
        )?;
    }
    for field in ["cpus", "mems"] {
        if let Some(value) = cpu.get(field).filter(|value| !value.is_null()) {
            validate_range_list(
                value
                    .as_str()
                    .with_context(|| format!("linux.resources.cpu.{field} must be a string"))?,
            )?;
        }
    }
    let quota = cpu.get("quota").and_then(cpp_number_as_i64);
    let burst = cpu.get("burst").and_then(cpp_number_as_u64);
    if quota.is_some_and(|quota| quota > 0)
        && burst.is_some_and(|burst| burst > quota.unwrap_or_default() as u64)
    {
        bail!("cpu.quota must be no smaller than cpu.burst");
    }
    Ok(())
}

fn validate_resource_block_io(block_io: Option<&Value>) -> Result<()> {
    let Some(block_io) = block_io.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let Some(block_io) = block_io.as_object() else {
        return Ok(());
    };
    for field in ["weight", "leafWeight"] {
        if let Some(value) = block_io.get(field).filter(|value| !value.is_null()) {
            validate_u16(value, &format!("linux.resources.blockIO.{field}"))?;
        }
    }
    if let Some(devices) = block_io
        .get("weightDevice")
        .filter(|value| !value.is_null())
    {
        for device in devices
            .as_array()
            .context("linux.resources.blockIO.weightDevice must be an array")?
        {
            let device = device
                .as_object()
                .context("linux.resources.blockIO.weightDevice entries must be objects")?;
            require_i64(
                device,
                "major",
                "linux.resources.blockIO.weightDevice.major",
            )?;
            require_i64(
                device,
                "minor",
                "linux.resources.blockIO.weightDevice.minor",
            )?;
            for field in ["weight", "leafWeight"] {
                if let Some(value) = device.get(field).filter(|value| !value.is_null()) {
                    validate_u16(
                        value,
                        &format!("linux.resources.blockIO.weightDevice.{field}"),
                    )?;
                }
            }
        }
    }
    for field in [
        "throttleReadBpsDevice",
        "throttleWriteBpsDevice",
        "throttleReadIOPSDevice",
        "throttleWriteIOPSDevice",
    ] {
        let Some(devices) = block_io.get(field).filter(|value| !value.is_null()) else {
            continue;
        };
        for device in devices
            .as_array()
            .with_context(|| format!("linux.resources.blockIO.{field} must be an array"))?
        {
            let device = device.as_object().with_context(|| {
                format!("linux.resources.blockIO.{field} entries must be objects")
            })?;
            require_i64(
                device,
                "major",
                &format!("linux.resources.blockIO.{field}.major"),
            )?;
            require_i64(
                device,
                "minor",
                &format!("linux.resources.blockIO.{field}.minor"),
            )?;
            device
                .get("rate")
                .and_then(cpp_number_as_u64)
                .with_context(|| format!("linux.resources.blockIO.{field}.rate is required"))?;
        }
    }
    Ok(())
}

fn validate_resource_hugepages(hugepages: Option<&Value>) -> Result<()> {
    let Some(hugepages) = hugepages.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    for hugepage in hugepages
        .as_array()
        .context("linux.resources.hugepageLimits must be an array")?
    {
        let hugepage = hugepage
            .as_object()
            .context("linux.resources.hugepageLimits entries must be objects")?;
        hugepage
            .get("pageSize")
            .and_then(Value::as_str)
            .context("linux.resources.hugepageLimits.pageSize is required")?;
        hugepage
            .get("limit")
            .and_then(cpp_number_as_u64)
            .context("linux.resources.hugepageLimits.limit is required")?;
    }
    Ok(())
}

fn validate_resource_network(network: Option<&Value>) -> Result<()> {
    let Some(network) = network.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let Some(network) = network.as_object() else {
        return Ok(());
    };
    if let Some(class_id) = network.get("classID").filter(|value| !value.is_null()) {
        validate_u32(class_id, "linux.resources.network.classID")?;
    }
    if let Some(priorities) = network.get("priorities").filter(|value| !value.is_null()) {
        for priority in priorities
            .as_array()
            .context("linux.resources.network.priorities must be an array")?
        {
            let priority = priority
                .as_object()
                .context("linux.resources.network.priorities entries must be objects")?;
            priority
                .get("name")
                .and_then(Value::as_str)
                .context("linux.resources.network.priorities.name is required")?;
            let value = priority
                .get("priority")
                .context("linux.resources.network.priorities.priority is required")?;
            validate_u32(value, "linux.resources.network.priorities.priority")?;
        }
    }
    Ok(())
}

fn validate_resource_pids(pids: Option<&Value>) -> Result<()> {
    let Some(pids) = pids.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let Some(pids) = pids.as_object() else {
        return Ok(());
    };
    validate_optional_type(pids, "limit", "linux.resources.pids.limit", |value| {
        cpp_number_as_i64(value).is_some()
    })
}

fn validate_resource_rdma(rdma: Option<&Value>) -> Result<()> {
    let Some(rdma) = rdma.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    for limits in rdma
        .as_object()
        .context("linux.resources.rdma must be an object")?
        .values()
    {
        let Some(limits) = limits.as_object() else {
            continue;
        };
        for field in ["hcaHandles", "hcaObjects"] {
            if let Some(value) = limits.get(field).filter(|value| !value.is_null()) {
                validate_u32(value, &format!("linux.resources.rdma.{field}"))?;
            }
        }
    }
    Ok(())
}

fn validate_optional_type(
    object: &serde_json::Map<String, Value>,
    field: &str,
    display: &str,
    predicate: impl Fn(&Value) -> bool,
) -> Result<()> {
    if let Some(value) = object.get(field).filter(|value| !value.is_null())
        && !predicate(value)
    {
        bail!("{display} has an invalid type");
    }
    Ok(())
}

fn require_i64(object: &serde_json::Map<String, Value>, field: &str, display: &str) -> Result<i64> {
    object
        .get(field)
        .and_then(cpp_number_as_i64)
        .with_context(|| format!("{display} is required"))
}

fn validate_u16(value: &Value, display: &str) -> Result<u16> {
    let value = cpp_number_as_u16(value)
        .with_context(|| format!("{display} must be an unsigned integer"))?;
    Ok(value)
}

fn validate_u32(value: &Value, display: &str) -> Result<u32> {
    let value = cpp_number_as_u32(value)
        .with_context(|| format!("{display} must be an unsigned integer"))?;
    Ok(value)
}

fn validate_personality(personality: Option<&Value>) -> Result<()> {
    let Some(personality) = personality.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let personality = personality
        .as_object()
        .context("linux.personality must be an object")?;
    let domain = personality
        .get("domain")
        .and_then(Value::as_str)
        .context("linux.personality.domain is required")?;
    if !matches!(domain, "LINUX" | "LINUX32") {
        bail!("unknown value: {domain}");
    }
    if let Some(flags) = personality.get("flags").filter(|value| !value.is_null()) {
        let flags = flags
            .as_array()
            .context("linux.personality.flags must be an array")?;
        if flags.iter().any(|flag| !flag.is_string()) {
            bail!("linux.personality.flags entries must be strings");
        }
    }
    Ok(())
}

fn validate_memory_policy(policy: Option<&Value>) -> Result<()> {
    let Some(policy) = policy.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let policy = policy
        .as_object()
        .context("linux.memoryPolicy must be an object")?;
    let mode = policy
        .get("mode")
        .and_then(Value::as_str)
        .context("linux.memoryPolicy.mode is required")?;
    if !matches!(
        mode,
        "MPOL_DEFAULT"
            | "MPOL_BIND"
            | "MPOL_INTERLEAVE"
            | "MPOL_WEIGHTED_INTERLEAVE"
            | "MPOL_PREFERRED"
            | "MPOL_PREFERRED_MANY"
            | "MPOL_LOCAL"
    ) {
        bail!("unknown value: {mode}");
    }
    if let Some(nodes) = policy.get("nodes").filter(|value| !value.is_null()) {
        validate_range_list(
            nodes
                .as_str()
                .context("linux.memoryPolicy.nodes must be a string")?,
        )?;
    }
    if let Some(flags) = policy.get("flags").filter(|value| !value.is_null()) {
        for flag in
            nlohmann_string_values(flags, "linux.memoryPolicy.flags entries must be strings")?
        {
            if !matches!(
                flag,
                "MPOL_F_NUMA_BALANCING" | "MPOL_F_RELATIVE_NODES" | "MPOL_F_STATIC_NODES"
            ) {
                bail!("unknown value: {flag}");
            }
        }
    }
    Ok(())
}

fn validate_range_list(value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    let entries = value.split(',').collect::<Vec<_>>();
    for (index, entry) in entries.iter().enumerate() {
        let entry = entry.trim_ascii();
        if entry.is_empty() && index + 1 == entries.len() {
            continue;
        }
        let (start, finish) = entry
            .split_once('-')
            .map_or((entry, None), |(start, finish)| {
                (start.trim_ascii(), Some(finish.trim_ascii()))
            });
        let start = parse_range_number(start, "value", entry)?;
        if let Some(finish) = finish {
            let finish = parse_range_number(finish, "range end", entry)?;
            if finish < start {
                bail!("invalid range in range list (finish < start) at: {entry}");
            }
            if start == 0 && finish == u32::MAX {
                bail!("range too large in range list at: {entry}");
            }
        }
    }
    Ok(())
}

fn parse_range_number(value: &str, kind: &str, entry: &str) -> Result<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("invalid {kind} in range list at: {entry}");
    }
    value
        .parse::<u32>()
        .with_context(|| format!("{kind} overflow in range list at: {entry}"))
}

fn validate_time_offsets(offsets: Option<&Value>) -> Result<()> {
    let Some(offsets) = offsets.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let values = match offsets {
        Value::Object(offsets) => offsets.values().collect::<Vec<_>>(),
        Value::Array(offsets) => offsets.iter().collect::<Vec<_>>(),
        _ => vec![offsets],
    };
    for offset in values {
        let offset = offset
            .as_object()
            .context("linux.timeOffsets entries must be objects")?;
        offset
            .get("secs")
            .and_then(cpp_number_as_i64)
            .context("linux.timeOffsets.secs must be an integer")?;
        cpp_number_as_u32(
            offset
                .get("nanosecs")
                .context("linux.timeOffsets.nanosecs is required")?,
        )
        .context("linux.timeOffsets.nanosecs must be an unsigned integer")?;
    }
    Ok(())
}

fn validate_intel_rdt(intel_rdt: Option<&Value>) -> Result<()> {
    let Some(intel_rdt) = intel_rdt.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let Some(intel_rdt) = intel_rdt.as_object() else {
        return Ok(());
    };
    for field in ["closID", "l3CacheSchema", "memBwSchema"] {
        if let Some(value) = intel_rdt.get(field)
            && !value.is_null()
            && !value.is_string()
        {
            bail!("linux.intelRdt.{field} must be a string");
        }
    }
    if let Some(schemata) = intel_rdt.get("schemata").filter(|value| !value.is_null()) {
        let schemata = schemata
            .as_array()
            .context("linux.intelRdt.schemata must be an array")?;
        if schemata.iter().any(|schema| !schema.is_string()) {
            bail!("linux.intelRdt.schemata entries must be strings");
        }
    }
    if let Some(monitoring) = intel_rdt
        .get("enableMonitoring")
        .filter(|value| !value.is_null())
        && !monitoring.is_boolean()
    {
        bail!("linux.intelRdt.enableMonitoring must be a boolean");
    }
    Ok(())
}

fn strip_upstream_noop_fields(value: &mut Value) {
    normalize_cpp_numeric_fields(value);
    value.as_object_mut().into_iter().for_each(|object| {
        object.remove("hostname");
        object.remove("domainname");
        if object.get("linux").is_none_or(|value| !value.is_object()) {
            object.insert("linux".to_string(), Value::Object(Default::default()));
        }
        if object.get("hooks").is_some_and(|value| !value.is_object()) {
            object.insert("hooks".to_string(), Value::Object(Default::default()));
        }
    });
    if let Some(process) = value.get_mut("process").and_then(Value::as_object_mut) {
        strip_upstream_noop_process_fields(process);
    }
    if let Some(linux) = value.get_mut("linux").and_then(Value::as_object_mut) {
        let has_user_namespace = linux
            .get("namespaces")
            .and_then(Value::as_array)
            .is_some_and(|namespaces| {
                namespaces
                    .iter()
                    .any(|namespace| namespace.get("type").and_then(Value::as_str) == Some("user"))
            });
        if !has_user_namespace {
            linux.remove("uidMappings");
            linux.remove("gidMappings");
        }
        for field in [
            "devices",
            "netDevices",
            "cgroupsPath",
            "resources",
            "sysctl",
            "seccomp",
            "personality",
            "memoryPolicy",
            "timeOffsets",
            "intelRdt",
            "mountLabel",
        ] {
            linux.remove(field);
        }
        if let Some(namespaces) = linux.get_mut("namespaces").and_then(Value::as_array_mut) {
            for namespace in namespaces {
                if let Some(namespace) = namespace.as_object_mut() {
                    namespace.remove("path");
                }
            }
        }
    }
}

fn normalize_cpp_numeric_fields(value: &mut Value) {
    if let Some(process) = value.get_mut("process").and_then(Value::as_object_mut) {
        if process
            .get("terminal")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && let Some(console) = process
                .get_mut("consoleSize")
                .and_then(Value::as_object_mut)
        {
            for field in ["height", "width"] {
                if let Some(value) = console.get_mut(field) {
                    *value = Value::from(
                        cpp_number_as_u16(value)
                            .expect("console size is validated before normalization"),
                    );
                }
            }
        }
        if let Some(rlimits) = process.get_mut("rlimits").and_then(Value::as_array_mut) {
            for rlimit in rlimits.iter_mut().filter_map(Value::as_object_mut) {
                for field in ["soft", "hard"] {
                    if let Some(value) = rlimit.get_mut(field) {
                        *value = Value::from(
                            cpp_number_as_u64(value)
                                .expect("rlimits are validated before normalization"),
                        );
                    }
                }
            }
        }
        if let Some(user) = process.get_mut("user").and_then(Value::as_object_mut) {
            for field in ["uid", "gid", "umask"] {
                if let Some(value) = user.get_mut(field).filter(|value| !value.is_null()) {
                    *value = Value::from(
                        cpp_number_as_u32(value)
                            .expect("process user is validated before normalization"),
                    );
                }
            }
            if let Some(gids) = user.get_mut("additionalGids").and_then(Value::as_array_mut) {
                for gid in gids {
                    *gid = Value::from(
                        cpp_number_as_u32(gid)
                            .expect("additional gids are validated before normalization"),
                    );
                }
            }
        }
        if let Some(score) = process
            .get_mut("oomScoreAdj")
            .filter(|value| !value.is_null())
            && let Some(score_value) = cpp_number_as_i32(score)
        {
            *score = Value::from(score_value);
        }
    }

    if let Some(linux) = value.get_mut("linux").and_then(Value::as_object_mut) {
        for field in ["uidMappings", "gidMappings"] {
            normalize_id_mappings(linux.get_mut(field));
        }
    }

    if let Some(hooks) = value.get_mut("hooks").and_then(Value::as_object_mut) {
        for name in [
            "prestart",
            "createRuntime",
            "createContainer",
            "startContainer",
            "poststart",
            "poststop",
        ] {
            let Some(entries) = hooks.get_mut(name).and_then(Value::as_array_mut) else {
                continue;
            };
            for hook in entries.iter_mut().filter_map(Value::as_object_mut) {
                if let Some(timeout) = hook.get_mut("timeout").filter(|value| !value.is_null()) {
                    *timeout = Value::from(
                        cpp_number_as_i32(timeout)
                            .expect("hook timeout is validated before normalization"),
                    );
                }
            }
        }
    }
}

fn normalize_id_mappings(mappings: Option<&mut Value>) {
    let Some(mappings) = mappings.and_then(Value::as_array_mut) else {
        return;
    };
    for mapping in mappings.iter_mut().filter_map(Value::as_object_mut) {
        for field in ["hostID", "containerID"] {
            if let Some(value) = mapping.get_mut(field) {
                *value = Value::from(
                    cpp_number_as_u32(value)
                        .expect("ID mappings are validated before normalization"),
                );
            }
        }
        if let Some(value) = mapping.get_mut("size") {
            let size =
                cpp_number_as_u64(value).expect("ID mappings are validated before normalization");
            *value = Value::from(u32::try_from(size).unwrap_or(0));
        }
    }
}

fn strip_upstream_noop_process_fields(process: &mut serde_json::Map<String, Value>) {
    if process.get("user").is_none_or(Value::is_null) {
        process.insert("user".to_string(), serde_json::json!({"uid": 0, "gid": 0}));
    }
    if !process
        .get("terminal")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        process.remove("consoleSize");
    }
    normalize_upstream_process_boole(process);
    normalize_process_capabilities(process);
    process.remove("scheduler");
    process.remove("apparmorProfile");
    process.remove("selinuxLabel");
    process.remove("ioPriority");
    process.remove("execCPUAffinity");
}

fn normalize_process_capabilities(process: &mut serde_json::Map<String, Value>) {
    let Some(capabilities) = process.get_mut("capabilities") else {
        return;
    };
    if !capabilities.is_object() {
        *capabilities = Value::Object(Default::default());
        return;
    }
    let capabilities = capabilities
        .as_object_mut()
        .expect("capabilities was normalized to an object");
    for set in [
        "effective",
        "bounding",
        "inheritable",
        "permitted",
        "ambient",
    ] {
        let Some(values) = capabilities.get_mut(set) else {
            continue;
        };
        if values.is_null() {
            continue;
        }
        let normalized = nlohmann_string_values(values, "capability values must be strings")
            .expect("capabilities are validated before normalization")
            .into_iter()
            .filter_map(capability::parse_index)
            .filter_map(capability::canonical_name)
            .map(Value::String)
            .collect();
        *values = Value::Array(normalized);
    }
}

fn normalize_upstream_process_boole(process: &mut serde_json::Map<String, Value>) {
    for field in ["terminal", "noNewPrivileges"] {
        if matches!(process.get(field), Some(Value::Bool(_))) {
            process.insert(field.to_string(), Value::Bool(true));
        }
    }
}

fn validate_seccomp_enum_values(seccomp: &serde_json::Map<String, Value>) -> Result<()> {
    let valid_action = |action: &str| {
        matches!(
            action,
            "SCMP_ACT_ALLOW"
                | "SCMP_ACT_ERRNO"
                | "SCMP_ACT_KILL"
                | "SCMP_ACT_KILL_PROCESS"
                | "SCMP_ACT_KILL_THREAD"
                | "SCMP_ACT_LOG"
                | "SCMP_ACT_NOTIFY"
                | "SCMP_ACT_TRACE"
                | "SCMP_ACT_TRAP"
        )
    };
    if let Some(action) = seccomp.get("defaultAction").and_then(Value::as_str)
        && !valid_action(action)
    {
        bail!("unknown value: {action}");
    }
    if let Some(architectures) = seccomp.get("architectures").and_then(Value::as_array) {
        for architecture in architectures.iter().filter_map(Value::as_str) {
            if !matches!(
                architecture,
                "SCMP_ARCH_X86"
                    | "SCMP_ARCH_X86_64"
                    | "SCMP_ARCH_X32"
                    | "SCMP_ARCH_ARM"
                    | "SCMP_ARCH_AARCH64"
                    | "SCMP_ARCH_MIPS"
                    | "SCMP_ARCH_MIPS64"
                    | "SCMP_ARCH_MIPS64N32"
                    | "SCMP_ARCH_MIPSEL"
                    | "SCMP_ARCH_MIPSEL64"
                    | "SCMP_ARCH_MIPSEL64N32"
                    | "SCMP_ARCH_PPC"
                    | "SCMP_ARCH_PPC64"
                    | "SCMP_ARCH_PPC64LE"
                    | "SCMP_ARCH_S390"
                    | "SCMP_ARCH_S390X"
                    | "SCMP_ARCH_PARISC"
                    | "SCMP_ARCH_PARISC64"
                    | "SCMP_ARCH_RISCV64"
                    | "SCMP_ARCH_LOONGARCH64"
                    | "SCMP_ARCH_M68K"
                    | "SCMP_ARCH_SH"
                    | "SCMP_ARCH_SHEB"
            ) {
                bail!("unknown architecture: {architecture}");
            }
        }
    }
    if let Some(flags) = seccomp.get("flags").and_then(Value::as_array) {
        for flag in flags.iter().filter_map(Value::as_str) {
            if !matches!(
                flag,
                "SECCOMP_FILTER_FLAG_TSYNC"
                    | "SECCOMP_FILTER_FLAG_LOG"
                    | "SECCOMP_FILTER_FLAG_SPEC_ALLOW"
                    | "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV"
            ) {
                bail!("unknown value: {flag}");
            }
        }
    }
    if let Some(syscalls) = seccomp.get("syscalls").and_then(Value::as_array) {
        for syscall in syscalls.iter().filter_map(Value::as_object) {
            if let Some(action) = syscall.get("action").and_then(Value::as_str)
                && !valid_action(action)
            {
                bail!("unknown value: {action}");
            }
            if let Some(arguments) = syscall.get("args").and_then(Value::as_array) {
                for argument in arguments.iter().filter_map(Value::as_object) {
                    if let Some(operator) = argument.get("op").and_then(Value::as_str)
                        && !matches!(
                            operator,
                            "SCMP_CMP_EQ"
                                | "SCMP_CMP_NE"
                                | "SCMP_CMP_LT"
                                | "SCMP_CMP_LE"
                                | "SCMP_CMP_GT"
                                | "SCMP_CMP_GE"
                                | "SCMP_CMP_MASKED_EQ"
                        )
                    {
                        bail!("unknown value: {operator}");
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_seccomp(seccomp: Option<&Value>) -> Result<()> {
    let Some(seccomp_value) = seccomp.filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let seccomp = seccomp_value
        .as_object()
        .context("linux.seccomp must be an object")?;
    validate_seccomp_enum_values(seccomp)?;
    let mut normalized = seccomp_value.clone();
    if let Some(seccomp) = normalized.as_object_mut() {
        for field in ["architectures", "flags"] {
            if let Some(values) = seccomp.get_mut(field).filter(|value| !value.is_null()) {
                *values = Value::Array(
                    nlohmann_string_values(values, "seccomp entries must be strings")?
                        .into_iter()
                        .map(|value| Value::String(value.to_string()))
                        .collect(),
                );
            }
        }
        if let Some(errno) = seccomp
            .get_mut("defaultErrnoRet")
            .filter(|value| !value.is_null())
            && let Some(errno_value) = cpp_number_as_u32(errno)
        {
            *errno = Value::from(errno_value);
        }
        if let Some(syscalls) = seccomp.get_mut("syscalls").and_then(Value::as_array_mut) {
            for syscall in syscalls.iter_mut().filter_map(Value::as_object_mut) {
                if let Some(errno) = syscall.get_mut("errnoRet").filter(|value| !value.is_null())
                    && let Some(errno_value) = cpp_number_as_u32(errno)
                {
                    *errno = Value::from(errno_value);
                }
                let Some(arguments) = syscall.get_mut("args").and_then(Value::as_array_mut) else {
                    continue;
                };
                for argument in arguments.iter_mut().filter_map(Value::as_object_mut) {
                    if let Some(index) = argument.get_mut("index")
                        && let Some(index_value) = cpp_number_as_u32(index)
                    {
                        *index = Value::from(index_value);
                    }
                    for field in ["value", "valueTwo"] {
                        if let Some(value) =
                            argument.get_mut(field).filter(|value| !value.is_null())
                            && let Some(normalized) = cpp_number_as_u64(value)
                        {
                            *value = Value::from(normalized);
                        }
                    }
                }
            }
        }
    }
    serde_json::from_value::<LinuxSeccomp>(normalized).context("invalid linux.seccomp")?;
    let action = seccomp
        .get("defaultAction")
        .and_then(Value::as_str)
        .context("seccomp.defaultAction is required")?;
    if seccomp
        .get("defaultErrnoRet")
        .is_some_and(|entry| !entry.is_null())
        && !matches!(action, "SCMP_ACT_ERRNO" | "SCMP_ACT_TRACE")
    {
        bail!("seccomp defaultErrnoRet is only valid with SCMP_ACT_ERRNO or SCMP_ACT_TRACE");
    }
    if action == "SCMP_ACT_NOTIFY" && seccomp.get("listenerPath").is_none_or(Value::is_null) {
        bail!("seccomp SCMP_ACT_NOTIFY requires listenerPath");
    }
    if seccomp
        .get("listenerMetadata")
        .is_some_and(|entry| !entry.is_null())
        && seccomp.get("listenerPath").is_none_or(Value::is_null)
    {
        bail!("seccomp listenerMetadata requires listenerPath to be set");
    }
    if let Some(syscalls) = seccomp.get("syscalls").and_then(Value::as_array) {
        for syscall in syscalls {
            let names = syscall
                .get("names")
                .and_then(Value::as_array)
                .context("seccomp syscall names are required")?;
            if names.is_empty() {
                bail!("seccomp syscall names must not be empty");
            }
            let action = syscall
                .get("action")
                .and_then(Value::as_str)
                .context("seccomp syscall action is required")?;
            if syscall
                .get("errnoRet")
                .is_some_and(|entry| !entry.is_null())
                && !matches!(action, "SCMP_ACT_ERRNO" | "SCMP_ACT_TRACE")
            {
                bail!(
                    "seccomp syscall errnoRet is only valid with SCMP_ACT_ERRNO or SCMP_ACT_TRACE"
                );
            }
        }
    }
    Ok(())
}

fn validate_hook(hook: &Value) -> Result<()> {
    let path = hook
        .get("path")
        .and_then(Value::as_str)
        .context("hook path is required")?;
    if !Path::new(path).is_absolute() {
        bail!("hook path must be absolute");
    }
    if let Some(environment) = hook.get("env").and_then(Value::as_array) {
        for entry in environment {
            let entry = entry.as_str().context("hook.env entries must be strings")?;
            if invalid_environment(entry) {
                bail!("hook.env contains a invalid env: {entry}");
            }
        }
    }
    if let Some(timeout) = hook.get("timeout").filter(|value| !value.is_null()) {
        let timeout = cpp_number_as_i32(timeout).context("hook timeout must be a number")?;
        if timeout <= 0 {
            bail!("hook timeout must be greater than zero");
        }
    }
    Ok(())
}

fn validate_mount(mount: &Value) -> Result<()> {
    let destination = mount
        .get("destination")
        .and_then(Value::as_str)
        .context("mount.destination is required")?;
    if !Path::new(destination).is_absolute() {
        bail!("destination of mount point is relative");
    }
    let options = mount
        .get("options")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let bind = options
        .iter()
        .any(|option| matches!(*option, "bind" | "rbind"));
    if bind && mount.get("source").is_none_or(Value::is_null) {
        bail!("bind mount must has a source");
    }
    validate_mount_id_mappings(mount)?;
    Ok(())
}

fn normalize_paths(value: &mut Value, bundle: &Path) -> Result<()> {
    let root = value
        .get_mut("root")
        .and_then(Value::as_object_mut)
        .context("root must be an object")?;
    let root_path = root
        .get("path")
        .and_then(Value::as_str)
        .context("root.path is required")?
        .to_string();
    if Path::new(&root_path).is_relative() {
        let canonical = bundle.join(&root_path);
        root.insert(
            "path".to_string(),
            Value::String(canonical.to_string_lossy().into_owned()),
        );
    }

    if let Some(mounts) = value.get_mut("mounts").and_then(Value::as_array_mut) {
        for mount in mounts {
            let Some(object) = mount.as_object_mut() else {
                continue;
            };
            let is_bind = object
                .get("options")
                .and_then(Value::as_array)
                .is_some_and(|options| {
                    options
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|option| matches!(option, "bind" | "rbind"))
                });
            if !is_bind
                && object.get("source").is_none_or(Value::is_null)
                && let Some(mount_type) = object
                    .get("type")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            {
                object.insert("source".to_string(), Value::String(mount_type));
            }
            if !is_bind {
                continue;
            }
            let Some(source) = object.get("source").and_then(Value::as_str) else {
                bail!("bind mount must has a source");
            };
            if Path::new(source).is_relative() {
                let canonical = bundle
                    .join(source)
                    .canonicalize()
                    .with_context(|| format!("failed to canonicalize bind source {source}"))?;
                object.insert(
                    "source".to_string(),
                    Value::String(canonical.to_string_lossy().into_owned()),
                );
            }
        }
    }
    Ok(())
}

fn process_mount_extensions(value: &mut Value) -> Result<()> {
    let root_path = value
        .pointer("/root/path")
        .and_then(Value::as_str)
        .context("root.path is required")?
        .to_string();
    let root_path = Path::new(&root_path);
    let Some(mounts) = value.get_mut("mounts").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    let mut retained = Vec::with_capacity(mounts.len());
    for mut mount in mounts.drain(..) {
        validate_mount_id_mappings(&mount)?;
        let copy_symlink = mount
            .get("options")
            .and_then(Value::as_array)
            .is_some_and(|options| options.iter().any(|option| option == COPY_SYMLINK));
        if copy_symlink {
            apply_copy_symlink(root_path, &mount)?;
            continue;
        }
        if let Some(options) = mount.get_mut("options").and_then(Value::as_array_mut) {
            options.retain(|option| {
                option.as_str().is_none_or(|option| {
                    !IGNORED_MOUNT_OPTIONS.contains(&option)
                        && !matches!(
                            option.split_once('=').map_or(option, |(name, _)| name),
                            "idmap" | "ridmap"
                        )
                })
            });
        }
        if let Some(object) = mount.as_object_mut() {
            object.remove("uidMappings");
            object.remove("gidMappings");
        }
        retained.push(mount);
    }
    *mounts = retained;
    Ok(())
}

fn validate_mount_id_mappings(mount: &Value) -> Result<()> {
    for field in ["uidMappings", "gidMappings"] {
        let Some(mappings) = mount.get(field) else {
            continue;
        };
        if mappings.is_null() {
            continue;
        }
        let mappings = mappings
            .as_array()
            .with_context(|| format!("mount.{field} must be an array"))?;
        for mapping in mappings {
            let mapping = mapping
                .as_object()
                .with_context(|| format!("mount.{field} entries must be objects"))?;
            for name in ["hostID", "containerID", "size"] {
                mapping
                    .get(name)
                    .and_then(cpp_number_as_u64)
                    .with_context(|| format!("mount.{field}.{name} must be a number"))?;
            }
        }
    }

    let raw_uid_mappings = mount
        .get("uidMappings")
        .is_some_and(|mappings| !mappings.is_null());
    let raw_gid_mappings = mount
        .get("gidMappings")
        .is_some_and(|mappings| !mappings.is_null());
    let Some(options) = mount.get("options").filter(|options| !options.is_null()) else {
        if raw_uid_mappings != raw_gid_mappings {
            bail!("uidMappings and gidMappings on mounts must be specified together");
        }
        return Ok(());
    };
    let options = options
        .as_array()
        .context("mount.options must be an array")?;

    let mut idmap_type: Option<&str> = None;
    let mut effective_uid_mappings = false;
    let mut effective_gid_mappings = false;
    for option in options {
        let option = option
            .as_str()
            .context("mount.options entries must be strings")?;
        let (kind, inline) = if option == "idmap" || option == "ridmap" {
            (option, None)
        } else if let Some(rest) = option.strip_prefix("idmap=") {
            ("idmap", Some(rest))
        } else if let Some(rest) = option.strip_prefix("ridmap=") {
            ("ridmap", Some(rest))
        } else {
            continue;
        };
        if idmap_type.is_some_and(|existing| existing != kind) {
            bail!("idmap and ridmap options are mutually exclusive");
        }
        idmap_type = Some(kind);
        if let Some(inline) = inline {
            (effective_uid_mappings, effective_gid_mappings) =
                validate_inline_idmap(option, inline)?;
        }
    }
    if effective_uid_mappings != effective_gid_mappings {
        bail!("uidMappings and gidMappings on mounts must be specified together");
    }
    Ok(())
}

fn validate_inline_idmap(option: &str, inline: &str) -> Result<(bool, bool)> {
    let mut uid_mappings = false;
    let mut gid_mappings = false;
    let mut remaining = inline;
    while !remaining.is_empty() {
        let (part, next) = remaining
            .split_once(',')
            .map_or((remaining, None), |(part, next)| (part, Some(next)));
        let (kind, mapping) = part
            .split_once('=')
            .with_context(|| format!("invalid id mapping option: {option}"))?;
        match kind {
            "uids" => uid_mappings = true,
            "gids" => gid_mappings = true,
            _ => bail!("unknown id mapping key: {kind}"),
        }
        if !mapping.is_empty() {
            validate_id_mapping(mapping)?;
        }
        let Some(next) = next else {
            break;
        };
        remaining = next;
    }
    Ok((uid_mappings, gid_mappings))
}

fn parse_u32_prefix(value: &str) -> Option<u32> {
    let length = value
        .as_bytes()
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if length == 0 {
        return None;
    }
    value[..length].parse().ok()
}

fn parse_usize_prefix(value: &str) -> Option<usize> {
    let length = value
        .as_bytes()
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if length == 0 {
        return None;
    }
    value[..length].parse().ok()
}

fn validate_id_mapping(mapping: &str) -> Result<()> {
    let Some(first_colon) = mapping.find(':') else {
        bail!("invalid id mapping: {mapping}");
    };
    let Some(second_offset) = mapping[first_colon + 1..].find(':') else {
        bail!("invalid id mapping: {mapping}");
    };
    let second_colon = first_colon + 1 + second_offset;
    if parse_u32_prefix(&mapping[..first_colon]).is_none() {
        bail!("invalid container id in mapping: {mapping}");
    }
    if parse_u32_prefix(&mapping[first_colon + 1..second_colon]).is_none() {
        bail!("invalid host id in mapping: {mapping}");
    }
    if parse_usize_prefix(&mapping[second_colon + 1..]).is_none() {
        bail!("invalid size in mapping: {mapping}");
    }
    Ok(())
}

fn validate_runtime_extensions(value: &Value) -> Result<()> {
    let ns_last_pid = value
        .get("annotations")
        .and_then(|annotations| annotations.get(NS_LAST_PID_ANNOTATION))
        .and_then(Value::as_str);
    if let Some(ns_last_pid) = ns_last_pid {
        validate_ns_last_pid(ns_last_pid)?;
    }
    Ok(())
}

fn validate_ns_last_pid(value: &str) -> Result<i32> {
    let parsed = value
        .parse::<i64>()
        .with_context(|| format!("parse ns_last_pid {value} failed"))?;
    if !(0..=i32::MAX as i64).contains(&parsed) {
        bail!(
            "ns_last_pid value out of range: {value} (must be between 0 and {})",
            i32::MAX
        );
    }
    Ok(parsed as i32)
}

pub fn bind_host_dev(
    source: &Path,
    target: &Path,
    options: &[String],
    terminal: bool,
    console_source: &Path,
) -> Result<()> {
    let preserved_devpts = if terminal {
        Some(PreservedDevpts::new(&target.join("pts"))?)
    } else {
        None
    };
    let recursive = options.iter().any(|option| option == "rbind");
    let bind_flags = MsFlags::MS_BIND
        | if recursive {
            MsFlags::MS_REC
        } else {
            MsFlags::empty()
        };
    mount(Some(source), target, None::<&str>, bind_flags, None::<&str>).with_context(|| {
        format!(
            "failed to bind {} to {}",
            source.display(),
            target.display()
        )
    })?;

    let mut attributes = MsFlags::empty();
    for option in options {
        attributes |= match option.as_str() {
            "ro" => MsFlags::MS_RDONLY,
            "nosuid" => MsFlags::MS_NOSUID,
            "nodev" => MsFlags::MS_NODEV,
            "noexec" => MsFlags::MS_NOEXEC,
            "sync" => MsFlags::MS_SYNCHRONOUS,
            "dirsync" => MsFlags::MS_DIRSYNC,
            "mand" => MsFlags::MS_MANDLOCK,
            "noatime" => MsFlags::MS_NOATIME,
            "nodiratime" => MsFlags::MS_NODIRATIME,
            "relatime" => MsFlags::MS_RELATIME,
            "strictatime" => MsFlags::MS_STRICTATIME,
            "lazytime" => MsFlags::MS_LAZYTIME,
            _ => MsFlags::empty(),
        };
    }
    if !attributes.is_empty()
        || options
            .iter()
            .any(|option| matches!(option.as_str(), "ro" | "rw"))
    {
        mount(
            None::<&Path>,
            target,
            None::<&str>,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | attributes,
            None::<&str>,
        )
        .with_context(|| format!("failed to remount {}", target.display()))?;
    }
    for option in options {
        let propagation = match option.as_str() {
            "shared" => Some(MsFlags::MS_SHARED),
            "rshared" => Some(MsFlags::MS_SHARED | MsFlags::MS_REC),
            "slave" => Some(MsFlags::MS_SLAVE),
            "rslave" => Some(MsFlags::MS_SLAVE | MsFlags::MS_REC),
            "private" => Some(MsFlags::MS_PRIVATE),
            "rprivate" => Some(MsFlags::MS_PRIVATE | MsFlags::MS_REC),
            "unbindable" => Some(MsFlags::MS_UNBINDABLE),
            "runbindable" => Some(MsFlags::MS_UNBINDABLE | MsFlags::MS_REC),
            _ => None,
        };
        if let Some(propagation) = propagation {
            mount(
                None::<&Path>,
                target,
                None::<&str>,
                propagation,
                None::<&str>,
            )
            .with_context(|| format!("failed to set propagation on {}", target.display()))?;
        }
    }
    if terminal {
        prepare_host_dev_terminal(
            preserved_devpts
                .as_ref()
                .expect("terminal devpts must be preserved")
                .path(),
            target,
            console_source,
        )?;
    }
    Ok(())
}

struct PreservedDevpts {
    directory: tempfile::TempDir,
}

impl PreservedDevpts {
    fn new(source: &Path) -> Result<Self> {
        let directory = tempfile::tempdir().context("failed to create devpts preservation path")?;
        mount(
            Some(source),
            directory.path(),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .with_context(|| format!("failed to preserve {}", source.display()))?;
        Ok(Self { directory })
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }
}

impl Drop for PreservedDevpts {
    fn drop(&mut self) {
        let _ = umount2(self.directory.path(), MntFlags::MNT_DETACH);
    }
}

fn prepare_host_dev_terminal(devpts: &Path, target: &Path, console_source: &Path) -> Result<()> {
    let pts_target = target.join("pts");
    mount(
        Some(devpts),
        pts_target.as_path(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .with_context(|| format!("failed to prepare {}", pts_target.display()))?;

    let ptmx_source = devpts.join("ptmx");
    let ptmx_target = target.join("ptmx");
    mount(
        Some(ptmx_source.as_path()),
        ptmx_target.as_path(),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "failed to bind {} to {}",
            ptmx_source.display(),
            ptmx_target.display()
        )
    })?;

    let console_target = target.join("console");
    mount(
        Some(console_source),
        console_target.as_path(),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| format!("failed to prepare {}", console_target.display()))?;
    Ok(())
}

fn apply_copy_symlink(root: &Path, mount: &Value) -> Result<()> {
    let source = mount
        .get("source")
        .and_then(Value::as_str)
        .context("copy-symlink mount requires a source")?;
    let destination = mount
        .get("destination")
        .and_then(Value::as_str)
        .context("mount.destination is required")?;
    let target =
        fs::read_link(source).with_context(|| format!("read copy-symlink source {source}"))?;
    let relative = normalized_container_path(Path::new(destination))?;
    let file_name = relative
        .file_name()
        .context("copy-symlink destination must not be root")?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let root_fd = owned_fd(open(
        root,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?);
    let parent_fd = open_or_create_directories(&root_fd, parent)?;
    match symlinkat(&target, Some(parent_fd.as_raw_fd()), file_name) {
        Ok(()) => Ok(()),
        Err(Errno::EEXIST) => {
            let existing = readlinkat(Some(parent_fd.as_raw_fd()), file_name)?;
            if existing.as_bytes() == target.as_os_str().as_bytes() {
                Ok(())
            } else {
                bail!("symlink {destination} already exists with different content")
            }
        }
        Err(error) => Err(error).context("create symlink for copy-symlink mount"),
    }
}

fn normalized_container_path(path: &Path) -> Result<PathBuf> {
    use std::path::Component;

    if !path.is_absolute() {
        bail!("destination of mount point is relative");
    }
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(component) => result.push(component),
            Component::Prefix(_) => bail!("invalid container path: {}", path.display()),
        }
    }
    Ok(result)
}

fn open_or_create_directories(root: &OwnedFd, path: &Path) -> Result<OwnedFd> {
    let mut current = owned_fd(nix::unistd::dup(root.as_raw_fd())?);
    for component in path.components() {
        let name = component.as_os_str();
        match mkdirat(
            Some(current.as_raw_fd()),
            name,
            Mode::from_bits_truncate(0o755),
        ) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(error) => return Err(error).context("create copy-symlink parent directory"),
        }
        current = owned_fd(openat(
            Some(current.as_raw_fd()),
            name,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
    }
    Ok(current)
}

fn owned_fd(raw: std::os::fd::RawFd) -> OwnedFd {
    // SAFETY: successful nix descriptor-returning functions transfer ownership.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

pub fn process_uses_terminal(path: &Path) -> Result<bool> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    let process = value.get("process").unwrap_or(&value);
    Ok(process
        .get("terminal")
        .is_some_and(|value| !value.is_null()))
}

pub fn process_console_size(path: &Path) -> Result<Option<(u16, u16)>> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    let process = value.get("process").unwrap_or(&value);
    if process.get("terminal").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    let Some(size) = process.get("consoleSize") else {
        return Ok(None);
    };
    let height = size
        .get("height")
        .and_then(Value::as_u64)
        .context("process.consoleSize.height must be an unsigned integer")?;
    let width = size
        .get("width")
        .and_then(Value::as_u64)
        .context("process.consoleSize.width must be an unsigned integer")?;
    Ok(Some((
        u16::try_from(height).context("process.consoleSize.height is out of range")?,
        u16::try_from(width).context("process.consoleSize.width is out of range")?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_relative_root_and_bind_source() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir(temporary.path().join("rootfs")).unwrap();
        fs::write(temporary.path().join("source"), b"x").unwrap();
        let mut value = serde_json::json!({
            "ociVersion": "1.3.0",
            "process": {},
            "root": { "path": "rootfs" },
            "mounts": [{
                "destination": "/source",
                "source": "source",
                "type": "bind",
                "options": ["bind"]
            }]
        });
        normalize_paths(&mut value, temporary.path()).unwrap();
        assert!(Path::new(value["root"]["path"].as_str().unwrap()).is_absolute());
        assert!(Path::new(value["mounts"][0]["source"].as_str().unwrap()).is_absolute());
    }

    #[test]
    fn supplies_non_bind_mount_source_from_type() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir(temporary.path().join("rootfs")).unwrap();
        let mut value = serde_json::json!({
            "root": {"path": "rootfs"},
            "mounts": [{"destination": "/proc", "type": "proc"}]
        });
        normalize_paths(&mut value, temporary.path()).unwrap();
        assert_eq!(value.pointer("/mounts/0/source").unwrap(), "proc");
    }

    #[test]
    fn reads_terminal_flag_from_process() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temporary.path(),
            serde_json::to_vec(&serde_json::json!({
                "terminal": false,
                "process": {"terminal": true}
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(process_uses_terminal(temporary.path()).unwrap());

        fs::write(temporary.path(), br#"{"terminal":false}"#).unwrap();
        assert!(process_uses_terminal(temporary.path()).unwrap());

        fs::write(temporary.path(), br#"{}"#).unwrap();
        assert!(!process_uses_terminal(temporary.path()).unwrap());
    }

    #[test]
    fn reads_console_size_from_process() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            temporary.path(),
            br#"{"process":{"terminal":true,"consoleSize":{"height":24,"width":80}}}"#,
        )
        .unwrap();
        assert_eq!(
            process_console_size(temporary.path()).unwrap(),
            Some((24, 80))
        );

        fs::write(
            temporary.path(),
            br#"{"terminal":true,"consoleSize":{"height":30,"width":100}}"#,
        )
        .unwrap();
        assert_eq!(
            process_console_size(temporary.path()).unwrap(),
            Some((30, 100))
        );

        fs::write(
            temporary.path(),
            br#"{"terminal":false,"consoleSize":{"height":"ignored"}}"#,
        )
        .unwrap();
        assert_eq!(process_console_size(temporary.path()).unwrap(), None);
    }

    #[test]
    fn applies_copy_symlink_and_removes_mount() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir(temporary.path().join("rootfs")).unwrap();
        std::os::unix::fs::symlink(
            "/run/host/rootfs/etc/resolv.conf",
            temporary.path().join("link"),
        )
        .unwrap();
        let mut value = serde_json::json!({
            "root": { "path": temporary.path().join("rootfs") },
            "mounts": [{
                "destination": "/etc/resolv.conf",
                "source": temporary.path().join("link"),
                "type": "bind",
                "options": ["bind", "copy-symlink"]
            }]
        });

        process_mount_extensions(&mut value).unwrap();

        assert!(value["mounts"].as_array().unwrap().is_empty());
        assert_eq!(
            fs::read_link(temporary.path().join("rootfs/etc/resolv.conf")).unwrap(),
            PathBuf::from("/run/host/rootfs/etc/resolv.conf")
        );
    }

    #[test]
    fn copy_symlink_rejects_escape_through_existing_parent_symlink() {
        let temporary = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(temporary.path().join("rootfs")).unwrap();
        std::os::unix::fs::symlink(outside.path(), temporary.path().join("rootfs/etc")).unwrap();
        std::os::unix::fs::symlink("target", temporary.path().join("link")).unwrap();
        let mut value = serde_json::json!({
            "root": { "path": temporary.path().join("rootfs") },
            "mounts": [{
                "destination": "/etc/resolv.conf",
                "source": temporary.path().join("link"),
                "options": ["bind", "copy-symlink"]
            }]
        });

        assert!(process_mount_extensions(&mut value).is_err());
        assert!(!outside.path().join("resolv.conf").exists());
    }

    #[test]
    fn preserves_upstream_noop_mount_extension_behavior() {
        let temporary = tempfile::tempdir().unwrap();
        let mut value = serde_json::json!({
            "root": { "path": temporary.path() },
            "mounts": [{
                "destination": "/data",
                "source": "tmpfs",
                "options": ["nodev", "tmpcopyup", "rro", "idmap=uids=0:1000:1,gids=0:1000:1"],
                "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
                "gidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}]
            }]
        });

        process_mount_extensions(&mut value).unwrap();

        assert_eq!(value["mounts"][0]["options"], serde_json::json!(["nodev"]));
        assert!(value["mounts"][0].get("uidMappings").is_none());
        assert!(value["mounts"][0].get("gidMappings").is_none());
    }

    #[test]
    fn validates_upstream_idmap_option_errors_before_stripping() {
        let temporary = tempfile::tempdir().unwrap();
        for options in [
            serde_json::json!(["idmap", "ridmap"]),
            serde_json::json!(["idmap=uids=broken"]),
            serde_json::json!(["idmap=unknown=0:1000:1"]),
        ] {
            let mut value = serde_json::json!({
                "root": { "path": temporary.path() },
                "mounts": [{
                    "destination": "/data",
                    "source": "/data",
                    "options": options
                }]
            });
            assert!(process_mount_extensions(&mut value).is_err());
        }

        let mut value = serde_json::json!({
            "root": { "path": temporary.path() },
            "mounts": [{
                "destination": "/data",
                "source": "/data",
                "options": ["idmap=uids=0:1000:1,gids=0:1000:1"]
            }]
        });
        process_mount_extensions(&mut value).unwrap();
        assert_eq!(value["mounts"][0]["options"], serde_json::json!([]));
    }

    #[test]
    fn matches_upstream_inline_idmap_parser_quirks() {
        let temporary = tempfile::tempdir().unwrap();
        for options in [
            serde_json::json!(["idmap="]),
            serde_json::json!(["ridmap="]),
            serde_json::json!(["idmap=uids=,gids="]),
            serde_json::json!(["idmap=uids=0x:1000x:1:2,gids=0x:1000x:1:2"]),
            serde_json::json!(["idmap=uids=01:01000:01,gids=01:01000:01"]),
        ] {
            let mut value = serde_json::json!({
                "root": { "path": temporary.path() },
                "mounts": [{
                    "destination": "/data",
                    "source": "/data",
                    "options": options
                }]
            });
            process_mount_extensions(&mut value).unwrap();
        }

        for options in [
            serde_json::json!(["idmap=uids=0:1000:1"]),
            serde_json::json!(["idmap=gids=0:1000:1"]),
            serde_json::json!(["idmap=uids=+0:1000:1,gids=0:1000:1"]),
            serde_json::json!(["idmap=uids=4294967296:0:1,gids=0:0:1"]),
            serde_json::json!(["idmap=uids=0:0:1,gids=0:0:1", "idmap=uids=0:0:1"]),
        ] {
            let mut value = serde_json::json!({
                "root": { "path": temporary.path() },
                "mounts": [{
                    "destination": "/data",
                    "source": "/data",
                    "options": options
                }]
            });
            assert!(process_mount_extensions(&mut value).is_err());
        }

        let mut value = serde_json::json!({
            "root": { "path": temporary.path() },
            "mounts": [{
                "destination": "/data",
                "uidMappings": [{"containerID": 0, "hostID": 0, "size": 1}],
                "options": []
            }]
        });
        process_mount_extensions(&mut value).unwrap();
    }

    #[test]
    fn validates_upstream_oci_constraints() {
        let value = serde_json::json!({
            "ociVersion": "1.3.1",
            "process": {"cwd": "relative", "args": []},
            "root": {"path": "rootfs"}
        });
        assert!(validate_required_fields(&value).is_err());

        let value = serde_json::json!({
            "process": {
                "cwd": "/",
                "args": ["true"],
                "scheduler": {"policy": "SCHED_OTHER", "priority": 1}
            }
        });
        assert!(validate_config(&value).is_err());

        let value = serde_json::json!({
            "process": {"cwd": "/", "args": ["true"]},
            "linux": {"namespaces": [{"type": "pid"}, {"type": "pid"}]}
        });
        assert!(validate_config(&value).is_err());

        for version in ["1.3.0+001", "1.3.0-01", "2147483648.0.0", "1.3.0-alpha+"] {
            let value = serde_json::json!({
                "ociVersion": version,
                "process": {"cwd": "/", "args": ["true"]},
                "root": {"path": "rootfs"}
            });
            assert!(validate_required_fields(&value).is_err(), "{version}");
        }

        for version in ["1.2.999999-alpha", "1.3.0-alpha", "1.3.0+build"] {
            let value = serde_json::json!({
                "ociVersion": version,
                "process": {"cwd": "/", "args": ["true"]},
                "root": {"path": "rootfs"}
            });
            validate_required_fields(&value).unwrap();
        }

        for value in [
            serde_json::json!({"ociVersion": "1.3.0", "process": null, "root": {"path": "rootfs"}}),
            serde_json::json!({"ociVersion": "1.3.0", "process": {"cwd": "/", "args": ["true"]}, "root": null}),
        ] {
            assert!(validate_required_fields(&value).is_err());
        }

        for value in [
            serde_json::json!({"process": "invalid"}),
            serde_json::json!({"root": []}),
            serde_json::json!({"mounts": {}}),
            serde_json::json!({"linux": {"namespaces": {}}}),
            serde_json::json!({"linux": {"namespaces": [{"type": "unknown"}]}}),
            serde_json::json!({"linux": {"namespaces": [{"type": "pid", "path": 1}]}}),
        ] {
            assert!(validate_config(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn parses_frozen_semver_grammar() {
        for version in [
            "0.0.0",
            "1.2.3",
            "2147483647.0.0",
            "1.2.3-alpha",
            "1.2.3-alpha.1",
            "1.2.3-0",
            "1.2.3+build-1",
            "1.2.3-alpha+build",
        ] {
            parse_oci_version(version).unwrap_or_else(|error| panic!("{version}: {error}"));
        }
        for version in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "-1.2.3",
            "1.-2.3",
            "1.2.-3",
            "2147483648.0.0",
            "1.2.3-",
            "1.2.3+",
            "1.2.3-alpha.",
            "1.2.3-.alpha",
            "1.2.3-01",
            "1.2.3+001",
            "1.2.3-alpha_beta",
            "1.2.3-alpha+build+extra",
        ] {
            assert!(parse_oci_version(version).is_err(), "{version}");
        }
    }

    #[test]
    fn validates_namespace_symlink_type_with_upstream_names() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("namespace");
        std::os::unix::fs::symlink("pid:[123]", &target).unwrap();
        let bundle = PreparedBundle {
            directory: tempfile::tempdir().unwrap(),
            original_bundle: temporary.path().to_path_buf(),
            original_config_path: temporary.path().join("config.json"),
            canonicalize_rootfs: false,
            namespace_paths: vec![NamespacePath {
                kind: "pid".to_string(),
                path: target.clone(),
            }],
        };
        bundle.validate_namespace_paths().unwrap();

        std::fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink("mnt:[123]", &target).unwrap();
        assert!(bundle.validate_namespace_paths().is_err());
    }

    #[test]
    fn hook_metadata_replaces_null_annotations() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("config.json"),
            serde_json::to_vec(&serde_json::json!({"annotations": null})).unwrap(),
        )
        .unwrap();
        let mut bundle = PreparedBundle {
            directory,
            original_bundle: PathBuf::from("/original-bundle"),
            original_config_path: PathBuf::from("/original-bundle/config.json"),
            canonicalize_rootfs: false,
            namespace_paths: Vec::new(),
        };

        bundle.set_hook_state_metadata("created", "owner").unwrap();

        let value: Value =
            serde_json::from_slice(&fs::read(bundle.directory.path().join("config.json")).unwrap())
                .unwrap();
        assert_eq!(
            value["annotations"][HOOK_ORIGINAL_BUNDLE_ANNOTATION],
            "/original-bundle"
        );
        assert_eq!(value["annotations"][HOOK_CREATED_ANNOTATION], "created");
        assert_eq!(value["annotations"][HOOK_OWNER_ANNOTATION], "owner");
    }

    #[test]
    fn accepts_unknown_capabilities_until_runtime_setup() {
        let value = serde_json::json!({
            "process": {
                "cwd": "/",
                "args": ["true"],
                "capabilities": {
                    "bounding": ["CAP_CHOWN"],
                    "effective": ["CAP_NOT_REAL"]
                }
            }
        });
        validate_config(&value).unwrap();
        assert_eq!(
            collect_capability_error(&value).as_deref(),
            Some("unknown capability: CAP_NOT_REAL")
        );

        let mut normalized = value;
        strip_upstream_noop_fields(&mut normalized);
        assert_eq!(
            normalized["process"]["capabilities"]["bounding"],
            serde_json::json!(["CAP_CHOWN"])
        );
        assert_eq!(
            normalized["process"]["capabilities"]["effective"],
            serde_json::json!([])
        );
    }

    #[test]
    fn validates_then_strips_upstream_noop_oci_fields() {
        let mut value = serde_json::json!({
            "hostname": "ignored-host",
            "domainname": "ignored-domain",
            "process": {
                "cwd": "/",
                "args": ["true"],
                "terminal": false,
                "consoleSize": {"height": "ignored"},
                "noNewPrivileges": false,
                "scheduler": {"policy": "SCHED_OTHER"},
                "apparmorProfile": "ignored-profile",
                "selinuxLabel": "ignored-label",
                "capabilities": {"effective": ["cap_net_bind_service"]},
                "ioPriority": {"class": "IOPRIO_CLASS_BE", "priority": 4},
                "execCPUAffinity": {"initial": "0-1", "final": "2"}
            },
            "linux": {
                "namespaces": [{"type": "pid", "path": "/proc/1/ns/pid"}],
                "devices": [{"type": "c", "path": "/dev/demo"}],
                "netDevices": {"eth0": {"name": "inside0"}},
                "cgroupsPath": "/ignored",
                "resources": {"memory": {"swappiness": 50}},
                "sysctl": {"kernel.hostname": "ignored"},
                "seccomp": {"defaultAction": "SCMP_ACT_ALLOW"},
                "personality": {"domain": "LINUX32", "flags": ["ignored"]},
                "memoryPolicy": {
                    "mode": "MPOL_BIND",
                    "nodes": "0-2,4",
                    "flags": ["MPOL_F_STATIC_NODES"]
                },
                "timeOffsets": {"monotonic": {"secs": 1, "nanosecs": 2}},
                "intelRdt": {
                    "closID": "demo",
                    "schemata": ["L3:0=ffff"],
                    "enableMonitoring": true
                },
                "mountLabel": "system_u:object_r:container_file_t:s0"
            }
        });

        validate_config(&value).unwrap();
        strip_upstream_noop_fields(&mut value);

        assert!(value.get("hostname").is_none());
        assert!(value.get("domainname").is_none());
        assert_eq!(value["process"]["terminal"], true);
        assert_eq!(value["process"]["noNewPrivileges"], true);
        assert_eq!(
            value["process"]["user"],
            serde_json::json!({"uid": 0, "gid": 0})
        );
        assert!(value["process"].get("consoleSize").is_none());
        assert_eq!(
            value["process"]["capabilities"]["effective"][0],
            "CAP_NET_BIND_SERVICE"
        );
        assert!(value["process"].get("ioPriority").is_none());
        assert!(value["process"].get("execCPUAffinity").is_none());
        for field in ["scheduler", "apparmorProfile", "selinuxLabel"] {
            assert!(value["process"].get(field).is_none(), "field {field}");
        }
        for field in [
            "devices",
            "netDevices",
            "cgroupsPath",
            "resources",
            "sysctl",
            "seccomp",
            "personality",
            "memoryPolicy",
            "timeOffsets",
            "intelRdt",
            "mountLabel",
        ] {
            assert!(value["linux"].get(field).is_none(), "field {field}");
        }
        assert!(value["linux"]["namespaces"][0].get("path").is_none());
    }

    #[test]
    fn ignores_linux_id_mappings_without_user_namespace_like_upstream() {
        let mut value = serde_json::json!({
            "process": {"cwd": "/", "args": ["true"]},
            "linux": {
                "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}]
            }
        });
        validate_config(&value).unwrap();
        strip_upstream_noop_fields(&mut value);
        assert!(value["linux"].get("uidMappings").is_none());
        assert!(value["linux"].get("gidMappings").is_none());

        let mut user_namespace = serde_json::json!({
            "process": {"cwd": "/", "args": ["true"]},
            "linux": {
                "namespaces": [{"type": "user"}],
                "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}]
            }
        });
        validate_config(&user_namespace).unwrap();
        strip_upstream_noop_fields(&mut user_namespace);
        assert!(user_namespace["linux"].get("uidMappings").is_some());
    }

    #[test]
    fn defaults_missing_user_but_rejects_incomplete_user() {
        let mut missing = serde_json::json!({"cwd": "/", "args": ["true"]});
        let process = missing.as_object_mut().unwrap();
        validate_user(process).unwrap();
        strip_upstream_noop_process_fields(process);
        assert_eq!(process["user"], serde_json::json!({"uid": 0, "gid": 0}));

        let incomplete = serde_json::json!({
            "cwd": "/",
            "args": ["true"],
            "user": {"uid": 1000}
        });
        assert!(validate_user(incomplete.as_object().unwrap()).is_err());
    }

    #[test]
    fn rejects_invalid_upstream_noop_oci_fields() {
        for value in [
            serde_json::json!({
                "process": {"cwd": "/", "args": ["true"], "ioPriority": {
                    "class": "INVALID", "priority": 0
                }}
            }),
            serde_json::json!({
                "process": {"cwd": "/", "args": ["true"]},
                "linux": {"personality": {"domain": "INVALID"}}
            }),
            serde_json::json!({
                "process": {"cwd": "/", "args": ["true"]},
                "linux": {"memoryPolicy": {"mode": "MPOL_BIND", "nodes": "2-1"}}
            }),
            serde_json::json!({
                "process": {"cwd": "/", "args": ["true"], "scheduler": {
                    "policy": "SCHED_OTHER", "flags": ["INVALID"]
                }}
            }),
            serde_json::json!({
                "process": {"cwd": "/", "args": ["true"]},
                "linux": {"resources": {"cpu": {"cpus": "+1"}}}
            }),
            serde_json::json!({
                "process": {"cwd": "/", "args": ["true"]},
                "linux": {"seccomp": {"defaultAction": "INVALID"}}
            }),
        ] {
            assert!(validate_config(&value).is_err());
        }
    }

    #[test]
    fn rejects_oci_spec_native_seccomp_architecture_absent_upstream() {
        let value = serde_json::json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": ["SCMP_ARCH_NATIVE"]
        });
        assert_eq!(
            validate_seccomp(Some(&value)).unwrap_err().to_string(),
            "unknown architecture: SCMP_ARCH_NATIVE"
        );
    }

    #[test]
    fn validates_ns_last_pid_without_mutating_existing_hooks() {
        let temporary = tempfile::tempdir().unwrap();
        let value = serde_json::json!({
            "root": {"path": temporary.path()},
            "annotations": {NS_LAST_PID_ANNOTATION: "1000"},
            "hooks": {"createContainer": [{"path": "/bin/true"}]}
        });

        validate_runtime_extensions(&value).unwrap();

        let hooks = value["hooks"]["createContainer"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["path"], "/bin/true");

        let invalid = serde_json::json!({
            "annotations": {NS_LAST_PID_ANNOTATION: "2147483648"}
        });
        assert!(validate_runtime_extensions(&invalid).is_err());
    }

    #[test]
    fn preserves_host_dev_bind_and_existing_create_hooks() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir(temporary.path().join("rootfs")).unwrap();
        let mut value = serde_json::json!({
            "root": {"path": temporary.path().join("rootfs")},
            "process": {"terminal": true},
            "mounts": [{
                "destination": "/dev",
                "source": "/dev",
                "type": "bind",
                "options": ["rbind", "nosuid", "noexec", "rslave"]
            }],
            "hooks": {"createContainer": [{"path": "/bin/true"}]}
        });
        process_mount_extensions(&mut value).unwrap();
        validate_runtime_extensions(&value).unwrap();

        assert_eq!(value["mounts"].as_array().unwrap().len(), 1);
        assert_eq!(value["mounts"][0]["destination"], "/dev");
        assert_eq!(value["mounts"][0]["source"], "/dev");
        assert_eq!(value["mounts"][0]["type"], "bind");
        let hooks = value["hooks"]["createContainer"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["path"], "/bin/true");
    }
}
