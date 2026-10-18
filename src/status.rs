use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::OCI_VERSION;
use crate::cli::ListFormat;
use crate::process_handle::ProcessHandle;
use crate::strict_json;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeStatus {
    Creating,
    Created,
    Running,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Status {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "pid")]
    pub pid: i32,
    #[serde(
        rename = "process-start-time",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_process_start_time"
    )]
    pub process_start_time: Option<u64>,
    #[serde(rename = "status", default = "default_runtime_status")]
    pub status: RuntimeStatus,
    #[serde(rename = "bundle")]
    pub bundle: PathBuf,
    #[serde(rename = "created", deserialize_with = "deserialize_created")]
    pub created: String,
    #[serde(rename = "owner")]
    pub owner: String,
    #[serde(rename = "annotations")]
    pub annotations: BTreeMap<String, String>,
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
}

impl Status {
    pub fn creating(id: String, original_bundle: PathBuf, created: String) -> Result<Self> {
        let owner = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .context("getpwuid")?
            .context("getpwuid returned no user")?
            .name;
        Ok(Self {
            id,
            pid: std::process::id() as i32,
            process_start_time: None,
            status: RuntimeStatus::Creating,
            bundle: original_bundle,
            created,
            owner,
            annotations: BTreeMap::new(),
            oci_version: OCI_VERSION.to_string(),
        })
    }

    pub fn refresh_liveness(&mut self) -> Result<()> {
        if self.pid <= 0 {
            self.status = RuntimeStatus::Creating;
            return Ok(());
        }
        let handle = match ProcessHandle::open(self.pid) {
            Ok(handle) => handle,
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                self.status = RuntimeStatus::Stopped;
                return Ok(());
            }
            Err(error) => {
                tracing::info!(
                    pid = self.pid,
                    "failed to get container process handle: {error}"
                );
                return Ok(());
            }
        };
        let process = match handle.status() {
            Ok(process) => process,
            Err(error) => {
                tracing::info!(
                    pid = self.pid,
                    "failed to get container process stat: {error}"
                );
                return Ok(());
            }
        };
        if process.state.is_dead()
            || self
                .process_start_time
                .is_some_and(|expected| expected != process.start_time)
        {
            self.status = RuntimeStatus::Stopped;
        } else {
            self.status = RuntimeStatus::Running;
        }
        Ok(())
    }
}

fn default_runtime_status() -> RuntimeStatus {
    RuntimeStatus::Creating
}

fn deserialize_process_start_time<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    u64::deserialize(deserializer).map(Some)
}

fn deserialize_created<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    normalize_created(&value).map_err(serde::de::Error::custom)
}

pub fn created_now() -> String {
    format_created(Utc::now())
}

fn normalize_created(value: &str) -> Result<String> {
    let datetime = if value.contains('T') || value.contains('-') {
        if !value.ends_with(['Z', 'z']) {
            bail!("expected 'Z' timezone");
        }
        let normalized;
        let value = if let Some(value) = value.strip_suffix('z') {
            normalized = format!("{value}Z");
            normalized.as_str()
        } else {
            value
        };
        DateTime::parse_from_rfc3339(value)
            .context("invalid ISO 8601 created time")?
            .with_timezone(&Utc)
    } else {
        let nanoseconds = value
            .parse::<u64>()
            .context("invalid integer nanoseconds format")?;
        let nanoseconds: i64 = nanoseconds
            .try_into()
            .context("nanoseconds value out of range")?;
        DateTime::<Utc>::from_timestamp(
            nanoseconds.div_euclid(1_000_000_000),
            nanoseconds.rem_euclid(1_000_000_000) as u32,
        )
        .context("date time out of representable range")?
    };
    Ok(format_created(datetime))
}

fn format_created(datetime: DateTime<Utc>) -> String {
    datetime.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

pub fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("container ID must not be empty");
    }
    if id.starts_with('.')
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-' | b'.'))
    {
        bail!("invalid container ID: {id}");
    }
    Ok(())
}

pub fn write_status(root: &Path, status: &Status) -> Result<()> {
    validate_id(&status.id)?;
    let directory = root.join(&status.id);
    fs::create_dir_all(&directory)
        .with_context(|| format!("failed to create status directory {}", directory.display()))?;
    let mut value = serde_json::to_value(status)?;
    value
        .as_object_mut()
        .expect("Status serializes as an object")
        .remove("status");
    atomic_write(&directory.join("status.json"), &serde_json::to_vec(&value)?)
}

pub fn save_config(root: &Path, id: &str, source: &Path) -> Result<()> {
    validate_id(id)?;
    let destination = root.join(id).join("config.json");
    let mut input = File::open(source)
        .with_context(|| format!("failed to open config file: {}", source.display()))?;
    let permissions = input.metadata()?.permissions();
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(permissions.mode())
        .open(&destination)
        .map_err(|error| {
            anyhow::anyhow!(
                "filesystem error: cannot copy: {} [{}] [{}]",
                io_error_message(&error),
                source.display(),
                destination.display()
            )
        })?;
    let result = io::copy(&mut input, &mut output)
        .and_then(|_| fs::set_permissions(&destination, permissions));
    if let Err(error) = result {
        let _ = fs::remove_file(&destination);
        return Err(error).context("failed to copy config file");
    }
    Ok(())
}

fn io_error_message(error: &io::Error) -> String {
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

pub fn remove_status_directory(root: &Path, id: &str) -> Result<()> {
    validate_id(id)?;
    let directory = root.join(id);
    match fs::remove_dir_all(&directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to remove status directory {}", directory.display())),
    }
}

pub fn load_status(path: &Path) -> Result<Status> {
    let content = fs::read(path)
        .with_context(|| format!("failed to open status file: {}", path.display()))?;
    let mut value = strict_json::value_from_slice(&content)
        .with_context(|| format!("failed to parse status file: {}", path.display()))?;
    let object = value
        .as_object_mut()
        .context("status file must contain an object")?;
    if let Some(pid) = object.get_mut("pid") {
        let normalized =
            strict_json::as_i32(pid).context("status pid must be an in-range integer")?;
        *pid = serde_json::Value::from(normalized);
    }
    if let Some(start_time) = object
        .get_mut("process-start-time")
        .filter(|value| !value.is_null())
    {
        let normalized = strict_json::as_u64(start_time)
            .context("process-start-time must be an unsigned integer")?;
        *start_time = serde_json::Value::from(normalized);
    }
    let mut status: Status = serde_json::from_value(value)
        .with_context(|| format!("failed to parse status file: {}", path.display()))?;
    status.refresh_liveness()?;
    Ok(status)
}

pub fn list_statuses(root: &Path) -> Result<Vec<Status>> {
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create status directory root: {}", root.display()))?;
    let mut statuses = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path().join("status.json");
        if path.try_exists()? {
            statuses.push(load_status(&path)?);
        }
    }
    Ok(statuses)
}

pub fn print_statuses(statuses: &[Status], format: ListFormat) -> Result<()> {
    match format {
        ListFormat::Json => {
            let values = statuses.iter().map(oci_status_value).collect::<Vec<_>>();
            let mut output = io::stdout().lock();
            let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
            let mut serializer = serde_json::Serializer::with_formatter(&mut output, formatter);
            values.serialize(&mut serializer)?;
            writeln!(output)?;
        }
        ListFormat::Table => print_table(statuses)?,
    }
    Ok(())
}

fn print_table(statuses: &[Status]) -> Result<()> {
    let width = statuses
        .iter()
        .map(|status| status.id.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let mut output = io::stdout().lock();
    writeln!(
        output,
        "{:<name_width$}{:<10}{:<9}{:<40}{:<31}OWNER",
        "NAME",
        "PID",
        "STATUS",
        "BUNDLE PATH",
        "CREATED",
        name_width = width
    )?;
    for status in statuses {
        writeln!(
            output,
            "{:<name_width$}{:<10}{:<9}{:<40}{:<31}{}",
            status.id,
            status.pid,
            status_name(status.status),
            quoted_path(&status.bundle),
            status.created,
            status.owner,
            name_width = width
        )?;
    }
    output.flush()?;
    Ok(())
}

fn quoted_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        if matches!(character, '\\' | '"') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

fn oci_status_value(status: &Status) -> serde_json::Value {
    serde_json::json!({
        "id": status.id,
        "pid": status.pid,
        "status": status_name(status.status),
        "bundle": status.bundle,
        "created": status.created,
        "owner": status.owner,
        "annotations": status.annotations,
        "ociVersion": status.oci_version,
    })
}

pub fn status_name(status: RuntimeStatus) -> &'static str {
    match status {
        RuntimeStatus::Creating => "creating",
        RuntimeStatus::Created => "created",
        RuntimeStatus::Running => "running",
        RuntimeStatus::Stopped => "stopped",
    }
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().context("status path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".tmp-")
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "failed to create temporary status file in {}",
                parent.display()
            )
        })?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o700))?;
    temporary.as_file_mut().write_all(content)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to atomically write status file: {}", path.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_original_id_grammar() {
        for id in ["demo", "org.deepin.demo", "A_1+2-3"] {
            validate_id(id).unwrap();
        }
        for id in ["", ".hidden", "bad/name", "space name"] {
            assert!(validate_id(id).is_err(), "{id}");
        }
    }

    #[test]
    fn separates_persistent_and_oci_status_fields() {
        let status = Status {
            id: "demo".to_string(),
            pid: 0,
            process_start_time: Some(123),
            status: RuntimeStatus::Stopped,
            bundle: PathBuf::from("/bundle"),
            created: "1970-01-01T00:00:00.000000Z".to_string(),
            owner: "tester".to_string(),
            annotations: BTreeMap::new(),
            oci_version: OCI_VERSION.to_string(),
        };
        let value = oci_status_value(&status);
        assert_eq!(value["ociVersion"], OCI_VERSION);
        assert_eq!(value["status"], "stopped");
        assert!(value.get("process-start-time").is_none());

        let temporary = tempfile::tempdir().unwrap();
        write_status(temporary.path(), &status).unwrap();
        let value = strict_json::value_from_slice(
            &fs::read(temporary.path().join("demo/status.json")).unwrap(),
        )
        .unwrap();
        assert!(value.get("status").is_none());
        assert_eq!(value["process-start-time"], 123);
    }

    #[test]
    fn legacy_status_omits_missing_process_start_time() {
        let mut value = serde_json::json!({
            "id": "demo",
            "pid": 1,
            "status": "running",
            "bundle": "/bundle",
            "created": "1",
            "owner": "tester",
            "annotations": {},
            "ociVersion": OCI_VERSION
        });
        let status: Status = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(status.process_start_time, None);
        assert_eq!(status.created, "1970-01-01T00:00:00.000000Z");
        assert!(
            serde_json::to_value(status)
                .unwrap()
                .get("process-start-time")
                .is_none()
        );

        value["process-start-time"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<Status>(value).is_err());
    }

    #[test]
    fn status_load_accepts_integral_floats_but_rejects_narrowing() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("status.json");
        fs::write(
            &path,
            br#"{"id":"demo","pid":0.0,"process-start-time":5.0,"bundle":"/bundle","created":"0","owner":"tester","annotations":{},"ociVersion":"1.3.0"}"#,
        )
        .unwrap();
        let status = load_status(&path).unwrap();
        assert_eq!(status.pid, 0);
        assert_eq!(status.process_start_time, Some(5));

        fs::write(
            &path,
            br#"{"id":"demo","pid":2147483648,"bundle":"/bundle","created":"0","owner":"tester","annotations":{},"ociVersion":"1.3.0"}"#,
        )
        .unwrap();
        assert!(load_status(&path).is_err());
    }

    #[test]
    fn quotes_table_paths_like_std_filesystem() {
        assert_eq!(quoted_path(Path::new("/a b/\\\"c")), r#""/a b/\\\"c""#);
    }

    #[test]
    fn config_copy_preserves_permissions_and_rejects_overwrite() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("state");
        fs::create_dir_all(root.join("demo")).unwrap();
        let source = temporary.path().join("config.json");
        fs::write(&source, b"first").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();

        save_config(&root, "demo", &source).unwrap();
        let destination = root.join("demo/config.json");
        assert_eq!(fs::read(&destination).unwrap(), b"first");
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o640
        );

        fs::write(&source, b"second").unwrap();
        let error = save_config(&root, "demo", &source).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "filesystem error: cannot copy: File exists [{}] [{}]",
                source.display(),
                destination.display()
            )
        );
        assert_eq!(fs::read(destination).unwrap(), b"first");
    }
}
