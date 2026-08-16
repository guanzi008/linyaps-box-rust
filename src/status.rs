use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use serde::{Deserialize, Serialize};

use crate::OCI_VERSION;
use crate::cli::ListFormat;

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
    #[serde(rename = "status")]
    pub status: RuntimeStatus,
    #[serde(rename = "bundle")]
    pub bundle: PathBuf,
    #[serde(rename = "created")]
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
            status: RuntimeStatus::Creating,
            bundle: original_bundle,
            created,
            owner,
            annotations: BTreeMap::new(),
            oci_version: OCI_VERSION.to_string(),
        })
    }

    pub fn refresh_liveness(&mut self) -> Result<()> {
        if unsafe { libc::kill(self.pid, 0) } == 0 {
            return Ok(());
        }
        match Errno::last() {
            Errno::EPERM => Ok(()),
            Errno::ESRCH => {
                self.status = RuntimeStatus::Stopped;
                Ok(())
            }
            error => Err(error).context("failed to probe container process"),
        }
    }
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
    let value = serde_json::to_value(status)?;
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
    let mut status: Status = serde_json::from_slice(&content)
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
            let values = statuses
                .iter()
                .map(serde_json::to_value)
                .collect::<std::result::Result<Vec<_>, _>>()?;
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
        name_width = width + 1
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
    let mut temporary_name = path.as_os_str().to_os_string();
    temporary_name.push(".tmp");
    let temporary_path = PathBuf::from(temporary_name);
    let result = (|| -> io::Result<()> {
        let mut temporary = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary_path)?;
        temporary.write_all(content)?;
        drop(temporary);
        fs::rename(&temporary_path, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result.with_context(|| format!("failed to atomically write status file: {}", path.display()))
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
    fn uses_oci_compatible_field_names() {
        let status = Status {
            id: "demo".to_string(),
            pid: 0,
            status: RuntimeStatus::Stopped,
            bundle: PathBuf::from("/bundle"),
            created: "1".to_string(),
            owner: "tester".to_string(),
            annotations: BTreeMap::new(),
            oci_version: OCI_VERSION.to_string(),
        };
        let value = serde_json::to_value(status).unwrap();
        assert_eq!(value["ociVersion"], OCI_VERSION);
        assert_eq!(value["status"], "stopped");
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
