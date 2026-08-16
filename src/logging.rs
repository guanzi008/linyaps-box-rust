use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::registry::LookupSpan;

use crate::cli::{GlobalOptions, LogFormat, LogLevel};

static SYSLOG_LOCK: Mutex<()> = Mutex::new(());
pub const FATAL_TARGET: &str = "linyaps_box::fatal";

thread_local! {
    static CURRENT_JOURNAL_CONTEXT: RefCell<Option<JournalContext>> = const { RefCell::new(None) };
}

pub fn initialize(options: &GlobalOptions) -> Result<()> {
    let level = match options.log_level {
        LogLevel::Fatal => "off,linyaps_box::fatal=error",
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
    };
    let filter = EnvFilter::new(level)
        .add_directive("libcontainer=off".parse()?)
        .add_directive("libcgroups=off".parse()?);
    let destinations = if options.log.is_empty() {
        vec!["stderr".to_string()]
    } else {
        options.log.clone()
    };
    let sinks = destinations
        .iter()
        .map(|destination| Sink::open(destination, options.cee_syslog))
        .collect::<Result<Vec<_>>>()?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .event_format(OciFormatter(options.log_format))
        .with_writer(SinkWriterFactory {
            format: options.log_format,
            sinks: Arc::new(sinks),
        })
        .try_init()
        .map_err(|error| anyhow!("failed to initialize logger: {error}"))
}

enum Sink {
    Stderr,
    File(Mutex<File>),
    Syslog { ident: CString, cee: bool },
    Journald { ident: String },
}

impl Sink {
    fn open(destination: &str, cee: bool) -> Result<Self> {
        if destination == "stderr" {
            return Ok(Self::Stderr);
        }
        let (scheme, content) = destination
            .split_once(':')
            .map_or(("file", destination), |(scheme, content)| (scheme, content));
        match scheme {
            "file" => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(content)
                    .map_err(|error| anyhow!(io_error_message(&error)))?;
                Ok(Self::File(Mutex::new(file)))
            }
            "syslog" => Ok(Self::Syslog {
                ident: CString::new(content).context("syslog identifier contains a NUL byte")?,
                cee,
            }),
            "journald" => Ok(Self::Journald {
                ident: content.to_string(),
            }),
            _ => Err(anyhow!("unknown log destination: {destination}")),
        }
    }

    fn write(
        &self,
        bytes: &[u8],
        level: &Level,
        fatal: bool,
        format: LogFormat,
        context: Option<&JournalContext>,
    ) {
        match self {
            Self::Stderr => {
                let _ = io::stderr().lock().write_all(bytes);
            }
            Self::File(file) => {
                if let Ok(mut file) = file.lock() {
                    let _ = file.write_all(bytes);
                }
            }
            Self::Syslog { ident, cee } => {
                write_syslog(
                    ident,
                    bytes,
                    level,
                    fatal,
                    *cee && format == LogFormat::Json,
                );
            }
            Self::Journald { ident } => {
                write_journal(ident, bytes, level, fatal, format, context);
            }
        }
    }
}

#[derive(Clone)]
struct SinkWriterFactory {
    format: LogFormat,
    sinks: Arc<Vec<Sink>>,
}

impl<'writer> MakeWriter<'writer> for SinkWriterFactory {
    type Writer = EventWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        EventWriter {
            bytes: Vec::new(),
            format: self.format,
            level: Level::INFO,
            fatal: false,
            sinks: self.sinks.clone(),
        }
    }

    fn make_writer_for(&'writer self, metadata: &Metadata<'_>) -> Self::Writer {
        EventWriter {
            bytes: Vec::new(),
            format: self.format,
            level: *metadata.level(),
            fatal: metadata.target() == FATAL_TARGET,
            sinks: self.sinks.clone(),
        }
    }
}

struct EventWriter {
    bytes: Vec<u8>,
    format: LogFormat,
    level: Level,
    fatal: bool,
    sinks: Arc<Vec<Sink>>,
}

impl Write for EventWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for EventWriter {
    fn drop(&mut self) {
        if self.bytes.is_empty() {
            return;
        }
        let context = CURRENT_JOURNAL_CONTEXT.with(|context| context.borrow_mut().take());
        for sink in self.sinks.iter() {
            sink.write(
                &self.bytes,
                &self.level,
                self.fatal,
                self.format,
                context.as_ref(),
            );
        }
    }
}

#[derive(Clone, Copy)]
struct OciFormatter(LogFormat);

impl<S, Fields> FormatEvent<S, Fields> for OciFormatter
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    Fields: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        _context: &FmtContext<'_, S, Fields>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let formatted = visitor.finish();
        let timestamp = timestamp();
        let metadata = event.metadata();
        let level = if metadata.target() == FATAL_TARGET {
            "FATAL"
        } else {
            level_name(metadata.level())
        };
        let file = metadata
            .file()
            .and_then(|file| Path::new(file).file_name())
            .and_then(|file| file.to_str())
            .unwrap_or_default();
        let line = metadata.line().unwrap_or_default();
        let pid = formatted.pid.unwrap_or_else(std::process::id);
        let function = formatted.function.as_deref().unwrap_or_else(|| {
            metadata
                .module_path()
                .unwrap_or_else(|| metadata.target())
                .rsplit("::")
                .next()
                .unwrap_or_default()
        });
        CURRENT_JOURNAL_CONTEXT.with(|context| {
            *context.borrow_mut() = Some(JournalContext {
                message: formatted.message.clone(),
                file: file.to_string(),
                line: u64::from(line),
                function: function.to_string(),
                errno: formatted.errno,
            });
        });
        match self.0 {
            LogFormat::Text => {
                let message = formatted
                    .message
                    .trim_end_matches('\n')
                    .replace('\n', "\n    ");
                write!(
                    writer,
                    "[{timestamp}] [{level:<5}] [{pid}] [{file}:{line} {function}]:\n    {message}",
                )?;
                if let Some(errno) = nonzero_errno(formatted.errno) {
                    write!(writer, "\n    {}", strerror(errno))?;
                }
                writeln!(writer)
            }
            LogFormat::Json => {
                let errno = nonzero_errno(formatted.errno);
                let error_text = errno.map(strerror);
                let value = JsonLogRecord {
                    time: &timestamp,
                    level,
                    pid,
                    message: &formatted.message,
                    file,
                    line,
                    function,
                    errno,
                    error_text: error_text.as_deref(),
                };
                let value = serde_json::to_string(&value).map_err(|_| fmt::Error)?;
                writeln!(writer, "{value}")
            }
        }
    }
}

#[derive(Serialize)]
struct JsonLogRecord<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    errno: Option<i32>,
    file: &'a str,
    function: &'a str,
    level: &'a str,
    line: u32,
    #[serde(rename = "msg")]
    message: &'a str,
    pid: u32,
    #[serde(rename = "strerror", skip_serializing_if = "Option::is_none")]
    error_text: Option<&'a str>,
    time: &'a str,
}

#[derive(Default)]
struct MessageVisitor {
    fields: Vec<String>,
    message: Option<String>,
    errno: Option<i32>,
    function: Option<String>,
    pid: Option<u32>,
}

impl MessageVisitor {
    fn finish(self) -> FormattedMessage {
        let message = match (self.message, self.fields.is_empty()) {
            (Some(message), true) => message,
            (Some(message), false) => format!("{message} {}", self.fields.join(" ")),
            (None, _) => self.fields.join(" "),
        };
        FormattedMessage {
            message,
            errno: self.errno,
            function: self.function,
            pid: self.pid,
        }
    }

    fn record_value(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else if field.name() == "function" {
            self.function = Some(value);
        } else {
            self.fields.push(format!("{}={value}", field.name()));
        }
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_value(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "errno" {
            self.errno = i32::try_from(value).ok();
        } else if field.name() == "compat_pid" {
            self.pid = u32::try_from(value).ok();
        } else {
            self.record_value(field, value.to_string());
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "errno" {
            self.errno = i32::try_from(value).ok();
        } else if field.name() == "compat_pid" {
            self.pid = u32::try_from(value).ok();
        } else {
            self.record_value(field, value.to_string());
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record_value(field, value.to_string());
    }
}

struct FormattedMessage {
    message: String,
    errno: Option<i32>,
    function: Option<String>,
    pid: Option<u32>,
}

fn strerror(errno: i32) -> String {
    let pointer = unsafe { libc::strerror(errno) };
    if pointer.is_null() {
        return format!("Unknown error {errno}");
    }
    unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

fn nonzero_errno(errno: Option<i32>) -> Option<i32> {
    errno.filter(|errno| *errno != 0)
}

fn io_error_message(error: &io::Error) -> String {
    error
        .raw_os_error()
        .map(strerror)
        .unwrap_or_else(|| error.to_string())
}

fn timestamp() -> String {
    let now = Utc::now();
    format!(
        "{}.{:09}Z",
        now.format("%Y-%m-%dT%H:%M:%S"),
        now.timestamp_subsec_nanos()
    )
}

fn level_name(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG | Level::TRACE => "DEBUG",
    }
}

fn syslog_priority(level: &Level, fatal: bool) -> libc::c_int {
    if fatal {
        return libc::LOG_CRIT;
    }
    match *level {
        Level::ERROR => libc::LOG_ERR,
        Level::WARN => libc::LOG_WARNING,
        Level::INFO => libc::LOG_INFO,
        Level::DEBUG | Level::TRACE => libc::LOG_DEBUG,
    }
}

fn write_syslog(ident: &CString, bytes: &[u8], level: &Level, fatal: bool, cee: bool) {
    let Ok(_guard) = SYSLOG_LOCK.lock() else {
        return;
    };
    let message = syslog_message(bytes, cee);
    let Ok(message) = CString::new(message) else {
        return;
    };
    unsafe {
        libc::openlog(ident.as_ptr(), 0, libc::LOG_USER);
        libc::syslog(
            syslog_priority(level, fatal),
            c"%s".as_ptr(),
            message.as_ptr(),
        );
        libc::closelog();
    }
}

fn syslog_message(bytes: &[u8], cee: bool) -> Vec<u8> {
    let bytes = &bytes[..bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())];
    let mut message = Vec::with_capacity(bytes.len() + usize::from(cee) * 6);
    if cee {
        message.extend_from_slice(b"@cee: ");
    }
    message.extend_from_slice(bytes);
    message
}

fn write_journal(
    ident: &str,
    bytes: &[u8],
    level: &Level,
    fatal: bool,
    format: LogFormat,
    context: Option<&JournalContext>,
) {
    let extracted;
    let context = if let Some(context) = context {
        context
    } else {
        extracted = extract_journal_context(bytes, format);
        &extracted
    };
    let datagram = journal_datagram(ident, level, fatal, context);
    if let Ok(socket) = UnixDatagram::unbound() {
        let _ = socket.send_to(&datagram, "/run/systemd/journal/socket");
    }
}

fn journal_datagram(ident: &str, level: &Level, fatal: bool, context: &JournalContext) -> Vec<u8> {
    let line = context.line.to_string();
    let errno = context.errno.unwrap_or_default().to_string();
    let fields = [
        ("MESSAGE", context.message.as_str()),
        ("PRIORITY", journal_priority(level, fatal)),
        ("SYSLOG_IDENTIFIER", ident),
        ("CODE_FILE", context.file.as_str()),
        ("CODE_LINE", line.as_str()),
        ("CODE_FUNC", context.function.as_str()),
        ("ERRNO", errno.as_str()),
    ];
    let mut datagram = Vec::new();
    for (key, value) in fields {
        append_journal_field(&mut datagram, key, value.as_bytes());
    }
    datagram
}

struct JournalContext {
    message: String,
    file: String,
    line: u64,
    function: String,
    errno: Option<i32>,
}

fn extract_journal_context(bytes: &[u8], format: LogFormat) -> JournalContext {
    if format == LogFormat::Json
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes)
    {
        return JournalContext {
            message: value["msg"].as_str().unwrap_or_default().to_string(),
            file: value["file"].as_str().unwrap_or_default().to_string(),
            line: value["line"].as_u64().unwrap_or_default(),
            function: value["function"].as_str().unwrap_or_default().to_string(),
            errno: value["errno"]
                .as_i64()
                .and_then(|value| value.try_into().ok()),
        };
    }
    let formatted = String::from_utf8_lossy(bytes);
    let header = formatted.lines().next().unwrap_or_default();
    let source = header
        .rsplit_once('[')
        .map(|(_, source)| source)
        .unwrap_or_default();
    let source = source.strip_suffix("]:").unwrap_or(source);
    let (file_and_line, function) = source.split_once(' ').unwrap_or((source, ""));
    let (file, line) = file_and_line
        .rsplit_once(':')
        .unwrap_or((file_and_line, "0"));
    JournalContext {
        message: extract_message(bytes, format),
        file: file.to_string(),
        line: line.parse().unwrap_or_default(),
        function: function.to_string(),
        errno: None,
    }
}

fn extract_message(bytes: &[u8], format: LogFormat) -> String {
    let formatted = String::from_utf8_lossy(bytes);
    match format {
        LogFormat::Json => serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|value| value["msg"].as_str().map(str::to_string))
            .unwrap_or_else(|| formatted.trim_end().to_string()),
        LogFormat::Text => formatted
            .split_once(":\n")
            .map(|(_, message)| {
                message
                    .trim_end_matches('\n')
                    .lines()
                    .map(|line| line.strip_prefix("    ").unwrap_or(line))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_else(|| formatted.trim_end().to_string()),
    }
}

fn journal_priority(level: &Level, fatal: bool) -> &'static str {
    if fatal {
        return "2";
    }
    match *level {
        Level::ERROR => "3",
        Level::WARN => "4",
        Level::INFO => "6",
        Level::DEBUG | Level::TRACE => "7",
    }
}

fn append_journal_field(output: &mut Vec<u8>, key: &str, value: &[u8]) {
    if value.contains(&b'\n') {
        output.extend_from_slice(key.as_bytes());
        output.push(b'\n');
        output.extend_from_slice(&(value.len() as u64).to_le_bytes());
        output.extend_from_slice(value);
        output.push(b'\n');
    } else {
        output.extend_from_slice(key.as_bytes());
        output.push(b'=');
        output.extend_from_slice(value);
        output.push(b'\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_messages_from_both_output_formats() {
        assert_eq!(
            extract_message(
                b"[2026-01-01T00:00:00.000000000Z] [ERROR] [1]:\n    first\n    second\n",
                LogFormat::Text
            ),
            "first\nsecond"
        );
        assert_eq!(
            extract_message(b"{\"msg\":\"failure\"}\n", LogFormat::Json),
            "failure"
        );
    }

    #[test]
    fn journal_binary_field_encodes_embedded_newlines() {
        let mut output = Vec::new();
        append_journal_field(&mut output, "MESSAGE", b"one\ntwo");
        assert_eq!(&output[..8], b"MESSAGE\n");
        assert_eq!(u64::from_le_bytes(output[8..16].try_into().unwrap()), 7);
        assert_eq!(&output[16..], b"one\ntwo\n");
    }

    #[test]
    fn extracts_journal_source_fields_from_both_formats() {
        let text = extract_journal_context(
            b"[2026-01-01T00:00:00.000000000Z] [ERROR] [7] [exec.cpp:68 exec]:\n    failure\n",
            LogFormat::Text,
        );
        assert_eq!(text.message, "failure");
        assert_eq!(text.file, "exec.cpp");
        assert_eq!(text.line, 68);
        assert_eq!(text.function, "exec");
        assert_eq!(text.errno, None);

        let json = extract_journal_context(
            b"{\"msg\":\"denied\",\"file\":\"container.cpp\",\"line\":137,\"function\":\"run\",\"errno\":13}\n",
            LogFormat::Json,
        );
        assert_eq!(json.message, "denied");
        assert_eq!(json.file, "container.cpp");
        assert_eq!(json.line, 137);
        assert_eq!(json.function, "run");
        assert_eq!(json.errno, Some(13));
    }

    #[test]
    fn journald_datagram_preserves_structured_errno() {
        let context = JournalContext {
            message: "segfault".to_string(),
            file: "crash.c".to_string(),
            line: 77,
            function: "deref".to_string(),
            errno: Some(13),
        };
        assert_eq!(
            journal_datagram("myapp", &Level::ERROR, true, &context),
            b"MESSAGE=segfault\nPRIORITY=2\nSYSLOG_IDENTIFIER=myapp\nCODE_FILE=crash.c\nCODE_LINE=77\nCODE_FUNC=deref\nERRNO=13\n"
        );
    }

    #[test]
    fn logger_initialization_uses_system_error_text() {
        assert_eq!(
            io_error_message(&io::Error::from_raw_os_error(libc::ENOENT)),
            "No such file or directory"
        );
    }

    #[test]
    fn level_and_priority_mappings_match_the_frozen_runtime() {
        assert_eq!(level_name(&Level::ERROR), "ERROR");
        assert_eq!(level_name(&Level::WARN), "WARN");
        assert_eq!(level_name(&Level::INFO), "INFO");
        assert_eq!(level_name(&Level::DEBUG), "DEBUG");
        assert_eq!(syslog_priority(&Level::ERROR, false), libc::LOG_ERR);
        assert_eq!(syslog_priority(&Level::WARN, false), libc::LOG_WARNING);
        assert_eq!(syslog_priority(&Level::INFO, false), libc::LOG_INFO);
        assert_eq!(syslog_priority(&Level::DEBUG, false), libc::LOG_DEBUG);
        assert_eq!(syslog_priority(&Level::ERROR, true), libc::LOG_CRIT);
        assert_eq!(journal_priority(&Level::ERROR, false), "3");
        assert_eq!(journal_priority(&Level::WARN, false), "4");
        assert_eq!(journal_priority(&Level::INFO, false), "6");
        assert_eq!(journal_priority(&Level::DEBUG, false), "7");
        assert_eq!(journal_priority(&Level::ERROR, true), "2");
    }

    #[test]
    fn zero_errno_is_only_emitted_to_journald() {
        assert_eq!(nonzero_errno(None), None);
        assert_eq!(nonzero_errno(Some(0)), None);
        assert_eq!(nonzero_errno(Some(libc::EACCES)), Some(libc::EACCES));

        let context = JournalContext {
            message: "ok".to_string(),
            file: "main.cpp".to_string(),
            line: 8,
            function: "main".to_string(),
            errno: Some(0),
        };
        assert!(journal_datagram("ll-box", &Level::INFO, false, &context).ends_with(b"ERRNO=0\n"));
    }

    #[test]
    fn json_field_order_matches_nlohmann_map_order() {
        let record = JsonLogRecord {
            time: "1970-01-01T00:00:00.005000000Z",
            level: "ERROR",
            pid: 7,
            message: "failure",
            file: "exec.cpp",
            line: 42,
            function: "run",
            errno: Some(libc::EACCES),
            error_text: Some("Permission denied"),
        };
        assert_eq!(
            serde_json::to_string(&record).unwrap(),
            "{\"errno\":13,\"file\":\"exec.cpp\",\"function\":\"run\",\"level\":\"ERROR\",\"line\":42,\"msg\":\"failure\",\"pid\":7,\"strerror\":\"Permission denied\",\"time\":\"1970-01-01T00:00:00.005000000Z\"}"
        );
    }

    #[test]
    fn syslog_preserves_newlines_and_truncates_at_nul() {
        assert_eq!(syslog_message(b"message\n", false), b"message\n");
        assert_eq!(
            syslog_message(b"message\0ignored\n", true),
            b"@cee: message"
        );
    }
}
