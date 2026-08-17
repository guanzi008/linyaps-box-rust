use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::str::FromStr;

use clap::error::{ContextKind, ErrorKind};
use clap::{Args, Parser, Subcommand, ValueEnum};
use libcontainer::signal::Signal;

use crate::OCI_VERSION;
use crate::capability;

const LINYAPS_BOX_VERSION: &str = "2.3.0-dev-";

#[derive(Debug, Parser)]
#[command(
    name = "ll-box",
    about = "A simple OCI runtime implementation focused on desktop applications.",
    version = version_text(),
    disable_version_flag = true,
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    version: Option<bool>,

    #[command(flatten)]
    pub global: GlobalOptions,

    #[command(subcommand)]
    pub command: Command,
}

pub fn parse() -> Cli {
    let arguments = env::args_os().collect::<Vec<_>>();
    match try_parse_from(arguments.clone()) {
        Ok(options) => options,
        Err(error) => match error.kind() {
            ErrorKind::DisplayHelp => {
                print!("{}", help_text(find_subcommand(&arguments)));
                std::process::exit(0);
            }
            ErrorKind::DisplayVersion => {
                println!("ll-box version {LINYAPS_BOX_VERSION}\nspec {OCI_VERSION}\n");
                std::process::exit(0);
            }
            _ => {
                eprint!("{}", parse_error_text(&arguments, &error));
                std::process::exit(1);
            }
        },
    }
}

pub fn try_parse_from<I, T>(arguments: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    Cli::try_parse_from(normalize_exec_arguments(normalize_log_arguments(arguments)))
}

fn normalize_log_arguments<I, T>(arguments: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
    let mut normalized = Vec::with_capacity(arguments.len());
    let mut index = 0;
    while index < arguments.len() {
        normalized.push(arguments[index].clone());
        if arguments[index] == OsStr::new("--log") && index + 1 < arguments.len() {
            index += 1;
            normalized.push(arguments[index].clone());
            while index + 1 < arguments.len() {
                let candidate = arguments[index + 1].as_os_str();
                if candidate.as_encoded_bytes().starts_with(b"-")
                    || ["list", "run", "exec", "kill"]
                        .iter()
                        .any(|command| candidate == OsStr::new(command))
                {
                    break;
                }
                index += 1;
                normalized.push(OsString::from("--log"));
                normalized.push(arguments[index].clone());
            }
        }
        index += 1;
    }
    normalized
}

fn normalize_exec_arguments<I, T>(arguments: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
    let Some(exec) = find_exec_subcommand(&arguments) else {
        return arguments;
    };
    let mut index = exec + 1;
    while index < arguments.len() {
        if let Some((option, value)) = split_exec_variadic_option(&arguments[index]) {
            arguments.splice(index..=index, [OsString::from(option), value]);
        }
        let argument = arguments[index].as_os_str();
        if argument == OsStr::new("--") {
            return arguments;
        }
        if is_exec_variadic_option(argument) {
            let mut end = index + 1;
            while end < arguments.len() && !arguments[end].as_encoded_bytes().starts_with(b"-") {
                end += 1;
            }
            if end == arguments.len() && end.saturating_sub(index + 1) >= 2 {
                arguments.insert(end - 1, OsString::from("--"));
                return arguments;
            }
            index = end;
            continue;
        }
        if exec_option_takes_value(argument) {
            index += 2;
            continue;
        }
        if exec_option_has_attached_value(argument) || exec_flag_has_attached_value(argument) {
            index += 1;
            continue;
        }
        if is_exec_flag(argument) {
            index += 1;
            continue;
        }
        if argument.as_encoded_bytes().starts_with(b"-") {
            return arguments;
        }
        if index + 1 < arguments.len() {
            arguments.insert(index + 1, OsString::from("--"));
        }
        return arguments;
    }
    arguments
}

fn split_exec_variadic_option(argument: &OsStr) -> Option<(&'static str, OsString)> {
    let value = argument.to_str()?;
    for (prefix, option) in [("--env=", "--env"), ("--cap=", "--cap")] {
        if let Some(value) = value.strip_prefix(prefix) {
            return Some((option, OsString::from(value)));
        }
    }
    for (prefix, option) in [("-e", "-e"), ("-c", "-c")] {
        if let Some(value) = value.strip_prefix(prefix).filter(|value| !value.is_empty()) {
            return Some((option, OsString::from(value)));
        }
    }
    None
}

fn find_exec_subcommand(arguments: &[OsString]) -> Option<usize> {
    find_subcommand_entry(arguments)
        .filter(|(_, command)| *command == "exec")
        .map(|(index, _)| index)
}

fn find_subcommand(arguments: &[OsString]) -> Option<&'static str> {
    find_subcommand_entry(arguments).map(|(_, command)| command)
}

fn find_subcommand_entry(arguments: &[OsString]) -> Option<(usize, &'static str)> {
    let mut index = 1;
    while index < arguments.len() {
        let argument = arguments[index].as_os_str();
        for command in ["list", "run", "exec", "kill"] {
            if argument == OsStr::new(command) {
                return Some((index, command));
            }
        }
        if global_option_takes_value(argument) {
            index += 2;
        } else {
            index += 1;
        }
    }
    None
}

fn parse_error_text(arguments: &[OsString], error: &clap::Error) -> String {
    let command = find_subcommand(arguments);
    let message = if command.is_none() && error.kind() == ErrorKind::UnknownArgument {
        Some("A subcommand is required".to_string())
    } else {
        None
    }
    .or_else(|| missing_option_value(arguments, command))
    .or_else(|| repeated_option_error(arguments, command, error))
    .or_else(|| validation_error(error))
    .or_else(|| unexpected_argument_error(arguments, command, error))
    .unwrap_or_else(|| match (error.kind(), command) {
        (ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand, _)
        | (ErrorKind::MissingSubcommand, _)
        | (ErrorKind::InvalidSubcommand, None) => "A subcommand is required".to_string(),
        (ErrorKind::MissingRequiredArgument, Some("run" | "kill")) => {
            "CONTAINER is required".to_string()
        }
        (ErrorKind::MissingRequiredArgument, Some("exec"))
            if exec_has_container_without_command(arguments) =>
        {
            "At least one of COMMAND or --process must be provided".to_string()
        }
        (ErrorKind::MissingRequiredArgument, Some("exec")) => "CONTAINER is required".to_string(),
        _ => clap_error_summary(error),
    });
    format!("{message}\nRun with --help for more information.\n")
}

fn clap_error_summary(error: &clap::Error) -> String {
    let rendered = error.to_string();
    let summary = rendered
        .lines()
        .take_while(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    summary
        .strip_prefix("error: ")
        .unwrap_or(&summary)
        .to_string()
}

fn error_context(error: &clap::Error, kind: ContextKind) -> Option<String> {
    error.get(kind).map(ToString::to_string)
}

fn missing_option_value(arguments: &[OsString], command: Option<&str>) -> Option<String> {
    let command_index = command.and_then(|name| {
        arguments
            .iter()
            .position(|argument| argument == OsStr::new(name))
    });
    for (index, argument) in arguments.iter().enumerate().skip(1) {
        let in_global = command_index.is_none_or(|command_index| index < command_index);
        let in_command = command_index.is_some_and(|command_index| index > command_index);
        let specification = if in_global {
            global_option_specification(argument)
        } else if in_command {
            command_option_specification(command?, argument)
        } else {
            None
        };
        if let Some((name, type_name)) = specification
            && index + 1 == arguments.len()
        {
            return Some(format!("{name}: 1 required {type_name} missing"));
        }
    }
    None
}

fn global_option_specification(argument: &OsStr) -> Option<(&'static str, &'static str)> {
    match argument.as_encoded_bytes() {
        b"--root" => Some(("--root", "TEXT")),
        b"--cgroup-manager" => Some((
            "--cgroup-manager",
            "MANAGER:value in {cgroupfs->cgroupfs,systemd->systemd,disabled->disabled} OR {2,1,0}",
        )),
        b"--log-level" => Some((
            "--log-level",
            "LEVEL:value in {fatal->0,error->1,warn->2,info->3,debug->4} OR {0,1,2,3,4}",
        )),
        b"--log-format" => Some(("--log-format", "FORMAT:value in {text->0,json->1} OR {0,1}")),
        b"--log" => Some(("--log", "SINK")),
        _ => None,
    }
}

fn command_option_specification(
    command: &str,
    argument: &OsStr,
) -> Option<(&'static str, &'static str)> {
    match (command, argument.as_encoded_bytes()) {
        ("list", b"-f" | b"--format") => {
            Some(("--format", "FORMAT:value in {json->1,table->0} OR {1,0}"))
        }
        ("run", b"-b" | b"--bundle") => Some(("--bundle", "TEXT:DIR")),
        ("run", b"-f" | b"--config") => Some(("--config", "FILE")),
        ("run" | "exec", b"--preserve-fds") => Some(("--preserve-fds", "N:NONNEGATIVE")),
        ("run" | "exec", b"--console-socket") => {
            Some(("--console-socket", "SOCKET:must be an existing socket file"))
        }
        ("exec", b"-u" | b"--user") => Some(("--user", "UID[:GID]")),
        ("exec", b"--cwd") => Some(("--cwd", "PATH")),
        ("exec", b"-e" | b"--env") => {
            Some(("--env", "ENV:check environment variables is valid or not"))
        }
        ("exec", b"-c" | b"--cap") => Some(("--cap", "CAP")),
        ("exec", b"-p" | b"--process") => Some(("--process", "FILE:FILE")),
        _ => None,
    }
}

fn repeated_option_error(
    arguments: &[OsString],
    command: Option<&str>,
    error: &clap::Error,
) -> Option<String> {
    if error.kind() != ErrorKind::ArgumentConflict {
        return None;
    }
    let global_options: &[(&str, &[&str])] = &[
        ("--root", &["--root"]),
        ("--cgroup-manager", &["--cgroup-manager"]),
        ("--log-level", &["--log-level"]),
        ("--log-format", &["--log-format"]),
    ];
    if let Some(message) = find_repeated_option(arguments, global_options) {
        return Some(message);
    }
    let command_options: &[(&str, &[&str])] = match command {
        Some("list") => &[("--format", &["-f", "--format"])],
        Some("run") => &[
            ("--bundle", &["-b", "--bundle"]),
            ("--config", &["-f", "--config"]),
            ("--preserve-fds", &["--preserve-fds"]),
            ("--console-socket", &["--console-socket"]),
        ],
        Some("exec") => &[
            ("--user", &["-u", "--user"]),
            ("--cwd", &["--cwd"]),
            ("--console-socket", &["--console-socket"]),
            ("--preserve-fds", &["--preserve-fds"]),
            ("--process", &["-p", "--process"]),
        ],
        _ => &[],
    };
    find_repeated_option(arguments, command_options)
}

fn find_repeated_option(arguments: &[OsString], options: &[(&str, &[&str])]) -> Option<String> {
    options.iter().find_map(|(canonical, names)| {
        let count = arguments
            .iter()
            .filter(|argument| option_matches(argument, names))
            .count();
        (count > 1).then(|| format!("{canonical}: At most 1 required but received {count}"))
    })
}

fn option_matches(argument: &OsStr, names: &[&str]) -> bool {
    let bytes = argument.as_encoded_bytes();
    names.iter().any(|name| {
        let name = name.as_bytes();
        bytes == name
            || (name.starts_with(b"--")
                && bytes.starts_with(name)
                && bytes.get(name.len()) == Some(&b'='))
            || (name.len() == 2
                && name.starts_with(b"-")
                && bytes.starts_with(name)
                && bytes.len() > 2)
    })
}

fn validation_error(error: &clap::Error) -> Option<String> {
    if !matches!(
        error.kind(),
        ErrorKind::InvalidValue | ErrorKind::ValueValidation
    ) {
        return None;
    }
    let argument = error_context(error, ContextKind::InvalidArg)?;
    let value = error_context(error, ContextKind::InvalidValue).unwrap_or_default();
    for flag in ["--cee-syslog", "--tty", "--no-new-privs"] {
        if argument.contains(flag) {
            return Some(format!("Could not convert: {flag} = {value}"));
        }
    }
    if argument.contains("cgroup-manager") {
        return Some(format!(
            "--cgroup-manager: Check {value} value in {{cgroupfs->cgroupfs,systemd->systemd,disabled->disabled}} OR {{2,1,0}} FAILED"
        ));
    }
    if argument.contains("log-level") {
        return Some(format!(
            "--log-level: Check {value} value in {{fatal->0,error->1,warn->2,info->3,debug->4}} OR {{0,1,2,3,4}} FAILED"
        ));
    }
    if argument.contains("log-format") {
        return Some(format!(
            "--log-format: Check {value} value in {{text->0,json->1}} OR {{0,1}} FAILED"
        ));
    }
    if argument.contains("format") {
        return Some(format!(
            "--format: Check {value} value in {{json->1,table->0}} OR {{1,0}} FAILED"
        ));
    }
    if argument.contains("--log") {
        return validate_log_sink(&value)
            .err()
            .map(|reason| format!("--log: {reason}"));
    }
    if argument.contains("bundle") {
        return existing_directory(&value)
            .err()
            .map(|reason| format!("--bundle: {reason}"));
    }
    if argument.contains("preserve-fds") {
        let numeric = value.parse::<f64>();
        return Some(match numeric {
            Ok(number) if (0.0..=f64::MAX).contains(&number) => {
                format!("Could not convert: --preserve-fds = {value}")
            }
            _ => format!("--preserve-fds: Value {value} not in range [0 - 1.79769e+308]"),
        });
    }
    if argument.contains("console-socket") {
        return Some(
            "--console-socket: console-socket must be an existing socket file".to_string(),
        );
    }
    if argument.contains("user") {
        return value
            .parse::<UserSpec>()
            .err()
            .map(|reason| format!("--user: {reason}"));
    }
    if argument.contains("env") {
        return valid_environment(&value)
            .err()
            .map(|reason| format!("--env: {reason}"));
    }
    if argument.contains("cap") {
        return valid_capability(&value)
            .err()
            .map(|reason| format!("--cap: --cap: {reason}"));
    }
    if argument.contains("process") {
        return existing_file(&value)
            .err()
            .map(|reason| format!("--process: {reason}"));
    }
    if argument.contains("SIGNAL") || argument.contains("signal") {
        if value.starts_with('-') && value.parse::<i32>().is_err() {
            return Some(format!(
                "kill: The following argument was not expected: {value}"
            ));
        }
        return valid_signal(&value)
            .err()
            .map(|reason| format!("SIGNAL: SIGNAL: {reason}"));
    }
    None
}

fn unexpected_argument_error(
    arguments: &[OsString],
    command: Option<&str>,
    error: &clap::Error,
) -> Option<String> {
    if !matches!(
        error.kind(),
        ErrorKind::UnknownArgument | ErrorKind::InvalidSubcommand | ErrorKind::TooManyValues
    ) {
        return None;
    }
    let command = command?;
    let invalid = error_context(error, ContextKind::InvalidArg)
        .or_else(|| error_context(error, ContextKind::InvalidSubcommand))?;
    let invalid_index = arguments
        .iter()
        .position(|argument| argument.to_string_lossy() == invalid)?;
    let command_index = arguments
        .iter()
        .position(|argument| argument == OsStr::new(command))?;
    let end = if invalid_index < command_index {
        command_index
    } else {
        arguments.len()
    };
    let unexpected = arguments[invalid_index..end]
        .iter()
        .map(|argument| argument.to_string_lossy())
        .collect::<Vec<_>>();
    let scope = if invalid_index < command_index {
        "ll-box"
    } else {
        command
    };
    Some(if unexpected.len() == 1 {
        format!(
            "{scope}: The following argument was not expected: {}",
            unexpected[0]
        )
    } else {
        format!(
            "{scope}: The following arguments were not expected: {}",
            unexpected.join(" ")
        )
    })
}

fn exec_has_container_without_command(arguments: &[OsString]) -> bool {
    let Some(exec) = find_exec_subcommand(arguments) else {
        return false;
    };
    let tail = &arguments[exec + 1..];
    !tail.is_empty()
        && !tail.iter().any(|argument| {
            matches!(argument.as_encoded_bytes(), b"-p" | b"--process")
                || argument.as_encoded_bytes().starts_with(b"--process=")
        })
}

fn help_text(command: Option<&str>) -> String {
    match command {
        Some("list") => LIST_HELP.to_string(),
        Some("run") => RUN_HELP.to_string(),
        Some("exec") => EXEC_HELP.to_string(),
        Some("kill") => KILL_HELP.to_string(),
        _ => ROOT_HELP.replace("{root}", &default_root_path().display().to_string()),
    }
}

const ROOT_HELP: &str = "A simple OCI runtime implementation focused on desktop applications.\n\n\nll-box [OPTIONS] SUBCOMMAND\n\n\nOPTIONS:\n  -h,     --help              Print this help message and exit\n  -v,     --version           Display program version information and exit\n          --root TEXT [{root}]  \n                              Root directory for storage of container state\n          --cgroup-manager MANAGER:value in {cgroupfs->cgroupfs,systemd->systemd,disabled->disabled} OR {2,1,0} [0]  \n                              Cgroup manager to use\n          --log-level LEVEL:value in {fatal->0,error->1,warn->2,info->3,debug->4} OR {0,1,2,3,4} [2]  (Env:LINYAPS_BOX_LOG_LEVEL) \n                              Set log level (fatal/error/warn/info/debug)\n          --log-format FORMAT:value in {text->0,json->1} OR {0,1} [0]  \n                              Set log format: text (default) or json\n          --log SINK ...      Log destinations (stderr, [file:]PATH, syslog:ID, journald:ID)\n          --cee-syslog        Prefix syslog messages with @cee: when --log-format=json\n\nSUBCOMMANDS:\n  list                        List known containers\n  run                         Create and immediately start a container\n  exec                        Exec a command in a running container\n  kill                        Send the specified signal to the container init process\n";

const LIST_HELP: &str = "List known containers\n\n\nll-box list [OPTIONS]\n\n\nOPTIONS:\n  -h,     --help              Print this help message and exit\n  -f,     --format FORMAT:value in {json->1,table->0} OR {1,0} [0]  \n                              Specify the output format\n";

const RUN_HELP: &str = "Create and immediately start a container\n\n\nll-box run [OPTIONS] CONTAINER\n\n\nPOSITIONALS:\n  CONTAINER TEXT REQUIRED     The container ID\n\nOPTIONS:\n  -h,     --help              Print this help message and exit\n  -b,     --bundle TEXT:DIR [.]  \n                              Path to the OCI bundle\n  -f,     --config FILE [config.json]  \n                              Override the configuration file to use\n          --preserve-fds N:NONNEGATIVE [0]  \n                              Pass N additional file descriptors to the container\n          --console-socket SOCKET:must be an existing socket file \n                              Path to an unix socket that will receive the master end of the\n                              console's pseudoterminal\n";

const EXEC_HELP: &str = "Exec a command in a running container\n\n\nll-box exec [OPTIONS] CONTAINER [COMMAND...]\n\n\nPOSITIONALS:\n  CONTAINER TEXT REQUIRED     Container ID\n  COMMAND TEXT ...            Command to execute\n\nOPTIONS:\n  -h,     --help              Print this help message and exit\n  -u,     --user UID[:GID]    Specify the user, for example `1000` for UID=1000 or `1000:1000`\n                              for UID=1000 and GID=1000\n          --cwd PATH          Current working directory.\n  -e,     --env ENV:check environment variables is valid or not ... \n                              Environment variables to set, use -e KEY=VALUE -e KEY2=VALUE2 for\n                              multiple\n          --console-socket SOCKET:must be an existing socket file \n                              Path to an unix socket that will receive the master end of the\n                              console's pseudoterminal\n  -t,     --tty               Allocate a pseudo-TTY\n          --preserve-fds N:NONNEGATIVE [0]  \n                              Pass N additional file descriptors to the container\n  -c,     --cap CAP ...       Set capabilities\n          --no-new-privs      Set the no new privileges value for the process\n  -p,     --process FILE:FILE Path to the process.json file to use\n";

const KILL_HELP: &str = "Send the specified signal to the container init process\n\n\nll-box kill [OPTIONS] CONTAINER [SIGNAL]\n\n\nPOSITIONALS:\n  CONTAINER TEXT REQUIRED     The container ID\n  SIGNAL INT [15]             Signal to send\n\nOPTIONS:\n  -h,     --help              Print this help message and exit\n";

fn global_option_takes_value(value: &OsStr) -> bool {
    matches!(
        value.as_encoded_bytes(),
        b"--root" | b"--cgroup-manager" | b"--log-level" | b"--log-format" | b"--log"
    )
}

fn exec_option_takes_value(value: &OsStr) -> bool {
    matches!(
        value.as_encoded_bytes(),
        b"-u"
            | b"--user"
            | b"--cwd"
            | b"--console-socket"
            | b"--preserve-fds"
            | b"-p"
            | b"--process"
    )
}

fn exec_option_has_attached_value(value: &OsStr) -> bool {
    let bytes = value.as_encoded_bytes();
    [
        b"--user=".as_slice(),
        b"--cwd=",
        b"--console-socket=",
        b"--preserve-fds=",
        b"--process=",
    ]
    .iter()
    .any(|prefix| bytes.starts_with(prefix))
        || [b"-u".as_slice(), b"-p"]
            .iter()
            .any(|prefix| bytes.starts_with(prefix) && bytes.len() > prefix.len())
}

fn exec_flag_has_attached_value(value: &OsStr) -> bool {
    let bytes = value.as_encoded_bytes();
    bytes.starts_with(b"--tty=") || bytes.starts_with(b"--no-new-privs=")
}

fn is_exec_variadic_option(value: &OsStr) -> bool {
    matches!(
        value.as_encoded_bytes(),
        b"-e" | b"--env" | b"-c" | b"--cap"
    )
}

fn is_exec_flag(value: &OsStr) -> bool {
    matches!(
        value.as_encoded_bytes(),
        b"-t" | b"--tty" | b"--no-new-privs"
    )
}

#[derive(Debug, Args)]
pub struct GlobalOptions {
    #[arg(long, default_value_os_t = default_root_path())]
    pub root: PathBuf,

    #[arg(long, value_enum, default_value_t = CgroupManager::Disabled)]
    pub cgroup_manager: CgroupManager,

    #[arg(
        long,
        value_enum,
        env = "LINYAPS_BOX_LOG_LEVEL",
        default_value_t = LogLevel::Warn,
        ignore_case = true
    )]
    pub log_level: LogLevel,

    #[arg(long, value_enum, default_value_t = LogFormat::Text, ignore_case = true)]
    pub log_format: LogFormat,

    #[arg(long, value_parser = validate_log_sink)]
    pub log: Vec<String>,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true,
        value_parser = cli_bool,
        overrides_with = "cee_syslog"
    )]
    pub cee_syslog: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CgroupManager {
    #[value(alias = "2")]
    Cgroupfs,
    #[value(alias = "1")]
    Systemd,
    #[value(alias = "0")]
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum LogLevel {
    #[value(alias = "0")]
    Fatal,
    #[value(alias = "1")]
    Error,
    #[value(alias = "2")]
    Warn,
    #[value(alias = "3")]
    Info,
    #[value(alias = "4")]
    Debug,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Fatal => "fatal",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum LogFormat {
    #[value(alias = "0")]
    Text,
    #[value(alias = "1")]
    Json,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "List known containers")]
    List(ListOptions),
    #[command(about = "Create and immediately start a container")]
    Run(RunOptions),
    #[command(about = "Exec a command in a running container")]
    Exec(ExecOptions),
    #[command(about = "Send the specified signal to the container init process")]
    Kill(KillOptions),
}

#[derive(Debug, Args)]
pub struct ListOptions {
    #[arg(short = 'f', long = "format", value_enum, default_value_t = ListFormat::Table)]
    pub format: ListFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ListFormat {
    #[value(alias = "0")]
    Table,
    #[value(alias = "1")]
    Json,
}

#[derive(Debug, Args)]
pub struct RunOptions {
    #[arg(value_name = "CONTAINER")]
    pub container: String,

    #[arg(short = 'b', long = "bundle", default_value = ".", value_parser = existing_directory)]
    pub bundle: PathBuf,

    #[arg(
        short = 'f',
        long = "config",
        default_value = "config.json",
        value_name = "FILE"
    )]
    pub config: PathBuf,

    #[arg(long = "preserve-fds", default_value_t = 0, allow_hyphen_values = true, value_parser = clap::value_parser!(i32).range(0..))]
    pub preserve_fds: i32,

    #[arg(long = "console-socket", value_name = "SOCKET", value_parser = existing_socket)]
    pub console_socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(trailing_var_arg = true)]
pub struct ExecOptions {
    #[arg(short = 'u', long = "user", value_name = "UID[:GID]")]
    pub user: Option<UserSpec>,

    #[arg(long, value_name = "PATH")]
    pub cwd: Option<PathBuf>,

    #[arg(short = 'e', long = "env", value_name = "ENV", num_args = 1.., value_parser = valid_environment)]
    pub env: Vec<String>,

    #[arg(long = "console-socket", value_name = "SOCKET", value_parser = existing_socket)]
    pub console_socket: Option<PathBuf>,

    #[arg(
        short = 't',
        long = "tty",
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true,
        value_parser = cli_bool,
        overrides_with = "tty"
    )]
    pub tty: bool,

    #[arg(long = "preserve-fds", default_value_t = 0, allow_hyphen_values = true, value_parser = clap::value_parser!(i32).range(0..))]
    pub preserve_fds: i32,

    #[arg(short = 'c', long = "cap", value_name = "CAP", num_args = 1.., value_parser = valid_capability)]
    pub capabilities: Vec<String>,

    #[arg(
        long = "no-new-privs",
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true,
        value_parser = cli_bool,
        overrides_with = "no_new_privileges"
    )]
    pub no_new_privileges: bool,

    #[arg(short = 'p', long = "process", value_name = "FILE", value_parser = existing_file)]
    pub process: Option<PathBuf>,

    #[arg(value_name = "CONTAINER")]
    pub container: String,

    #[arg(
        value_name = "COMMAND",
        required_unless_present = "process",
        allow_hyphen_values = true
    )]
    pub command: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserSpec {
    pub uid: u32,
    pub gid: u32,
}

impl FromStr for UserSpec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (uid, gid) = value
            .split_once(':')
            .map_or((value, value), |(uid, gid)| (uid, gid));
        let uid = parse_user_id(uid, "UID")?;
        let gid = parse_user_id(gid, "GID")?;
        Ok(Self { uid, gid })
    }
}

fn parse_user_id(value: &str, kind: &str) -> Result<u32, String> {
    let separator = if kind == "UID" { ":" } else { ": " };
    if value.is_empty() || !value.as_bytes()[0].is_ascii_digit() {
        return Err(format!("invalid {kind}{separator}Invalid argument"));
    }
    let digit_count = value.bytes().take_while(u8::is_ascii_digit).count();
    let parsed = value[..digit_count]
        .parse::<u32>()
        .map_err(|_| format!("invalid {kind}{separator}Numerical result out of range"))?;
    if digit_count != value.len() {
        return Err(format!("invalid {kind}{separator}Success"));
    }
    Ok(parsed)
}

#[derive(Debug, Args)]
pub struct KillOptions {
    #[arg(value_name = "CONTAINER")]
    pub container: String,

    #[arg(
        value_name = "SIGNAL",
        default_value = "15",
        allow_hyphen_values = true,
        value_parser = valid_signal
    )]
    pub signal: String,
}

pub fn default_root_path() -> PathBuf {
    env::var_os("XDG_RUNTIME_DIR")
        .map_or_else(
            || PathBuf::from("/run/user").join(nix::unistd::geteuid().as_raw().to_string()),
            PathBuf::from,
        )
        .join("linglong")
        .join("box")
}

pub fn version_text() -> &'static str {
    Box::leak(format!("version {LINYAPS_BOX_VERSION}\nspec {OCI_VERSION}").into_boxed_str())
}

fn existing_directory(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_dir() => Ok(path),
        Ok(_) => Err(format!("Directory is actually a file: {}", path.display())),
        Err(_) => Err(format!("Directory does not exist: {}", path.display())),
    }
}

fn existing_file(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if value.is_empty() {
        return Err("File name is missing.".to_string());
    }
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_dir() => {
            Err(format!("File is actually a directory: {}", path.display()))
        }
        Ok(_) => Ok(path),
        Err(_) => Err(format!("File does not exist: {}", path.display())),
    }
}

fn existing_socket(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| "console-socket must be an existing socket file".to_string())?;
    if metadata.file_type().is_socket() {
        Ok(path)
    } else {
        Err("console-socket must be an existing socket file".to_string())
    }
}

fn valid_environment(value: &str) -> Result<String, String> {
    let Some((key, _)) = value.split_once('=') else {
        return Err(format!("invalid env: {value}"));
    };
    if key.is_empty() || key.as_bytes().contains(&0) {
        return Err(format!("invalid env: {value}"));
    }
    Ok(value.to_string())
}

fn valid_capability(value: &str) -> Result<String, String> {
    capability::parse_index(value)
        .map(|_| value.to_string())
        .ok_or_else(|| format!("invalid capability: {value}"))
}

fn valid_signal(value: &str) -> Result<String, String> {
    Signal::try_from(value)
        .map(|signal| signal.into_raw().to_string())
        .map_err(|error| error.to_string())
}

fn validate_log_sink(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("empty log destination".to_string());
    }
    if value == "stderr" || !value.contains(':') {
        return Ok(value.to_string());
    }
    let (scheme, destination) = value.split_once(':').expect("checked above");
    if destination.is_empty() {
        return Err(format!("empty {scheme} destination"));
    }
    if matches!(scheme, "file" | "syslog" | "journald") {
        Ok(value.to_string())
    } else {
        Err(format!("unknown log destination: {value}"))
    }
}

fn cli_bool(value: &str) -> Result<bool, String> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!("invalid boolean value: {value}")),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn parses_user_with_implicit_group() {
        assert_eq!(
            "1000".parse::<UserSpec>().unwrap(),
            UserSpec {
                uid: 1000,
                gid: 1000
            }
        );
        assert!("+1000".parse::<UserSpec>().is_err());
        assert!("1000:+1000".parse::<UserSpec>().is_err());
    }

    #[test]
    fn validates_capabilities_without_rewriting_names() {
        let parsed = Cli::try_parse_from([
            "ll-box",
            "exec",
            "--cap",
            "cap_net_bind_service",
            "--",
            "demo",
            "true",
        ])
        .unwrap();
        let Command::Exec(options) = parsed.command else {
            panic!("unexpected command");
        };
        assert_eq!(options.capabilities, ["cap_net_bind_service"]);

        let parsed =
            Cli::try_parse_from(["ll-box", "exec", "--cap", "0x1", "--", "demo", "true"]).unwrap();
        let Command::Exec(options) = parsed.command else {
            panic!("unexpected command");
        };
        assert_eq!(options.capabilities, ["0x1"]);

        let no_prefix = Cli::try_parse_from([
            "ll-box",
            "exec",
            "--cap",
            "net_bind_service",
            "demo",
            "true",
        ])
        .unwrap_err()
        .to_string();
        assert!(no_prefix.contains("invalid capability"));

        let error = Cli::try_parse_from([
            "ll-box",
            "exec",
            "--cap",
            "CAP_DOES_NOT_EXIST",
            "demo",
            "true",
        ])
        .unwrap_err()
        .to_string();
        assert!(error.contains("invalid capability"));
    }

    #[test]
    fn accepts_signal_names() {
        let parsed = Cli::try_parse_from(["ll-box", "kill", "demo", "SIGTERM"]).unwrap();
        let Command::Kill(options) = parsed.command else {
            panic!("unexpected command");
        };
        assert_eq!(options.signal, "15");
    }

    #[test]
    fn accepts_signal_zero_and_realtime_numbers() {
        for signal in ["0".to_string(), libc::SIGRTMAX().to_string()] {
            let parsed = Cli::try_parse_from(["ll-box", "kill", "demo", signal.as_str()]).unwrap();
            let Command::Kill(options) = parsed.command else {
                panic!("unexpected command");
            };
            assert_eq!(options.signal, signal);
        }
    }

    #[test]
    fn rejects_lowercase_and_out_of_range_signals() {
        let lowercase = Cli::try_parse_from(["ll-box", "kill", "demo", "sigterm"])
            .unwrap_err()
            .to_string();
        assert!(lowercase.contains("invalid signal: sigterm"));

        let out_of_range = (libc::SIGRTMAX() + 1).to_string();
        let error = Cli::try_parse_from(["ll-box", "kill", "demo", out_of_range.as_str()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("signal number out of range"));
    }

    #[test]
    fn rejects_environment_without_separator() {
        let error =
            Cli::try_parse_from(["ll-box", "exec", "-e", "INVALID", "demo", "true"]).unwrap_err();
        assert!(error.to_string().contains("invalid env"));
    }

    #[test]
    fn accepts_frozen_numeric_enum_aliases_and_flag_values() {
        let parsed = Cli::try_parse_from([
            "ll-box",
            "--cgroup-manager",
            "0",
            "--log-level",
            "4",
            "--log-format",
            "1",
            "--cee-syslog=true",
            "list",
            "--format",
            "1",
        ])
        .unwrap();
        assert_eq!(parsed.global.cgroup_manager, CgroupManager::Disabled);
        assert_eq!(parsed.global.log_level, LogLevel::Debug);
        assert_eq!(parsed.global.log_format, LogFormat::Json);
        assert!(parsed.global.cee_syslog);
        let Command::List(options) = parsed.command else {
            panic!("unexpected command");
        };
        assert_eq!(options.format, ListFormat::Json);
    }

    #[test]
    fn treats_options_after_exec_container_as_command_arguments() {
        let parsed = try_parse_from(["ll-box", "exec", "demo", "--cap", "CAP_CHOWN"]).unwrap();
        let Command::Exec(options) = parsed.command else {
            panic!("unexpected command");
        };
        assert!(options.capabilities.is_empty());
        assert_eq!(options.command, ["--cap", "CAP_CHOWN"]);
    }

    #[test]
    fn variadic_exec_options_reserve_only_the_required_container() {
        let arguments = ["ll-box", "exec", "--cwd", "/", "-e", "A=B", "demo"];
        let error = try_parse_from(arguments).unwrap_err();
        assert_eq!(
            parse_error_text(
                &arguments
                    .into_iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>(),
                &error
            ),
            "At least one of COMMAND or --process must be provided\nRun with --help for more information.\n"
        );

        let arguments = ["ll-box", "exec", "--cwd", "/", "--env=A=B", "demo", "echo"];
        let error = try_parse_from(arguments).unwrap_err();
        assert_eq!(
            parse_error_text(
                &arguments
                    .into_iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>(),
                &error
            ),
            "--env: invalid env: demo\nRun with --help for more information.\n"
        );
    }

    #[test]
    fn later_exec_option_ends_variadic_values_before_positionals() {
        let parsed = try_parse_from([
            "ll-box", "exec", "-e", "A=B", "--cwd", "/tmp", "demo", "echo",
        ])
        .unwrap();
        let Command::Exec(options) = parsed.command else {
            panic!("unexpected command");
        };
        assert_eq!(options.env, ["A=B"]);
        assert_eq!(options.cwd.as_deref(), Some(std::path::Path::new("/tmp")));
        assert_eq!(options.container, "demo");
        assert_eq!(options.command, ["echo"]);
    }

    #[test]
    fn unknown_global_without_subcommand_reports_required_subcommand() {
        let arguments = [OsString::from("ll-box"), OsString::from("--bad-option")];
        let error = try_parse_from(arguments.clone()).unwrap_err();
        assert_eq!(
            parse_error_text(&arguments, &error),
            "A subcommand is required\nRun with --help for more information.\n"
        );
    }
}
