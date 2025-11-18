mod config;
mod fs_server;

use std::{
    env::{self, temp_dir},
    ffi::{OsStr, OsString},
    fmt::Display,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::Context as _;
use fs_server::serve_webdav;
use inquire::{InquireError, Select, Text, error::InquireResult};
use relative_path::RelativePathBuf;
use tempfile::{NamedTempFile, TempPath};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
    try_join,
};

fn prompt_for_host_selection(
    existing_hosts: &[config::Host],
    target: &str,
) -> InquireResult<config::UserResponse> {
    if existing_hosts.is_empty() {
        // No hosts configured yet
        println!("No remote hosts configured for {} yet.", target);
        let destination = Text::new("Enter SSH destination:")
            .with_placeholder("user@server.com")
            .prompt()?;
        return Ok(config::UserResponse::AddNewHost { destination });
    }

    // Build options: existing hosts + "Add new host"
    enum SelectOption {
        ExistingHost { host: config::Host, index: usize },
        AddNewHost,
    }
    impl Display for SelectOption {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                SelectOption::ExistingHost { host, .. } => {
                    write!(
                        f,
                        "{} (targets: {})",
                        host.destination,
                        host.targets.join(", ")
                    )
                }
                SelectOption::AddNewHost => write!(f, "Add a new remote host"),
            }
        }
    }
    let mut options: Vec<SelectOption> = existing_hosts
        .iter()
        .enumerate()
        .map(|(index, host)| SelectOption::ExistingHost {
            host: host.clone(),
            index,
        })
        .collect();
    options.push(SelectOption::AddNewHost);

    let selection = Select::new(&format!("Select host for target '{}':", target), options)
        .without_filtering()
        .prompt()?;

    // Check if user selected "Add new host"
    match selection {
        SelectOption::AddNewHost => {
            let destination = Text::new("Enter SSH destination:")
                .with_placeholder("e.g., user@server.com")
                .prompt()?;
            Ok(config::UserResponse::AddNewHost { destination })
        }
        SelectOption::ExistingHost { index, .. } => {
            Ok(config::UserResponse::AddTargetToHost { host_index: index })
        }
    }
}

fn get_ssh_destination(target: &str) -> anyhow::Result<String> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
        .join("cargo-xrun");
    std::fs::create_dir_all(&config_dir)?;

    let config_path = config_dir.join("config.toml");

    // Create or open config file
    let mut toml_config_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(&config_path)
        .with_context(|| format!("Failed to open or create config file at {:?}", &config_path))?;

    let mut toml_config_str = String::new();
    toml_config_file
        .read_to_string(&mut toml_config_str)
        .context(format!("Failed to read config file at {:?}", &config_path))?;

    let host = config::upsert_with(&mut toml_config_str, target, |existing_hosts| {
        match prompt_for_host_selection(existing_hosts, target) {
            Ok(user_response) => Ok(user_response),
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
                std::process::exit(0)
            }
            Err(err) => Err(anyhow::Error::from(err).context("Failed during prompt")),
        }
    })?;

    toml_config_file.set_len(0)?;
    toml_config_file.seek(SeekFrom::Start(0))?;
    toml_config_file.write_all(toml_config_str.as_bytes())?;

    Ok(host.destination)
}

// fn to_path_in_dav(path: &Path) -> OsString {
//     let abs_path = path.
// }

const EXECUTABLE_DIR_PREFIX: &str = "/cargo_xrun_exedir";
const MANIFEST_DIR_PREFIX: &str = "/cargo_xrun_manifest";

pub async fn runner(target: &str, exe: &OsStr) -> anyhow::Result<()> {
    let ssh_destination = get_ssh_destination(target)?;

    let exe = Path::new(exe);
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .context("CARGO_MANIFEST_DIR not set by cargo")?;

    let cwd_relative_to_mainfest = env::current_dir()
        .context("Failed to get current working directory")?
        .strip_prefix(&manifest_dir)
        .context("cwd of runner is not inside CARGO_MANIFEST_DIR")?;

    let exe_filename = exe
        .file_name()
        .with_context(|| format!("Executable path has no file name: {:?}", &exe))?;

    let exe_dir = exe
        .parent()
        .with_context(|| format!("Executable path has no parent directory: {:?}", &exe))?
        .to_path_buf();

    let (dav_port, server_fut) = serve_webdav(
        [
            (EXECUTABLE_DIR_PREFIX.to_string(), exe_dir),
            (MANIFEST_DIR_PREFIX.to_string(), manifest_dir),
        ]
        .into_iter(),
    )?;
    tokio::spawn(server_fut);

    let ssh_path = tempfile::Builder::new().make(|path: &Path| Ok(path.to_path_buf()))?;

    let mut master_daemon = Command::new("ssh")
        .args([
            "-N", // no command execution
            "-R",
            &format!("0:localhost:{}", dav_port,), // remote port forwarding
            "-o",
            "ExitOnForwardFailure=yes",
            "-M", // master mode
            "-S", // socket path
        ])
        .arg(ssh_path.as_file().as_os_str())
        .arg(ssh_destination)
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn ssh master daemon")?;

    let remote_port: Option<u16> = {
        let mut master_daemon_stderr = BufReader::new(master_daemon.stderr.take().unwrap());
        let mut line_buf = String::new();
        let mut stderr = tokio::io::stderr();
        const ALLOCATED_PORT_PREFIX: &str = "Allocated port ";
        loop {
            let n = master_daemon_stderr.read_line(&mut line_buf).await?;
            if n == 0 {
                break None;
            }
            let line = &line_buf[..n];
            if line.starts_with(ALLOCATED_PORT_PREFIX) {
                let port_str = line[ALLOCATED_PORT_PREFIX.len()..]
                    .split_whitespace()
                    .next()
                    .context("Failed to parse allocated port from ssh output")?;
                let port: u16 = port_str.parse().context("Failed to parse allocated port")?;
                break Some(port);
            }
            stderr.write_all(line.as_bytes()).await?;
            line_buf.clear();
        }
    };

    let Some(remote_port) = remote_port else {
        let status = master_daemon.wait().await?;
        if status.success() {
            anyhow::bail!("ssh exited without allocating a remote port");
        }
        std::process::exit(status.code().unwrap_or(1));
    };

    dbg!(remote_port);

    let status = master_daemon.wait().await?;
    std::process::exit(status.code().unwrap_or(1));
}
