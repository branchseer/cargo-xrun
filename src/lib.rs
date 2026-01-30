mod config;
mod embedded_binaries;
mod fs_server;
mod runner;
mod ssh_master;

use anyhow::Context;
use ssh_master::SshMaster;
use std::{
    env::{self, args_os, current_exe},
    ffi::{OsStr, OsString},
    process::{ExitCode, ExitStatus},
};
use tokio::process::Command;

use clap::Parser;
use which::which;

/// Captures trailing arguments while preserving `--` separator.
///
/// Clap normally consumes `--` as a delimiter without including it in captured args.
/// To preserve `--` when present, we capture args before and after `--` separately,
/// then combine them with `--` inserted if the latter is non-empty.
#[derive(Debug, Parser)]
struct TrailingArgs {
    /// Arguments before `--`
    #[clap(allow_hyphen_values = true)]
    before_separator: Vec<OsString>,

    /// Arguments after `--` (hidden since this is an implementation detail)
    #[clap(last = true, hide = true)]
    after_separator: Vec<OsString>,
}

impl TrailingArgs {
    fn into_args(self) -> Vec<OsString> {
        let mut args = self.before_separator;
        if !self.after_separator.is_empty() {
            args.push("--".into());
            args.extend(self.after_separator);
        }
        args
    }
}

#[derive(Debug, Parser)]
#[command(
    version,
    name = "cargo-xrun",
    display_order = 1,
    styles = clap_cargo::style::CLAP_STYLING
)]
enum Opt {
    /// Run a binary or example of the local package remotely
    #[command(name = "xrun", aliases = ["run", "r"])]
    XRun {
        /// Build and run for the target triple
        #[clap(name = "target", long, required = true)]
        triple: String,

        ///Command for building, defaulting to 'cargo'. Possible values include: 'cargo', 'cargo-zigbuild', and 'cargo-xwin'.
        #[clap(name = "builder", long)]
        builder: Option<String>,

        #[clap(flatten)]
        trailing_args: TrailingArgs,
    },
    #[command(name = "xtest", aliases = ["test", "t"])]
    XTest {
        /// Build and run for the target triple
        #[clap(name = "target", long, required = true)]
        triple: String,

        ///Command for building, defaulting to 'cargo'. Possible values include: 'cargo', 'cargo-zigbuild', and 'cargo-xwin'.
        #[clap(name = "builder", long)]
        builder: Option<String>,

        #[clap(flatten)]
        trailing_args: TrailingArgs,
    },
}

async fn exec_cargo(
    builder: Option<String>,
    subcommand: &str,
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    envs: impl IntoIterator<Item = (impl AsRef<OsStr>, impl AsRef<OsStr>)>,
) -> anyhow::Result<ExitStatus> {
    let builder = builder.unwrap_or_else(|| env::var("CARGO").unwrap_or("cargo".into()));
    let cargo_path =
        which(&builder).with_context(|| format!("Failed to find executable {}", builder))?;

    // https://github.com/rust-cross/cargo-zigbuild/blob/75aca8d5f0230a4cf3f116a0b6ab24c7b6124926/src/bin/cargo-zigbuild.rs#L92
    let mut cargo_command = Command::new(cargo_path);
    cargo_command
        .arg(subcommand)
        .args(args)
        .env_remove("CARGO")
        .envs(envs);

    Ok(cargo_command.status().await?)
}

pub async fn cli_main() -> anyhow::Result<ExitCode> {
    const RUNNER_MODE_SUBCOMMAND: &str = "cargo-xrun-runner-mode";
    const SSH_CTRL_PATH_ENV_NAME: &str = "CARGOXRUN_SSH_CTRL_PATH";
    const SSH_REMOTE_FS_SERVER_PORT: &str = "CARGOXRUN_SSH_REMOTE_FS_SERVER_PORT";
    const SSH_DESTINATION_ENV_NAME: &str = "CARGOXRUN_SSH_DESTINATION";

    let mut args = args_os();
    if let Some(_program_name) = args.next()
        && let Some(subcommand) = args.next()
        && subcommand == RUNNER_MODE_SUBCOMMAND
    {
        let target = args.next().expect("target argument missing");
        let target = target.to_str().expect("invalid target string");

        let ssh_ctrl_path = env::var_os(SSH_CTRL_PATH_ENV_NAME)
            .expect("CARGOXRUN_SSH_CTRL_PATH environment variable missing");
        let ssh_remote_fs_server_port: u16 = env::var_os(SSH_REMOTE_FS_SERVER_PORT)
            .expect("CARGOXRUN_SSH_REMOTE_FS_SERVER_PORT environment variable missing")
            .to_str()
            .and_then(|s| s.parse().ok())
            .expect("invalid CARGOXRUN_SSH_REMOTE_FS_SERVER_PORT value");
        let ssh_destination = env::var_os(SSH_DESTINATION_ENV_NAME)
            .expect("CARGOXRUN_SSH_DESTINATION environment variable missing")
            .into_string()
            .expect("invalid CARGOXRUN_SSH_DESTINATION value");
        return runner::runner(
            target,
            args,
            &ssh_ctrl_path,
            ssh_remote_fs_server_port,
            &ssh_destination,
        )
        .await;
    }

    let current_exe_path = current_exe()?.into_os_string();
    if contains_space(&current_exe_path) {
        eprintln!(
            "The path to cargo-xrun contains whitespace: {:?}\n\
            This causes issues when used as a cargo runner.\n\
            Please move cargo-xrun to a path without whitespace and retry.\n\
            See <https://doc.rust-lang.org/cargo/reference/config.html#executable-paths-with-arguments> for details.",
            &current_exe_path
        );
        std::process::exit(1);
    }

    let opt = Opt::parse();

    let (cargo_subcommand, triple, builder, args) = match opt {
        Opt::XRun {
            triple,
            builder,
            trailing_args,
        } => ("run", triple, builder, trailing_args.into_args()),
        Opt::XTest {
            triple,
            builder,
            trailing_args,
        } => ("test", triple, builder, trailing_args.into_args()),
    };

    dbg!(&args);

    let args = [OsStr::new("--target"), OsStr::new(&triple)]
        .into_iter()
        .chain(args.iter().map(|arg| arg.as_os_str()));

    let runner_env_name = OsString::from(format!(
        "CARGO_TARGET_{}_RUNNER",
        triple.to_uppercase().replace('-', "_"),
    ));

    let runner_env_value = {
        let mut runner_command = current_exe_path.clone();
        runner_command.push(" ");
        runner_command.push(RUNNER_MODE_SUBCOMMAND);
        runner_command.push(" ");
        runner_command.push(&triple);
        runner_command.push(" ");
        // The executable path will be appended by cargo automatically
        runner_command
    };

    let ssh_destination = config::get_ssh_destination(&triple)?;

    let (dav_port, server_fut) = fs_server::serve_webdav().await?;
    tokio::spawn(server_fut);

    let ssh_master = SshMaster::start(&ssh_destination, dav_port).await?;

    let cargo_status = exec_cargo(
        builder,
        cargo_subcommand,
        args,
        [
            (runner_env_name.as_os_str(), runner_env_value.as_os_str()),
            (
                OsStr::new(SSH_CTRL_PATH_ENV_NAME),
                ssh_master.control_path().as_os_str(),
            ),
            (
                OsStr::new(SSH_CTRL_PATH_ENV_NAME),
                ssh_master.control_path().as_os_str(),
            ),
            (
                OsStr::new(SSH_REMOTE_FS_SERVER_PORT),
                OsStr::new(&ssh_master.remote_port().to_string()),
            ),
            (
                OsStr::new(SSH_DESTINATION_ENV_NAME),
                OsStr::new(&ssh_destination),
            ),
        ],
    )
    .await?;

    let _ = ssh_master.stop().await?;
    Ok((cargo_status.code().unwrap_or(1) as u8).into())
}

fn contains_space(s: impl AsRef<OsStr>) -> bool {
    #[cfg(unix)]
    return std::os::unix::ffi::OsStrExt::as_bytes(s.as_ref())
        .iter()
        .any(u8::is_ascii_whitespace);

    #[cfg(windows)]
    std::os::windows::ffi::OsStrExt::encode_wide(s.as_ref()).any(|ch| {
        char::from_u32(ch.into())
            .map(|c| c.is_whitespace())
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_space() {
        assert!(contains_space("hello world"));
        assert!(!contains_space("helloworld"));
    }

    #[test]
    fn test_xrun_without_separator() {
        let opt =
            Opt::parse_from(["cargo-xrun", "xrun", "--target", "aarch64-pc-windows-msvc", "foo"]);
        match opt {
            Opt::XRun { trailing_args, .. } => {
                assert_eq!(trailing_args.into_args(), vec!["foo"]);
            }
            _ => panic!("expected XRun"),
        }
    }

    #[test]
    fn test_xrun_with_separator() {
        let opt = Opt::parse_from([
            "cargo-xrun",
            "xrun",
            "--target",
            "aarch64-pc-windows-msvc",
            "--",
            "bar",
        ]);
        match opt {
            Opt::XRun { trailing_args, .. } => {
                assert_eq!(trailing_args.into_args(), vec!["--", "bar"]);
            }
            _ => panic!("expected XRun"),
        }
    }

    #[test]
    fn test_xrun_with_args_before_and_after_separator() {
        let opt = Opt::parse_from([
            "cargo-xrun",
            "xrun",
            "--target",
            "aarch64-pc-windows-msvc",
            "foo",
            "--",
            "bar",
        ]);
        match opt {
            Opt::XRun { trailing_args, .. } => {
                assert_eq!(trailing_args.into_args(), vec!["foo", "--", "bar"]);
            }
            _ => panic!("expected XRun"),
        }
    }

    #[test]
    fn test_xrun_no_trailing_args() {
        let opt = Opt::parse_from(["cargo-xrun", "xrun", "--target", "aarch64-pc-windows-msvc"]);
        match opt {
            Opt::XRun { trailing_args, .. } => {
                assert!(trailing_args.into_args().is_empty());
            }
            _ => panic!("expected XRun"),
        }
    }
}
