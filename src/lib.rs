mod runner;
mod targets;

use std::{
    env::{self, args_os, current_exe},
    ffi::{OsStr, OsString},
    process::Command,
};

use clap::Parser;

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
        /// Arguments for `cargo run`. Check `cargo help run` for details.
        #[clap(trailing_var_arg = true, allow_hyphen_values = true)]
        cargo_run_args: Vec<OsString>,
    },
    #[command(name = "xtest", aliases = ["test", "t"])]
    XTest {
        /// Arguments for `cargo test`. Check `cargo help test` for details.
        #[clap(trailing_var_arg = true, allow_hyphen_values = true)]
        cargo_test_args: Vec<OsString>,
    },
}

fn exec_cargo(
    subcommand: &str,
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    envs: impl IntoIterator<Item = (impl AsRef<OsStr>, impl AsRef<OsStr>)>,
) -> anyhow::Error {
    // https://github.com/rust-cross/cargo-zigbuild/blob/75aca8d5f0230a4cf3f116a0b6ab24c7b6124926/src/bin/cargo-zigbuild.rs#L92
    let mut cargo_command = Command::new(env::var_os("CARGO").unwrap_or("cargo".into()));
    cargo_command
        .arg(subcommand)
        .args(args)
        .env_remove("CARGO")
        .envs(envs);

    #[cfg(unix)]
    return std::os::unix::process::CommandExt::exec(&mut cargo_command).into();

    #[cfg(not(unix))]
    match cargo_command.status() {
        Err(err) => err.into(),
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
    }
}

pub fn cli_main() -> anyhow::Result<()> {
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

    const RUNNER_MODE_SUBCOMMAND: &str = "cargo-xrun-runner-mode";

    let mut args = args_os();
    if let Some(_program_name) = args.next()
        && let Some(subcommand) = args.next()
        && subcommand == RUNNER_MODE_SUBCOMMAND
    {
        let target = args.next().expect("target argument missing");
        let target = target.to_str().expect("invalid target string");
        let exe = args.next().expect("executable argument missing");
        return runner::runner(target, &exe);
    }

    let opt = Opt::parse();
    let (cargo_subcommand, args) = match opt {
        Opt::XRun { cargo_run_args } => ("run", cargo_run_args),
        Opt::XTest { cargo_test_args } => ("test", cargo_test_args),
    };

    let runner_envs = targets::TARGETS.iter().map(|target| {
        let mut runner_value = current_exe_path.clone();
        runner_value.push(" ");
        runner_value.push(RUNNER_MODE_SUBCOMMAND);
        runner_value.push(" ");
        runner_value.push(target);
        (
            OsString::from(format!(
                "CARGO_TARGET_{}_RUNNER",
                target.to_uppercase().replace('-', "_"),
            )),
            runner_value,
        )
    });

    return Err(exec_cargo(cargo_subcommand, args, runner_envs));
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

#[test]
fn test_contains_space() {
    assert!(contains_space("hello world"));
    assert!(!contains_space("helloworld"));
}
