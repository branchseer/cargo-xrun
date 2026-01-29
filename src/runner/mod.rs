use std::{ffi::OsStr, process::ExitCode};

use anyhow::Context as _;
use cargo_xrun_remote::{ExecContext, encode::encode_context};
use tokio::process::Command;

pub async fn runner(
    target: &str,
    mut args: impl Iterator<Item = impl AsRef<OsStr>>,
    ssh_ctrl_path: &OsStr,
    ssh_remote_fs_server_port: u16,
    ssh_destination: &str,
) -> anyhow::Result<ExitCode> {
    let to_remote_path = |path: &OsStr| -> anyhow::Result<String> {
        let path = std::path::absolute(path)?
            .into_os_string()
            .into_string()
            .ok()
            .context("Path is not valid UTF-8")?;
        if path.contains(char::is_whitespace) {
            anyhow::bail!(
                "Path contains whitespace, which is not supported for remote execution: {}",
                path
            );
        }
        let path = path.replace("/", "\\");
        Ok(format!(
            "\\\\localhost@{}\\DavWWWRoot\\fs\\{}",
            ssh_remote_fs_server_port,
            path.trim_start_matches('\\')
        ))
    };

    let mut envs = Vec::new();
    for (env_name, env_value) in std::env::vars_os() {
        let Ok(env_name) = env_name.into_string() else {
            continue;
        };
        if env_name == "CARGO"
            || env_name == "CARGO_MANIFEST_DIR"
            || env_name == "CARGO_MANIFEST_PATH"
            || env_name.starts_with("CARGO_BIN_EXE_")
        {
            let env_value = to_remote_path(&env_value)?;
            envs.push((env_name, env_value));
        } else if env_name.starts_with("CARGO_") {
            let env_value = env_value
                .into_string()
                .ok()
                .context("Env value is not valid UTF-8")?;
            envs.push((env_name, env_value));
        }
    }

    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let remote_cwd = to_remote_path(cwd.as_os_str())?;

    let exe = args.next().context("executable argument missing")?;
    let bin_path = to_remote_path(exe.as_ref())?;

    let args_vec: Vec<String> = args
        .map(|arg| {
            arg.as_ref()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Arg is not valid UTF-8"))
                .map(String::from)
        })
        .collect::<Result<_, _>>()?;

    let webdav_path = format!(
        "\\\\localhost@{}\\DavWWWRoot",
        ssh_remote_fs_server_port
    );

    let ctx = ExecContext {
        cwd: remote_cwd,
        envs,
        bin_path,
        args: args_vec,
        webdav_path,
    };
    let encoded = encode_context(&ctx);

    let remote_bin = get_remote_bin_path(target, ssh_remote_fs_server_port)?;

    let mut command = Command::new("ssh");
    command
        .arg("-S")
        .arg(ssh_ctrl_path)
        .args(["-o", "PreferredAuthentications=none"])
        .arg(ssh_destination)
        .arg(&remote_bin)
        .arg(&encoded);

    let status = command.status().await?;
    Ok((status.code().unwrap_or(1) as u8).into())
}

fn get_remote_bin_path(target: &str, port: u16) -> anyhow::Result<String> {
    let bin_name = if target.contains("windows") {
        "cargo-xrun-remote-i686-pc-windows-gnullvm.exe"
    } else if target.contains("x86_64") && target.contains("linux") {
        "cargo-xrun-remote-x86_64-unknown-linux-musl"
    } else if target.contains("aarch64") && target.contains("linux") {
        "cargo-xrun-remote-aarch64-unknown-linux-musl"
    } else {
        anyhow::bail!("Unsupported target: {}", target)
    };
    Ok(format!(
        "\\\\localhost@{}\\DavWWWRoot\\remote-bin\\{}",
        port, bin_name
    ))
}
