#[cfg(feature = "decode")]
use wincode::SchemaRead;
#[cfg(feature = "encode")]
use wincode::SchemaWrite;

/// Execution context passed from host to remote binary.
#[cfg_attr(feature = "encode", derive(SchemaWrite))]
#[cfg_attr(feature = "decode", derive(SchemaRead))]
#[derive(Debug, Clone)]
pub struct ExecContext {
    pub cwd: String,
    pub envs: Vec<(String, String)>,
    pub bin_path: String,
    pub args: Vec<String>,
}

#[cfg(feature = "encode")]
pub mod encode {
    use super::ExecContext;
    use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};

    pub fn encode_context(ctx: &ExecContext) -> String {
        let bytes = wincode::serialize(ctx).unwrap();
        URL_SAFE_NO_PAD.encode(&bytes)
    }
}

#[cfg(feature = "decode")]
pub mod decode {
    use super::ExecContext;
    use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};

    pub fn decode_context(encoded: &str) -> Result<ExecContext, Box<dyn std::error::Error>> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
        let ctx = wincode::deserialize(&bytes)?;
        Ok(ctx)
    }
}

#[cfg(feature = "decode")]
pub fn main() -> std::process::ExitCode {
    use std::{env, process::Command};

    let args: Vec<String> = env::args().collect();
    let ctx = decode::decode_context(&args[1]).unwrap();

    env::set_current_dir(&ctx.cwd).unwrap();

    let mut cmd = Command::new(&ctx.bin_path);
    for (name, value) in &ctx.envs {
        cmd.env(name, value);
    }
    cmd.args(&ctx.args);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        panic!("cargo-xrun-remote: {}", err);
    }

    #[cfg(windows)]
    {
        use std::process::ExitCode;
        let status = match cmd.status() {
            Ok(s) => s,
            Err(err) if err.kind() == std::io::ErrorKind::FileTooLarge => {
                eprintln!(
                    r#"cargo-xrun-remote: The executable size exceeds the limit allowed by Windows WebDav Client.
To raise the limit, update FileSizeLimitInBytes in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient\Parameters,
and then restart the WebClient service."#
                );
                return ExitCode::from(1);
            }
            Err(err) => {
                eprintln!(
                    "cargo-xrun-remote: Failed to execute remote binary: {}",
                    err
                );
                return ExitCode::from(1);
            }
        };
        ExitCode::from(status.code().unwrap_or(1) as u8)
    }
}
