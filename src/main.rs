use std::process::ExitCode;

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    cargo_xrun::cli_main().await
}
