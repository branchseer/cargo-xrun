mod config;

use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};

use anyhow::Context as _;

pub fn runner(target: &str, exe: &OsStr) -> anyhow::Result<()> {
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

    let host = config::upsert_with(&mut toml_config_str, target, |existing_hosts| todo!())?;

    toml_config_file.set_len(0);
    toml_config_file.seek(SeekFrom::Start(0))?;
    toml_config_file.write_all(toml_config_str.as_bytes())?;
    drop(toml_config_file);

    for (name, value) in std::env::vars_os() {
        dbg!((name, value));
    }
    println!(
        "Running {:?} for target {} wit host {}",
        exe, target, host.destination,
    );
    Ok(())
}
