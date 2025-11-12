mod config;

use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};

use anyhow::Context as _;
use inquire::{Select, Text};

fn prompt_for_host_selection(
    existing_hosts: &[config::Host],
    target: &str,
) -> anyhow::Result<config::UserResponse> {
    if existing_hosts.is_empty() {
        // No hosts configured yet
        println!("No remote hosts configured for {} yet.", target);
        let destination = Text::new("Enter SSH destination:")
            .with_placeholder("e.g., user@server.com")
            .prompt()?;
        return Ok(config::UserResponse::AddNewHost { destination });
    }

    // Build options: existing hosts + "Add new host"
    let mut options: Vec<String> = existing_hosts
        .iter()
        .map(|host| {
            format!(
                "{} (targets: {})",
                host.destination,
                host.targets.join(", ")
            )
        })
        .collect();
    options.push("Add a new remote host".to_string());

    let selection = Select::new(
        &format!("Select host for target '{}':", target),
        options.clone(),
    )
    .prompt()?;

    // Check if user selected "Add new host"
    if selection == "Add a new remote host" {
        let destination = Text::new("Enter SSH destination:")
            .with_placeholder("e.g., user@server.com")
            .prompt()?;
        Ok(config::UserResponse::AddNewHost { destination })
    } else {
        // Find the index of the selected host
        let host_index = existing_hosts
            .iter()
            .position(|host| {
                format!(
                    "{} (targets: {})",
                    host.destination,
                    host.targets.join(", ")
                ) == selection
            })
            .expect("Selected host not found");

        Ok(config::UserResponse::AddTargetToHost { host_index })
    }
}

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

    let host = config::upsert_with(&mut toml_config_str, target, |existing_hosts| {
        prompt_for_host_selection(existing_hosts, target)
            .expect("Failed to get user input for host selection")
    })?;

    toml_config_file.set_len(0)?;
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
