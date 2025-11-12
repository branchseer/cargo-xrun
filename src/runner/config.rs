use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_spanned::Spanned;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Host {
    pub destination: String,
    pub targets: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigFile {
    host: Vec<Host>,
}

/// Span-aware host for better error reporting
#[derive(Deserialize, Debug)]
struct SpannedHost {
    destination: Spanned<String>,
    targets: Spanned<Vec<Spanned<String>>>,
}

pub enum UserResponse {
    AddTargetToHost { host_index: usize },
    AddNewHost { destination: String },
}

/// Upsert a host configuration for the given target.
///
/// If a host already exists for the target, return it.
///
/// Otherwise,
/// 1. invoke the provided closure to get user input on whether to add the target to an existing host or create a new host,
/// 2. perform the edit on `toml_config_str`.
/// 3. return the newly created or updated host.
///
/// Returns an error if the TOML is malformed or has invalid schema.
pub fn upsert_with(
    toml_config_str: &mut String,
    target: &str,
    f: impl FnOnce(&[Host]) -> UserResponse,
) -> Result<Host> {
    use toml_edit::{value, Array, ArrayOfTables, DocumentMut, Item, Table};

    // Parse the TOML document with span information for better errors
    let mut doc = toml_config_str
        .parse::<DocumentMut>()
        .context("Failed to parse TOML configuration")?;

    // Get hosts array - handle both array of tables, empty array, and missing
    let hosts_array = match &doc["host"] {
        Item::ArrayOfTables(arr) => arr,
        Item::None => {
            // Non-existent - create empty array of tables
            doc["host"] = Item::ArrayOfTables(ArrayOfTables::new());
            doc["host"]
                .as_array_of_tables()
                .ok_or_else(|| anyhow!("Failed to create hosts array"))?
        }
        Item::Value(val) if val.is_array() && val.as_array().map_or(false, |a| a.is_empty()) => {
            // Empty regular array - convert to array of tables
            doc["host"] = Item::ArrayOfTables(ArrayOfTables::new());
            doc["host"]
                .as_array_of_tables()
                .ok_or_else(|| anyhow!("Failed to create hosts array"))?
        }
        _ => {
            return Err(anyhow!(
                "'host' field must be an array of tables, found: {}",
                doc["host"].type_name()
            ));
        }
    };

    // Build Host structs from toml_edit tables with proper error handling
    let mut hosts = Vec::new();
    for (idx, table) in hosts_array.iter().enumerate() {
        let destination_item = table.get("destination");
        let destination = destination_item
            .and_then(|item| item.as_str())
            .ok_or_else(|| {
                let type_name = destination_item.map(|i| i.type_name()).unwrap_or("none");
                anyhow!(
                    "host[{}].destination must be a string, found: {}",
                    idx,
                    type_name
                )
            })?
            .to_string();

        let targets_item = table.get("targets");
        let targets_array = targets_item
            .and_then(|item| item.as_array())
            .ok_or_else(|| {
                let type_name = targets_item.map(|i| i.type_name()).unwrap_or("none");
                anyhow!("host[{}].targets must be an array, found: {}", idx, type_name)
            })?;

        let mut targets = Vec::new();
        for (target_idx, target_value) in targets_array.iter().enumerate() {
            let target_str = target_value.as_str().ok_or_else(|| {
                anyhow!(
                    "host[{}].targets[{}] must be a string, found: {}",
                    idx,
                    target_idx,
                    target_value.type_name()
                )
            })?;
            targets.push(target_str.to_string());
        }

        hosts.push(Host {
            destination,
            targets,
        });
    }

    // Check if target already exists in any host
    for host in &hosts {
        if host.targets.contains(&target.to_string()) {
            return Ok(host.clone());
        }
    }

    // Target doesn't exist, get user's choice
    let user_response = f(&hosts);

    match user_response {
        UserResponse::AddTargetToHost { host_index } => {
            // Add target to existing host's targets array
            let hosts_array = doc["host"]
                .as_array_of_tables_mut()
                .ok_or_else(|| anyhow!("'host' is not an array of tables"))?;

            let host_table = hosts_array
                .get_mut(host_index)
                .expect("Invalid host_index");

            let targets_array = host_table["targets"]
                .as_array_mut()
                .ok_or_else(|| anyhow!("host[{}].targets is not an array", host_index))?;

            targets_array.push(target);

            // Update the string
            *toml_config_str = doc.to_string();

            // Return the updated host with new target added
            let mut updated_host = hosts[host_index].clone();
            updated_host.targets.push(target.to_string());
            Ok(updated_host)
        }
        UserResponse::AddNewHost { destination } => {
            // Create a new host entry
            let mut new_host_table = Table::new();
            new_host_table["destination"] = value(&destination);

            let mut targets_array = Array::new();
            targets_array.push(target);
            new_host_table["targets"] = value(targets_array);

            // Add to the hosts array
            let hosts_array = doc["host"]
                .as_array_of_tables_mut()
                .ok_or_else(|| anyhow!("'host' is not an array of tables"))?;

            hosts_array.push(new_host_table);

            // Update the string
            *toml_config_str = doc.to_string();

            // Return the new host
            Ok(Host {
                destination: destination.clone(),
                targets: vec![target.to_string()],
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upsert_with_existing_target() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "user@server1.com"
targets = ["aarch64-apple-darwin", "x86_64-apple-darwin"]

[[host]]
destination = "user@server2.com"
targets = ["x86_64-unknown-linux-gnu"]
"#,
        );

        // Target already exists, should return existing host without calling closure
        let result = upsert_with(&mut config_str, "x86_64-apple-darwin", |_hosts| {
            panic!("Closure should not be called when target already exists");
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@server1.com");
        assert_eq!(result.targets.len(), 2);
        assert!(result.targets.contains(&"x86_64-apple-darwin".to_string()));

        // Config string should be unchanged
        assert!(config_str.contains("user@server1.com"));
        assert!(config_str.contains("user@server2.com"));
    }

    #[test]
    fn test_upsert_with_add_target_to_existing_host() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "user@server1.com"
targets = ["aarch64-apple-darwin"]

[[host]]
destination = "user@server2.com"
targets = ["x86_64-unknown-linux-gnu"]
"#,
        );

        let original_config = config_str.clone();

        // Add new target to first host
        let result = upsert_with(&mut config_str, "x86_64-apple-darwin", |hosts| {
            assert_eq!(hosts.len(), 2);
            assert_eq!(hosts[0].destination, "user@server1.com");
            UserResponse::AddTargetToHost { host_index: 0 }
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@server1.com");
        assert_eq!(result.targets.len(), 2);
        assert!(result.targets.contains(&"aarch64-apple-darwin".to_string()));
        assert!(result.targets.contains(&"x86_64-apple-darwin".to_string()));

        // Verify the config string was updated
        assert_ne!(config_str, original_config);
        assert!(config_str.contains(r#"targets = ["aarch64-apple-darwin", "x86_64-apple-darwin"]"#));

        // Verify second host is unchanged
        assert!(config_str.contains("user@server2.com"));
        assert!(config_str.contains(r#"targets = ["x86_64-unknown-linux-gnu"]"#));
    }

    #[test]
    fn test_upsert_with_add_target_to_second_host() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "user@server1.com"
targets = ["aarch64-apple-darwin"]

[[host]]
destination = "user@server2.com"
targets = ["x86_64-unknown-linux-gnu"]
"#,
        );

        // Add new target to second host
        let result = upsert_with(&mut config_str, "aarch64-unknown-linux-gnu", |hosts| {
            assert_eq!(hosts.len(), 2);
            assert_eq!(hosts[1].destination, "user@server2.com");
            UserResponse::AddTargetToHost { host_index: 1 }
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@server2.com");
        assert_eq!(result.targets.len(), 2);
        assert!(result
            .targets
            .contains(&"x86_64-unknown-linux-gnu".to_string()));
        assert!(result
            .targets
            .contains(&"aarch64-unknown-linux-gnu".to_string()));

        // Verify the config string was updated correctly
        assert!(config_str.contains(
            r#"targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]"#
        ));
    }

    #[test]
    fn test_upsert_with_add_new_host() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "user@server1.com"
targets = ["aarch64-apple-darwin"]
"#,
        );

        // Add a completely new host
        let result = upsert_with(&mut config_str, "x86_64-unknown-linux-gnu", |hosts| {
            assert_eq!(hosts.len(), 1);
            UserResponse::AddNewHost {
                destination: "user@newserver.com".to_string(),
            }
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@newserver.com");
        assert_eq!(result.targets.len(), 1);
        assert!(result
            .targets
            .contains(&"x86_64-unknown-linux-gnu".to_string()));

        // Verify both hosts exist in the config
        assert!(config_str.contains("user@server1.com"));
        assert!(config_str.contains("user@newserver.com"));
        assert!(config_str.contains(r#"targets = ["x86_64-unknown-linux-gnu"]"#));

        // Verify it's a proper array of tables
        let doc: toml_edit::DocumentMut = config_str.parse().unwrap();
        let hosts = doc["host"].as_array_of_tables().unwrap();
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn test_upsert_with_preserves_comments() {
        let mut config_str = String::from(
            r#"# This is a comment about the first host
[[host]]
destination = "user@server1.com"
targets = ["aarch64-apple-darwin"]  # inline comment
"#,
        );

        // Add target to existing host - should preserve comments
        upsert_with(&mut config_str, "x86_64-apple-darwin", |_hosts| {
            UserResponse::AddTargetToHost { host_index: 0 }
        })
        .expect("test should succeed");

        // Verify exact structure with comments and spacing preserved
        let expected = r#"# This is a comment about the first host
[[host]]
destination = "user@server1.com"
targets = ["aarch64-apple-darwin", "x86_64-apple-darwin"]  # inline comment
"#;
        assert_eq!(config_str, expected);

        // Additional checks to ensure comments are preserved
        assert!(config_str.contains("# This is a comment about the first host"));
        assert!(config_str.contains("# inline comment"));
    }

    #[test]
    fn test_upsert_with_empty_config_add_first_host() {
        let mut config_str = String::from(
            r#"host = []
"#,
        );

        let result = upsert_with(&mut config_str, "aarch64-apple-darwin", |hosts| {
            assert_eq!(hosts.len(), 0);
            UserResponse::AddNewHost {
                destination: "user@firsthost.com".to_string(),
            }
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@firsthost.com");
        assert_eq!(result.targets, vec!["aarch64-apple-darwin".to_string()]);

        // Verify the new host was added
        assert!(config_str.contains("user@firsthost.com"));
        assert!(config_str.contains(r#"targets = ["aarch64-apple-darwin"]"#));
    }

    #[test]
    fn test_upsert_with_multiple_targets_in_result() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "user@server1.com"
targets = ["aarch64-apple-darwin", "x86_64-apple-darwin", "aarch64-unknown-linux-gnu"]
"#,
        );

        // Find existing host with multiple targets
        let result = upsert_with(&mut config_str, "aarch64-unknown-linux-gnu", |_hosts| {
            panic!("Should not be called");
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@server1.com");
        assert_eq!(result.targets.len(), 3);
    }

    #[test]
    fn test_upsert_with_preserves_formatting() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "user@server1.com"
targets = [
    "aarch64-apple-darwin",
]
"#,
        );

        // Add new host - multiline formatting should be preserved where possible
        upsert_with(&mut config_str, "x86_64-unknown-linux-gnu", |_hosts| {
            UserResponse::AddNewHost {
                destination: "user@server2.com".to_string(),
            }
        })
        .expect("test should succeed");

        // Should still have both hosts
        assert!(config_str.contains("user@server1.com"));
        assert!(config_str.contains("user@server2.com"));

        // Parse to verify structure
        let doc: toml_edit::DocumentMut = config_str.parse().unwrap();
        let hosts = doc["host"].as_array_of_tables().unwrap();
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn test_upsert_with_preserves_spacing_and_structure() {
        let mut config_str = String::from(
            r#"# Configuration file for cargo-xrun

[[host]]
destination = "user@server1.com"
targets = ["aarch64-apple-darwin"]

# Second host with different architecture
[[host]]
destination = "user@server2.com"
targets = ["x86_64-unknown-linux-gnu"]
"#,
        );

        // Add target to second host
        upsert_with(&mut config_str, "aarch64-unknown-linux-gnu", |_hosts| {
            UserResponse::AddTargetToHost { host_index: 1 }
        })
        .expect("test should succeed");

        // Verify structure is preserved with exact content check
        let expected = r#"# Configuration file for cargo-xrun

[[host]]
destination = "user@server1.com"
targets = ["aarch64-apple-darwin"]

# Second host with different architecture
[[host]]
destination = "user@server2.com"
targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
"#;
        assert_eq!(config_str, expected);

        // Verify all comments are intact
        assert!(config_str.contains("# Configuration file for cargo-xrun"));
        assert!(config_str.contains("# Second host with different architecture"));

        // Verify blank lines are preserved (check for double newlines)
        assert!(config_str.contains("\n\n[[host]]"));
    }

    #[test]
    fn test_exact_content_preservation() {
        // This test demonstrates that toml_edit preserves the exact structure
        let mut config_str = String::from(
            r#"# Top comment
[[host]]
destination = "server1"  # inline 1
targets = ["target1"]

# Middle comment
[[host]]
destination = "server2"  # inline 2
targets = ["target2"]  # inline 3
"#,
        );

        // Add target to first host
        upsert_with(&mut config_str, "new-target", |_hosts| {
            UserResponse::AddTargetToHost { host_index: 0 }
        })
        .expect("test should succeed");

        // Assert exact expected output
        assert_eq!(
            config_str,
            r#"# Top comment
[[host]]
destination = "server1"  # inline 1
targets = ["target1", "new-target"]

# Middle comment
[[host]]
destination = "server2"  # inline 2
targets = ["target2"]  # inline 3
"#
        );
    }

    // Error test cases

    #[test]
    fn test_error_malformed_toml() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "server1"
targets = ["target1"
"#, // Missing closing bracket
        );

        let result = upsert_with(&mut config_str, "new-target", |_hosts| {
            panic!("Should not be called");
        });

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to parse TOML"));
    }

    #[test]
    fn test_error_host_not_array_of_tables() {
        let mut config_str = String::from(
            r#"host = "not an array"
"#,
        );

        let result = upsert_with(&mut config_str, "target", |_hosts| {
            panic!("Should not be called");
        });

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("'host' field must be an array of tables"));
    }

    #[test]
    fn test_error_missing_destination_field() {
        let mut config_str = String::from(
            r#"[[host]]
targets = ["target1"]
"#, // Missing destination
        );

        let result = upsert_with(&mut config_str, "new-target", |_hosts| {
            panic!("Should not be called");
        });

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("host[0].destination must be a string"));
    }

    #[test]
    fn test_error_destination_wrong_type() {
        let mut config_str = String::from(
            r#"[[host]]
destination = 123
targets = ["target1"]
"#,
        );

        let result = upsert_with(&mut config_str, "new-target", |_hosts| {
            panic!("Should not be called");
        });

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("host[0].destination must be a string"));
        assert!(err_msg.contains("found: integer"));
    }

    #[test]
    fn test_error_missing_targets_field() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "server1"
"#, // Missing targets
        );

        let result = upsert_with(&mut config_str, "new-target", |_hosts| {
            panic!("Should not be called");
        });

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("host[0].targets must be an array"));
    }

    #[test]
    fn test_error_targets_wrong_type() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "server1"
targets = "not-an-array"
"#,
        );

        let result = upsert_with(&mut config_str, "new-target", |_hosts| {
            panic!("Should not be called");
        });

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("host[0].targets must be an array"));
        assert!(err_msg.contains("found: string"));
    }

    #[test]
    fn test_error_target_element_wrong_type() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "server1"
targets = ["valid", 123, "also-valid"]
"#,
        );

        let result = upsert_with(&mut config_str, "new-target", |_hosts| {
            panic!("Should not be called");
        });

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("host[0].targets[1] must be a string"));
        assert!(err_msg.contains("found: integer"));
    }

    #[test]
    fn test_error_corrupted_targets_array_during_mutation() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "server1"
targets = ["target1"]
"#,
        );

        // First, corrupt the internal structure by manually editing
        // This tests the error handling during the mutation phase
        let result = upsert_with(&mut config_str, "new-target", |_hosts| {
            UserResponse::AddTargetToHost { host_index: 0 }
        });

        // This should succeed
        assert!(result.is_ok());

        // Now manually corrupt the config
        config_str = config_str.replace("targets = [", "targets = ");

        let result2 = upsert_with(&mut config_str, "another-target", |_hosts| {
            UserResponse::AddTargetToHost { host_index: 0 }
        });

        assert!(result2.is_err());
    }

    #[test]
    fn test_error_multiple_hosts_with_validation_error() {
        let mut config_str = String::from(
            r#"[[host]]
destination = "server1"
targets = ["target1"]

[[host]]
destination = 456
targets = ["target2"]

[[host]]
destination = "server3"
targets = ["target3"]
"#,
        );

        let result = upsert_with(&mut config_str, "new-target", |_hosts| {
            panic!("Should not be called");
        });

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        // Should report error at index 1 (second host)
        assert!(err_msg.contains("host[1].destination must be a string"));
    }
}

