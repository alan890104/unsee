use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use unsee_core::{credpaths, ignorelist, mapping::MultiFileMapping, parser};
use unsee_guard::sandbox::UnseeSandbox;

pub fn run(dir: &str) -> Result<()> {
    let dir = Path::new(dir);

    let env_files = parser::discover_env_files(dir)
        .context("discovering .env files")?;

    if env_files.is_empty() {
        println!("No .env files found in {}", dir.display());
    } else {
        let file_set = parser::parse_env_files(&env_files)
            .context("parsing .env files")?;

        // Load ignorelist
        let ignore_path = dir.join(".unsee.ignore");
        let ignorelist_set = if ignore_path.exists() {
            ignorelist::parse_ignorelist(&ignore_path)
                .context("parsing .unsee.ignore")?
        } else {
            HashSet::new()
        };

        let mapping = MultiFileMapping::build(&file_set, &ignorelist_set, Some(vec![0u8; 32]));

        println!(".env files:");
        for (path, vars) in &file_set.files {
            let name = path.file_name().unwrap().to_string_lossy();
            println!("  {} ({} keys)", name, vars.len());
        }

        println!("\nSecrets protected: {}", mapping.secrets_count());

        if !ignorelist_set.is_empty() {
            println!("\nIgnored variables:");
            let mut sorted: Vec<&String> = ignorelist_set.iter().collect();
            sorted.sort();
            for var in sorted {
                println!("  {}", var);
            }
        }

        if ignore_path.exists() {
            println!("\nIgnorelist: {}", ignore_path.display());
        } else {
            println!("\nNo .unsee.ignore found. Run `unsee init` to create one.");
        }
    }

    // Credential file protection status
    println!("\n--- Credential File Protection ---");

    // Sandbox support
    let info = UnseeSandbox::support_info();
    if info.is_supported {
        println!("Sandbox: supported ({})", info.details);
    } else {
        println!("Sandbox: NOT supported ({})", info.details);
    }

    // Credential paths
    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(&home);
        let config_path = home_path.join(".unsee/credentials.conf");
        let cred_paths = if config_path.exists() {
            println!("Config: {}", config_path.display());
            credpaths::load_credential_config(&config_path, &home_path)
        } else {
            println!("Config: default (no ~/.unsee/credentials.conf)");
            credpaths::resolve_credential_paths(&home_path)
        };

        if cred_paths.is_empty() {
            println!("Protected credential paths: none found");
        } else {
            println!("\nProtected credential paths:");
            for p in &cred_paths {
                let exists = if p.exists() { "exists" } else { "missing" };
                println!("  {} ({})", p.display(), exists);
            }
        }
    } else {
        println!("Warning: HOME not set, cannot resolve credential paths");
    }

    Ok(())
}
