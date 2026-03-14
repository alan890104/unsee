use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use unsee_core::parser;

pub fn run(dir: &str) -> Result<()> {
    let dir = Path::new(dir);

    let env_files = parser::discover_env_files(dir)
        .context("discovering .env files")?;

    if env_files.is_empty() {
        println!("No .env files found in {}", dir.display());
        return Ok(());
    }

    println!("Found {} .env file(s):", env_files.len());
    let file_set = parser::parse_env_files(&env_files)
        .context("parsing .env files")?;

    let mut all_keys: HashSet<String> = HashSet::new();
    for (path, vars) in &file_set.files {
        let name = path.file_name().unwrap().to_string_lossy();
        println!("  {} ({} keys)", name, vars.len());
        for key in vars.keys() {
            all_keys.insert(key.clone());
        }
    }

    // Create .unsee.ignore if it doesn't exist
    let ignore_path = dir.join(".unsee.ignore");
    if !ignore_path.exists() {
        std::fs::write(&ignore_path, "# Variables listed here will NOT be protected by Shield.\n# One variable name per line.\n")
            .context("creating .unsee.ignore")?;
        println!("\nCreated {}", ignore_path.display());
    } else {
        println!("\n{} already exists", ignore_path.display());
    }

    println!("\nAll keys found:");
    let mut sorted_keys: Vec<&String> = all_keys.iter().collect();
    sorted_keys.sort();
    for key in sorted_keys {
        println!("  {}", key);
    }

    println!("\nAdd variables to .unsee.ignore that don't need protection (e.g. DEBUG, PORT).");
    Ok(())
}
