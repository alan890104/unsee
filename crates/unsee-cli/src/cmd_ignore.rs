use std::path::Path;

use anyhow::{Context, Result};

pub fn run(var: &str, dir: &str) -> Result<()> {
    let dir = Path::new(dir);
    let ignore_path = dir.join(".unsee.ignore");

    // Read existing content if file exists
    let existing = if ignore_path.exists() {
        std::fs::read_to_string(&ignore_path).context("reading .unsee.ignore")?
    } else {
        String::new()
    };

    // Check if already present
    for line in existing.lines() {
        if line.trim() == var {
            println!("{} is already in .unsee.ignore", var);
            return Ok(());
        }
    }

    // Append
    let new_content = if existing.is_empty() || existing.ends_with('\n') {
        format!("{}{}\n", existing, var)
    } else {
        format!("{}\n{}\n", existing, var)
    };

    std::fs::write(&ignore_path, &new_content).context("writing .unsee.ignore")?;
    println!("Added {} to {}", var, ignore_path.display());
    Ok(())
}
