mod cmd_ignore;
mod cmd_init;
mod cmd_install;
mod cmd_protect;
mod cmd_status;
mod cmd_uninstall;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "unsee", about = "Credential protection for LLM agents")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan .env* files, create .unsee.ignore if missing
    Init {
        /// Directory to scan (default: current directory)
        #[arg(long, default_value = ".")]
        dir: String,
    },
    /// Run a command with credential protection
    Protect {
        /// Arguments after --
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Install shell wrappers into ~/.zshenv
    Install,
    /// Remove shell wrappers from ~/.zshenv
    Uninstall,
    /// Show .env files, secret count, ignorelist
    Status {
        /// Directory to check (default: current directory)
        #[arg(long, default_value = ".")]
        dir: String,
    },
    /// Add a variable to .unsee.ignore
    Ignore {
        /// Variable name to ignore
        var: String,
        /// Directory containing .unsee.ignore (default: current directory)
        #[arg(long, default_value = ".")]
        dir: String,
    },
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env(),
        )
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { dir } => cmd_init::run(&dir),
        Commands::Protect { cmd } => cmd_protect::run(&cmd),
        Commands::Install => cmd_install::run(),
        Commands::Uninstall => cmd_uninstall::run(),
        Commands::Status { dir } => cmd_status::run(&dir),
        Commands::Ignore { var, dir } => cmd_ignore::run(&var, &dir),
    };

    if let Err(e) = result {
        eprintln!("unsee: {:#}", e);
        std::process::exit(1);
    }
}
