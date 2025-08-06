//! DevDocs Pro CLI
//!
//! Command-line interface for DevDocs Pro

use clap::{Parser, Subcommand};
use devdocs_core::Config;

#[derive(Parser)]
#[command(name = "devdocs")]
#[command(about = "DevDocs Pro - Real-time API documentation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the DevDocs middleware
    Start {
        /// Configuration file path
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Validate configuration
    Config {
        /// Configuration file path
        #[arg(short, long)]
        config: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config: _ } => {
            println!("Starting DevDocs Pro middleware...");
            // TODO: Implement middleware startup
        }
        Commands::Config { config: _ } => {
            let config = Config::from_env()?;
            println!("Configuration loaded successfully:");
            println!("{:#?}", config);
        }
    }

    Ok(())
}
