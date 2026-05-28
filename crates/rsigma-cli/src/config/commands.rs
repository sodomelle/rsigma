//! The `rsigma config` command group: scaffold, validate, introspect, and
//! locate configuration files.
//!
//! Output contract (agent-friendly): machine-readable answers go to stdout,
//! diagnostics and human messages go to stderr. `validate` supports
//! `--format json` so agents can branch on a structured envelope.

use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand};

use crate::exit_code;

use super::{discover, inactive_sections, load_layered};

/// The committed, commented template emitted by `rsigma config init`.
const TEMPLATE: &str = include_str!("template.yaml");

#[derive(Subcommand, Debug)]
pub(crate) enum ConfigCommands {
    /// Write a commented config template
    Init(InitArgs),

    /// Load config files and report unknown keys, inactive sections, and errors
    Validate(ValidateArgs),

    /// Print the JSON Schema for the config file
    Schema,

    /// Print the config file path(s) that would be loaded
    Path(PathArgs),
}

#[derive(Args, Debug)]
pub(crate) struct InitArgs {
    /// Where to write the template (default: ./rsigma.yaml)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Overwrite an existing file
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub(crate) struct ValidateArgs {
    /// Explicit config file (otherwise the discovery chain is used)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Output format: text (default) or json
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Treat unknown keys as errors (non-zero exit)
    #[arg(long)]
    pub strict: bool,
}

#[derive(Args, Debug)]
pub(crate) struct PathArgs {
    /// Explicit config file (otherwise the discovery chain is used)
    #[arg(short, long)]
    pub config: Option<PathBuf>,
}

/// Dispatch a `rsigma config` subcommand.
pub(crate) fn dispatch(cmd: ConfigCommands) {
    match cmd {
        ConfigCommands::Init(args) => cmd_init(args),
        ConfigCommands::Validate(args) => cmd_validate(args),
        ConfigCommands::Schema => cmd_schema(),
        ConfigCommands::Path(args) => cmd_path(args),
    }
}

fn cmd_init(args: InitArgs) {
    let output = args.output.unwrap_or_else(|| PathBuf::from("rsigma.yaml"));
    if output.exists() && !args.force {
        eprintln!(
            "refusing to overwrite existing {} (pass --force to replace it)",
            output.display()
        );
        process::exit(exit_code::CONFIG_ERROR);
    }
    if let Err(e) = std::fs::write(&output, TEMPLATE) {
        eprintln!("could not write {}: {e}", output.display());
        process::exit(exit_code::CONFIG_ERROR);
    }
    eprintln!("Wrote config template to {}", output.display());
}

fn cmd_validate(args: ValidateArgs) {
    let json = args.format == "json";
    match load_layered(args.config.as_deref()) {
        Ok(loaded) => {
            let inactive = inactive_sections(&loaded.config);
            let unknown_count = loaded.unknown_keys.len();
            let failed = args.strict && unknown_count > 0;

            if json {
                let envelope = serde_json::json!({
                    "ok": !failed,
                    "sources": loaded.sources,
                    "unknown_keys": loaded
                        .unknown_keys
                        .iter()
                        .map(|(path, key)| serde_json::json!({
                            "file": path,
                            "key": key,
                        }))
                        .collect::<Vec<_>>(),
                    "inactive_sections": inactive,
                });
                println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
            } else {
                if loaded.sources.is_empty() {
                    eprintln!("No config files found; compiled defaults apply.");
                } else {
                    eprintln!("Loaded (low to high precedence):");
                    for source in &loaded.sources {
                        eprintln!("  - {}", source.display());
                    }
                }
                for (path, key) in &loaded.unknown_keys {
                    eprintln!("warning: unknown key '{key}' in {}", path.display());
                }
                for section in &inactive {
                    eprintln!(
                        "warning: section '{section}' is set but inert in this build (feature disabled)"
                    );
                }
                if failed {
                    eprintln!("{unknown_count} unknown key(s) found (--strict)");
                } else {
                    eprintln!("Config is valid.");
                }
            }

            if failed {
                process::exit(exit_code::CONFIG_ERROR);
            }
        }
        Err(e) => {
            if json {
                let envelope = serde_json::json!({
                    "ok": false,
                    "error": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
            } else {
                eprintln!("error: {e}");
            }
            process::exit(exit_code::CONFIG_ERROR);
        }
    }
}

fn cmd_schema() {
    let schema = schemars::schema_for!(super::RsigmaConfigPartial);
    match serde_json::to_string_pretty(&schema) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("could not serialize schema: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    }
}

fn cmd_path(args: PathArgs) {
    let paths = discover(args.config.as_deref());
    if paths.is_empty() {
        println!("none");
    } else {
        for path in paths {
            println!("{}", path.display());
        }
    }
}
