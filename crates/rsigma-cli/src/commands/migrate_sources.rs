//! `rsigma rule migrate-sources`: extract pipeline-embedded `sources:`
//! blocks into standalone source files.

use std::collections::HashMap;
use std::path::PathBuf;

use clap::Args;
use rsigma_eval::parse_pipeline_file;

/// Arguments for `rsigma rule migrate-sources`.
#[derive(Args, Debug)]
pub(crate) struct MigrateSourcesArgs {
    /// Pipeline file or directory of pipeline files to migrate
    #[arg(short = 'p', long = "pipeline", required = true)]
    pub pipelines: Vec<PathBuf>,

    /// Output file or directory for extracted sources
    #[arg(short, long = "output", required = true)]
    pub output: PathBuf,

    /// Consolidation strategy: 'single' writes one file (default),
    /// 'per-pipeline' writes one file per pipeline
    #[arg(long, default_value = "single", value_parser = ["single", "per-pipeline"])]
    pub strategy: String,

    /// Perform extraction without writing files
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

pub(crate) fn cmd_migrate_sources(args: MigrateSourcesArgs) {
    let MigrateSourcesArgs {
        pipelines: pipeline_paths,
        output,
        strategy,
        dry_run,
    } = args;

    let mut pipeline_files: Vec<PathBuf> = Vec::new();
    for path in &pipeline_paths {
        if path.is_dir() {
            let entries = match std::fs::read_dir(path) {
                Ok(entries) => entries,
                Err(e) => {
                    eprintln!("Error reading directory {}: {e}", path.display());
                    std::process::exit(crate::exit_code::CONFIG_ERROR);
                }
            };
            let mut files: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")))
                .collect();
            files.sort();
            pipeline_files.extend(files);
        } else {
            pipeline_files.push(path.clone());
        }
    }

    if pipeline_files.is_empty() {
        eprintln!("No pipeline files found.");
        std::process::exit(crate::exit_code::CONFIG_ERROR);
    }

    // Collected sources keyed by source ID for deduplication
    let mut consolidated: Vec<ExtractedSource> = Vec::new();
    let mut seen_ids: HashMap<String, String> = HashMap::new(); // id -> first pipeline name
    let mut per_pipeline: Vec<(String, Vec<ExtractedSource>)> = Vec::new();
    let mut pipelines_with_sources = 0;
    let mut pipelines_without_sources = 0;

    for path in &pipeline_files {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading {}: {e}", path.display());
                std::process::exit(crate::exit_code::RULE_ERROR);
            }
        };

        let pipeline = match parse_pipeline_file(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error parsing pipeline {}: {e}", path.display());
                std::process::exit(crate::exit_code::RULE_ERROR);
            }
        };

        if pipeline.sources.is_empty() {
            pipelines_without_sources += 1;
            continue;
        }

        pipelines_with_sources += 1;

        let mut extracted = Vec::new();
        for source in &pipeline.sources {
            if let Some(prev_pipeline) = seen_ids.get(&source.id) {
                eprintln!(
                    "Error: source ID '{}' declared in both '{}' and '{}'. \
                     Resolve the conflict before migrating.",
                    source.id,
                    prev_pipeline,
                    path.display()
                );
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
            seen_ids.insert(source.id.clone(), path.display().to_string());
            extracted.push(ExtractedSource {
                raw_yaml: extract_source_yaml(&content, &source.id),
            });
        }

        consolidated.extend(extracted.iter().cloned());
        per_pipeline.push((path.display().to_string(), extracted));
    }

    if consolidated.is_empty() {
        eprintln!("No sources found in any pipeline file.");
        return;
    }

    eprintln!(
        "Found {} source(s) across {} pipeline(s) ({} without sources).",
        consolidated.len(),
        pipelines_with_sources,
        pipelines_without_sources
    );

    if dry_run {
        eprintln!("Dry run: would write the following sources:");
        let yaml_content = build_sources_yaml(&consolidated);
        println!("{yaml_content}");
        return;
    }

    match strategy.as_str() {
        "single" => {
            let yaml_content = build_sources_yaml(&consolidated);
            if let Err(e) = std::fs::write(&output, &yaml_content) {
                eprintln!("Error writing {}: {e}", output.display());
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
            eprintln!(
                "Wrote {} source(s) to {}",
                consolidated.len(),
                output.display()
            );
        }
        "per-pipeline" => {
            if !output.exists()
                && let Err(e) = std::fs::create_dir_all(&output)
            {
                eprintln!("Error creating directory {}: {e}", output.display());
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
            for (pipeline_path, sources) in &per_pipeline {
                if sources.is_empty() {
                    continue;
                }
                let stem = std::path::Path::new(pipeline_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("sources");
                let out_file = output.join(format!("{stem}-sources.yml"));
                let yaml_content = build_sources_yaml(sources);
                if let Err(e) = std::fs::write(&out_file, &yaml_content) {
                    eprintln!("Error writing {}: {e}", out_file.display());
                    std::process::exit(crate::exit_code::CONFIG_ERROR);
                }
                eprintln!(
                    "Wrote {} source(s) from {pipeline_path} to {}",
                    sources.len(),
                    out_file.display()
                );
            }
        }
        _ => unreachable!(),
    }

    // Rewrite pipeline files with sources: block removed. A read failure
    // here (file deleted between scan and rewrite, permission flip, …)
    // used to panic the CLI; report the failure on stderr and keep
    // processing the remaining pipelines, matching the soft-error
    // behaviour the rewrite step itself already uses.
    for path in &pipeline_files {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "warning: could not re-read {} to strip sources: {e}",
                    path.display()
                );
                continue;
            }
        };
        let stripped = remove_sources_block(&content);
        if stripped != content {
            if let Err(e) = std::fs::write(path, &stripped) {
                eprintln!("warning: could not rewrite {}: {e}", path.display());
            } else {
                eprintln!("Removed sources: block from {}", path.display());
            }
        }
    }
}

#[derive(Clone)]
struct ExtractedSource {
    raw_yaml: String,
}

/// Extract the raw YAML text for a single source entry from a pipeline file.
/// Falls back to a simple serialization if the source can't be found by ID.
fn extract_source_yaml(content: &str, source_id: &str) -> String {
    // Try to find the source block by scanning for the id field
    let lines: Vec<&str> = content.lines().collect();
    let mut in_sources = false;
    let mut source_start: Option<usize> = None;
    let mut source_end: Option<usize> = None;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed == "sources:" {
            in_sources = true;
            continue;
        }
        if !in_sources {
            continue;
        }

        // Detect end of sources block (a non-indented, non-empty line that
        // isn't a list item or continuation)
        if !trimmed.is_empty()
            && !line.starts_with(' ')
            && !line.starts_with('\t')
            && !trimmed.starts_with('-')
        {
            if source_start.is_some() && source_end.is_none() {
                source_end = Some(i);
            }
            break;
        }

        // Detect start of our source by looking for `- id: <source_id>`
        if trimmed.starts_with("- id:") || trimmed.starts_with("-  id:") {
            let id_val = trimmed
                .trim_start_matches("- id:")
                .trim_start_matches("-  id:")
                .trim();
            if id_val == source_id || id_val == format!("\"{source_id}\"") {
                // Close any previously open source before starting ours
                source_start = Some(i);
                source_end = None;
                continue;
            } else if source_start.is_some() && source_end.is_none() {
                source_end = Some(i);
            }
        }
    }

    if source_start.is_none() {
        // Fallback: generate minimal YAML
        return format!("  - id: {source_id}\n");
    }

    let start = source_start.unwrap();
    let end = source_end.unwrap_or(lines.len());

    lines[start..end].iter().map(|l| format!("{l}\n")).collect()
}

/// Build a complete sources YAML file from extracted entries.
fn build_sources_yaml(sources: &[ExtractedSource]) -> String {
    let mut out = String::from("sources:\n");
    for src in sources {
        for line in src.raw_yaml.lines() {
            // Normalize indentation: source entries should be at 2-space indent
            if line.trim().starts_with("- id:") {
                out.push_str(&format!("  {}\n", line.trim()));
            } else if line.trim().is_empty() {
                continue;
            } else {
                // Preserve relative indentation for non-id lines
                let trimmed = line.trim();
                out.push_str(&format!("    {trimmed}\n"));
            }
        }
    }
    out
}

/// Remove the `sources:` block from a pipeline YAML string.
fn remove_sources_block(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::new();
    let mut in_sources = false;
    let mut sources_indent: Option<usize> = None;

    for line in &lines {
        let trimmed = line.trim();

        if trimmed == "sources:" && !in_sources {
            in_sources = true;
            sources_indent = Some(line.len() - line.trim_start().len());
            continue;
        }

        if in_sources {
            if trimmed.is_empty() {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if indent > sources_indent.unwrap_or(0)
                || trimmed.starts_with('-') && indent >= sources_indent.unwrap_or(0)
            {
                continue;
            }
            in_sources = false;
        }

        result.push(*line);
    }

    let mut out: String = result.join("\n");
    if content.ends_with('\n') {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_sources_block() {
        let input = r#"name: my_pipeline
priority: 50
sources:
  - id: threat_feed
    type: http
    url: https://example.com/feed
    format: json
  - id: local_data
    type: file
    path: /tmp/data.json
    format: json
transformations:
  - type: value_placeholders
"#;
        let output = remove_sources_block(input);
        assert!(!output.contains("sources:"));
        assert!(!output.contains("threat_feed"));
        assert!(!output.contains("local_data"));
        assert!(output.contains("name: my_pipeline"));
        assert!(output.contains("transformations:"));
    }

    #[test]
    fn test_remove_sources_block_no_sources() {
        let input = "name: simple\ntransformations:\n  - type: field_name_mapping\n";
        let output = remove_sources_block(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_build_sources_yaml() {
        let sources = vec![
            ExtractedSource {
                raw_yaml: "  - id: feed_a\n    type: http\n    url: https://example.com\n"
                    .to_string(),
            },
            ExtractedSource {
                raw_yaml: "  - id: feed_b\n    type: file\n    path: /tmp/data.json\n".to_string(),
            },
        ];
        let yaml = build_sources_yaml(&sources);
        assert!(yaml.starts_with("sources:\n"));
        assert!(yaml.contains("feed_a"));
        assert!(yaml.contains("feed_b"));

        // Must be valid YAML
        let parsed: yaml_serde::Value = yaml_serde::from_str(&yaml).unwrap();
        assert!(
            parsed
                .as_mapping()
                .unwrap()
                .contains_key(yaml_serde::Value::String("sources".to_string()))
        );
    }

    #[test]
    fn test_extract_source_yaml() {
        let content = r#"name: test
sources:
  - id: alpha
    type: file
    path: /tmp/a.json
    format: json
  - id: beta
    type: http
    url: https://example.com
    format: json
transformations:
  - type: value_placeholders
"#;
        let extracted = extract_source_yaml(content, "alpha");
        assert!(extracted.contains("alpha"));
        assert!(extracted.contains("file"));
        assert!(!extracted.contains("beta"));
    }
}
