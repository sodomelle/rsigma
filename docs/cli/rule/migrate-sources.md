# migrate-sources

Extract pipeline-embedded `sources:` blocks into standalone source files.

## Synopsis

```bash
rsigma rule migrate-sources -p <PIPELINE> -o <OUTPUT> [--strategy <STRATEGY>] [--dry-run]
```

## Description

Scans one or more pipeline files for inline `sources:` blocks, extracts them into standalone source file(s), and rewrites the original pipeline files with the `sources:` block removed. This is the recommended migration path now that pipeline-embedded `sources:` is deprecated in favor of the `--source` daemon flag.

The tool detects source ID collisions across pipelines and exits with an error if two pipelines declare the same ID with different configurations.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --pipeline <PATH>` | (required) | Pipeline file or directory of pipeline files to migrate. Repeatable. |
| `-o, --output <PATH>` | (required) | Output file (for `single` strategy) or directory (for `per-pipeline` strategy). |
| `--strategy <single\|per-pipeline>` | `single` | `single`: consolidate all sources into one file. `per-pipeline`: write one file per pipeline. |
| `--dry-run` | off | Preview the extracted sources on stdout without writing files. |

## Examples

Consolidate all sources from a pipeline directory into a single file:

```bash
rsigma rule migrate-sources -p pipelines/ -o sources.yml
```

Then update the daemon invocation to load the sources from the new file:

```bash
rsigma engine daemon -r rules/ -p pipelines/ --source sources.yml
```

Preview what would be extracted without writing:

```bash
rsigma rule migrate-sources -p pipeline.yml -o sources.yml --dry-run
```

Write one output file per pipeline:

```bash
rsigma rule migrate-sources -p pipelines/ -o sources.d/ --strategy per-pipeline
```
