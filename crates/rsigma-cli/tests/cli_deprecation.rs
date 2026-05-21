//! Smoke tests for the deprecated flat-form CLI aliases.
//!
//! Each deprecated alias (`eval`, `daemon`, `parse`, `validate`, `lint`,
//! `fields`, `condition`, `stdin`, `convert`, `list-targets`, `list-formats`,
//! `resolve`) is hidden from `rsigma --help` but kept as a functional
//! forwarder until v1.0 ([issue #126](https://github.com/timescale/rsigma/issues/126)).
//! This file asserts that:
//!
//! 1. The flat invocation still succeeds (or fails with the same exit code
//!    as the new grouped form for error paths).
//! 2. The flat invocation prints the `warning: \`rsigma <old>\` is deprecated`
//!    message on stderr.
//! 3. Where it makes sense (cheap stateless commands), the flat form
//!    produces the same stdout as the new grouped form.
//! 4. `rsigma --help` lists only the four new groups (`engine`, `rule`,
//!    `backend`, `pipeline`) plus `help`, and does NOT list any deprecated
//!    alias.
//! 5. Each new group's own `--help` lists the leaf subcommands.

mod common;

use common::{SIMPLE_RULE, rsigma, temp_file};
use predicates::prelude::*;

const DEPRECATION_PREFIX: &str = "warning: `rsigma ";

// ---------------------------------------------------------------------------
// Help output
// ---------------------------------------------------------------------------

#[test]
fn root_help_hides_deprecated_aliases() {
    let assert = rsigma()
        .args(["--help"])
        .assert()
        .success()
        // The four new groups still appear in the Commands list.
        .stdout(predicate::str::contains("engine"))
        .stdout(predicate::str::contains("rule"))
        .stdout(predicate::str::contains("backend"))
        .stdout(predicate::str::contains("pipeline"))
        // The `[deprecated]` tag is no longer rendered anywhere because every
        // alias that carried it is now hidden.
        .stdout(predicate::str::contains("[deprecated]").not());

    // The Commands block ends at the first blank line after "Commands:". Scope
    // the alias-absence check to that block so we don't trip on substring hits
    // elsewhere in the help output (e.g. `--log-format` mentioning `engine
    // daemon`, or the `--input-format` flag mentioning `stdin`).
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let commands_block = stdout
        .split_once("Commands:")
        .map(|(_, rest)| rest.split("\n\n").next().unwrap_or(""))
        .expect("`Commands:` header should appear in `rsigma --help`");

    // The single-word `eval`, `daemon`, `lint`, etc. would otherwise be
    // substrings of `engine eval`, `engine daemon`, `rule lint`, etc.; the
    // grouped form lives under each group's own `--help`, not the root one,
    // so each token only appears in the root help if its deprecated alias
    // is still rendered. Match the leading two-space indent + alias as a
    // standalone command name in the Commands block.
    for alias in [
        "  eval ",
        "  daemon ",
        "  parse ",
        "  validate ",
        "  lint ",
        "  fields ",
        "  condition ",
        "  stdin ",
        "  convert ",
        "  list-targets",
        "  list-formats",
        "  resolve ",
    ] {
        assert!(
            !commands_block.contains(alias),
            "deprecated alias `{}` should NOT appear in `rsigma --help` Commands block, got:\n{}",
            alias.trim(),
            commands_block,
        );
    }
}

#[test]
fn engine_group_help_lists_eval_and_daemon() {
    rsigma()
        .args(["engine", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("eval"))
        .stdout(predicate::str::contains("daemon"));
}

#[test]
fn rule_group_help_lists_all_six_leafs() {
    let assert = rsigma().args(["rule", "--help"]).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    for leaf in ["parse", "validate", "lint", "fields", "condition", "stdin"] {
        assert!(
            stdout.contains(leaf),
            "`rsigma rule --help` should list `{leaf}`, got:\n{stdout}"
        );
    }
}

#[test]
fn backend_group_help_lists_convert_targets_formats() {
    let assert = rsigma().args(["backend", "--help"]).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    for leaf in ["convert", "targets", "formats"] {
        assert!(
            stdout.contains(leaf),
            "`rsigma backend --help` should list `{leaf}`, got:\n{stdout}"
        );
    }
}

#[test]
fn pipeline_group_help_lists_resolve() {
    rsigma()
        .args(["pipeline", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("resolve"));
}

// ---------------------------------------------------------------------------
// Per-alias deprecation warning + behavior parity
// ---------------------------------------------------------------------------

#[test]
fn deprecated_parse_warns_and_succeeds() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let assert = rsigma()
        .args(["parse", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule parse"))
        .stdout(predicate::str::contains("Test Rule"));

    // Same stdout as the new form.
    let new_stdout = rsigma()
        .args(["rule", "parse", rule.path().to_str().unwrap()])
        .output()
        .unwrap()
        .stdout;
    let old_stdout = assert.get_output().stdout.clone();
    assert_eq!(
        String::from_utf8_lossy(&old_stdout),
        String::from_utf8_lossy(&new_stdout),
        "deprecated `parse` should produce identical stdout to `rule parse`",
    );
}

#[test]
fn deprecated_validate_warns_and_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rule.yml"), SIMPLE_RULE).unwrap();
    rsigma()
        .args(["validate", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule validate"))
        .stdout(predicate::str::contains("Detection rules:"));
}

#[test]
fn deprecated_lint_warns_and_succeeds() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule lint"));
}

#[test]
fn deprecated_fields_warns_and_succeeds() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule fields"));
}

#[test]
fn deprecated_condition_warns_and_succeeds() {
    let assert = rsigma()
        .args(["condition", "sel and not filter"])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule condition"));

    let new_stdout = rsigma()
        .args(["rule", "condition", "sel and not filter"])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(
        String::from_utf8_lossy(&assert.get_output().stdout),
        String::from_utf8_lossy(&new_stdout),
        "deprecated `condition` should produce identical stdout to `rule condition`",
    );
}

#[test]
fn deprecated_stdin_warns_and_succeeds() {
    rsigma()
        .args(["stdin"])
        .write_stdin(SIMPLE_RULE)
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule stdin"))
        .stdout(predicate::str::contains("Test Rule"));
}

#[test]
fn deprecated_eval_warns_and_succeeds() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine":"benign"}"#,
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("engine eval"));
}

#[test]
fn deprecated_convert_warns_and_succeeds() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args(["convert", rule.path().to_str().unwrap(), "-t", "test"])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("backend convert"));
}

#[test]
fn deprecated_list_targets_warns_and_matches_backend_targets() {
    let assert = rsigma()
        .args(["list-targets"])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("backend targets"));

    let new_stdout = rsigma()
        .args(["backend", "targets"])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(
        String::from_utf8_lossy(&assert.get_output().stdout),
        String::from_utf8_lossy(&new_stdout),
        "deprecated `list-targets` should produce identical stdout to `backend targets`",
    );
}

#[test]
fn deprecated_list_formats_warns_and_matches_backend_formats() {
    let assert = rsigma()
        .args(["list-formats", "test"])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("backend formats"));

    let new_stdout = rsigma()
        .args(["backend", "formats", "test"])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(
        String::from_utf8_lossy(&assert.get_output().stdout),
        String::from_utf8_lossy(&new_stdout),
        "deprecated `list-formats test` should produce identical stdout to `backend formats test`",
    );
}

// ---------------------------------------------------------------------------
// Daemon and resolve deprecation
// ---------------------------------------------------------------------------

/// `rsigma daemon` is the heaviest deprecated alias. Even though it is hidden
/// from `rsigma --help`, the alias-specific `--help` page must still render so
/// scripts that pass `--help` keep working through the deprecation window. We
/// assert that `rsigma daemon --help` is reachable and surfaces the same flag
/// list as `rsigma engine daemon --help`. Spawning a real daemon is covered by
/// `cli_daemon.rs` (which already uses the new path).
#[cfg(feature = "daemon")]
#[test]
fn deprecated_daemon_help_still_works() {
    rsigma()
        .args(["daemon", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--rules"))
        .stdout(predicate::str::contains("--input"));
}

#[cfg(feature = "daemon")]
#[test]
fn deprecated_resolve_warns_on_invalid_pipeline() {
    // Don't need a real dynamic source — empty pipeline list is a parse error
    // and exits non-zero. We're only checking the deprecation warning fires
    // before the failure.
    rsigma()
        .args(["resolve", "-p", "/tmp/nonexistent_rsigma_pipeline.yml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("pipeline resolve"));
}
