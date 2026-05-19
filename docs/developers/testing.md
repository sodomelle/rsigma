# Testing

The workspace runs five tiers of tests, all gated in CI. PRs are expected to pass every tier.

## At a glance

| Tier | Where it lives | How to run | Gated by |
|------|----------------|------------|----------|
| Unit | `src/` modules with `#[cfg(test)] mod tests` | `cargo test --workspace --all-features --locked` | `test` job on Linux, macOS, Windows. |
| Integration | `crates/<crate>/tests/*.rs` | Same. | Same. |
| Snapshot / golden | `crates/rsigma-eval/tests/state_snapshot.rs`, `tests/fixtures/dynamic-pipelines/golden/` | `cargo test` plus the SigmaHQ-corpus job for the dynamic-pipelines goldens. | `test` and `sigma-corpus` jobs. |
| SigmaHQ corpus | `.github/workflows/ci.yml` -> `sigma-corpus` | `cargo build --release --all-features --locked -p rsigma` then `target/release/rsigma rule validate /tmp/sigma/rules/ --verbose` | `sigma-corpus` job, on every PR. |
| Coverage | `cargo-llvm-cov` (Linux) | `cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info` | `coverage` job (advisory, not gating). |

## Unit tests

Located inside the crate modules they test. Conventional Rust:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_rule() {
        let rule = parse_sigma_yaml(MINIMAL_YAML).unwrap();
        assert_eq!(rule.rules.len(), 1);
    }
}
```

Bias toward unit tests for pure-functional logic (parsers, matchers, formatters). Bias toward integration tests for end-to-end shapes (CLI invocations, daemon HTTP round-trips, dynamic source resolution).

## Integration tests

| Crate | File(s) | What they cover |
|-------|---------|-----------------|
| `rsigma-parser` | `tests/*.rs` (2 files) | Multi-document parsing, malformed YAML, directory parsing. |
| `rsigma-eval` | `tests/integration.rs`, `correlation_edge.rs`, `error_paths.rs`, `pipeline_errors.rs`, `regression_eval.rs`, `state_snapshot.rs` (and a shared `helpers/`) | Full rule-eval pipelines, correlation edge cases, snapshot replay, pipeline error semantics. |
| `rsigma-convert` | `tests/*.rs` (3 files) | Backend output for each `--format` (`default`, `view`, `timescaledb`, …). |
| `rsigma-runtime` | `tests/integration.rs`, `nats_integration.rs`, `evtx_integration.rs`, `nats_e2e.rs`, `sources_integration.rs` | Streaming runtime, NATS round-trips (gated on a local NATS server in CI), EVTX file parsing, dynamic source resolution. |
| `rsigma-cli` | `tests/cli_*.rs` (13 files) | The full CLI surface: `convert`, `daemon` (stdin / HTTP / NATS / OTLP / dynamic sources), `eval`, `lint`, `parse`, `validate`, `fields`, deprecation warnings. |

Helpers (test rule fixtures, common test pipelines) live in `crates/<crate>/tests/helpers/mod.rs` or `crates/<crate>/tests/common/mod.rs`. Reuse them; do not duplicate.

Do not duplicate unit-level assertions in integration tests. Integration tests own the boundaries, the multi-component chains, and the error paths.

## Golden tests

The dynamic-pipelines suite under `tests/fixtures/dynamic-pipelines/` is the canonical golden-file harness:

```text
tests/fixtures/dynamic-pipelines/
├── pipelines/                  # inputs (one *.yml per scenario)
├── sources/                    # mock source bodies (HTTP, file, command output)
└── golden/                     # expected `rsigma pipeline resolve --pretty` output
```

The CI loop in the `sigma-corpus` job iterates `pipelines/*.yml`, runs `rsigma pipeline resolve --pretty`, and diffs against `golden/${name}.json`. To run the same check locally:

```bash
cargo build --release --all-features --locked -p rsigma
for pipeline in tests/fixtures/dynamic-pipelines/pipelines/*.yml; do
  name=$(basename "$pipeline" .yml)
  golden="tests/fixtures/dynamic-pipelines/golden/${name}.json"
  diff -u "$golden" <(./target/release/rsigma pipeline resolve --pipeline "$pipeline" --pretty) \
    || echo "FAIL: $name"
done
```

To regenerate a golden after an intentional behaviour change:

```bash
./target/release/rsigma pipeline resolve --pipeline tests/fixtures/dynamic-pipelines/pipelines/<name>.yml --pretty \
    > tests/fixtures/dynamic-pipelines/golden/<name>.json
```

Then `git diff` the resulting golden file; if the diff matches your intent, commit it along with the code change. Otherwise revert and investigate.

## SigmaHQ corpus regression

CI clones [`SigmaHQ/sigma`](https://github.com/SigmaHQ/sigma) at `main` and runs three checks (see `.github/workflows/ci.yml`, job `sigma-corpus`):

```bash
# 1. Every rule must parse and compile.
./target/release/rsigma rule validate /tmp/sigma/rules/ --verbose

# 2. The dynamic-pipelines fixtures must still resolve cleanly against
#    the live corpus, validating that the field-mapping and include
#    expansion stay compatible with rules in the wild.
./target/release/rsigma rule validate /tmp/sigma/rules/ \
    --pipeline tests/fixtures/dynamic-pipelines/pipelines/field_mapping.yml \
    --pipeline tests/fixtures/dynamic-pipelines/pipelines/allowlist.yml \
    --pipeline tests/fixtures/dynamic-pipelines/pipelines/multi_format.yml \
    --pipeline tests/fixtures/dynamic-pipelines/pipelines/extract_languages.yml \
    --pipeline tests/fixtures/dynamic-pipelines/pipelines/include_expansion.yml \
    --resolve-sources --verbose

# 3. The dynamic-pipelines goldens must match (the diff loop shown above).
```

A regression in any of those steps fails the PR. Locally:

```bash
cargo build --release --all-features --locked -p rsigma
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
./target/release/rsigma rule validate /tmp/sigma/rules/ --verbose
```

This is the only place we run "the real corpus". Keep it green.

## Coverage

The `coverage` job runs `cargo llvm-cov --workspace --all-features --lcov` on Linux and uploads `lcov.info`. It is advisory, not gating; there are no per-crate thresholds enforced today. Drops of more than a couple of percentage points warrant a comment on the PR.

## Performance regressions

Criterion benchmarks live under `crates/<crate>/benches/`. Run them manually:

```bash
cargo bench -p rsigma-eval -- eval
cargo bench -p rsigma-parser -- parse
cargo bench -p rsigma-runtime -- runtime_throughput
```

Benchmarks are not gated in CI. The numbers in [Benchmarks](../benchmarks.md) come from a manual run on the development workstation; if a PR makes a hot-path change, attach a before/after Criterion summary in the PR description.

## Tips

- **Run only the failing test first.** `cargo test -p rsigma-runtime nats_e2e::test_replay_from_offset -- --nocapture` is much faster than `--workspace`.
- **Run feature-gated tests once with the feature off.** A `#[cfg(feature = "nats")] fn test_x()` is silently skipped if you forget; CI catches that. Locally, `cargo test --no-default-features -p rsigma-runtime` is a useful smoke test.
- **NATS / OTLP integration tests** spawn a local server in-process; they do not need external infrastructure.
- **CLI tests use `assert_cmd`.** They invoke the compiled `rsigma` binary, so first time they run is slow because they trigger a full build.

See also: [Fuzzing](fuzzing.md), [Benchmarks](../benchmarks.md), [Contributing](../contributing.md).
