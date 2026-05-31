//! Deprecation warnings for pipeline-embedded configuration that is being
//! removed in a future release.
//!
//! Today the only such surface is the pipeline-level `sources:` block, which
//! v0.13.0 ([PR #135](https://github.com/timescale/rsigma/pull/135)) replaced
//! with the daemon-level `--source <file_or_dir>` flag. The parser still
//! accepts the inline form, but every CLI entry point that loads a pipeline
//! and every daemon hot-reload now surface the deprecation to the operator
//! before the parser swallows it.
//!
//! The helper lives in `rsigma-runtime` (rather than `rsigma-cli` where it
//! started) so the one-shot CLI startup path (`load_pipelines`) and the
//! long-running daemon hot-reload path (`RuntimeEngine::reload_rules` ->
//! `reload_pipelines`) can share one helper, one warning string, and one
//! process-wide dedup set. Library consumers that drive `RuntimeEngine`
//! directly inherit the same warning behaviour without needing to wire
//! anything up.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Deduplication set for the pipeline-embedded `sources:` deprecation warning.
///
/// The set is process-wide and shared between every caller of
/// [`warn_pipeline_inline_sources`] (the CLI's `load_pipelines` at startup,
/// the daemon's [`RuntimeEngine::load_rules`] on every hot-reload, the
/// `pipeline resolve` command, and any library embedder that drives
/// `RuntimeEngine` themselves). Paths are canonicalised before insertion so
/// equivalent spellings (`./pipeline.yml` vs `pipeline.yml`) collapse to one
/// entry; canonicalisation failures fall back to the raw path so we still
/// get one-per-spelling dedup.
///
/// One-shot commands (`eval`, `validate`, `fields`, `convert`, `resolve`)
/// only call into the helper once per pipeline path, so the dedup set is
/// effectively a noop for them. The daemon's hot-reload path is where it
/// earns its keep: SIGHUP, file-watcher events, and `POST /api/v1/reload`
/// all funnel through `reload_pipelines`, which would otherwise re-emit the
/// warning on every reload tick.
///
/// [`RuntimeEngine::load_rules`]: crate::RuntimeEngine::load_rules
static SEEN_INLINE_SOURCES: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

/// Lock a mutex, recovering the guarded value if a previous holder panicked.
///
/// The dedup set is process-wide, so a panicking unit test (e.g. a failed
/// assertion while holding the lock) must not poison the mutex for unrelated
/// callers and cascade into spurious failures elsewhere in the test binary.
fn lock_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Canonicalise `path` and record it in `seen`. Returns `true` if the path was
/// newly inserted (the caller should emit the warning), `false` if it had
/// already been seen. Factored out so the dedup behaviour can be unit-tested
/// against a local set without touching the process-wide state.
fn mark_inline_source_seen(seen: &Mutex<HashSet<PathBuf>>, path: &Path) -> bool {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    lock_recover(seen).insert(canonical)
}

/// Surface the pipeline-embedded `sources:` deprecation notice for one
/// pipeline file. Idempotent per canonical path (see [`SEEN_INLINE_SOURCES`]).
///
/// The warning is emitted via both `tracing::warn!` (for structured log
/// aggregation, with `pipeline` and `path` fields) and `eprintln!` (for
/// direct operator visibility on stderr when the tracing subscriber is
/// quiet, e.g. one-shot CLI invocations without `RUST_LOG=info`).
///
/// Phases of the deprecation cycle this helper backs:
/// - Phase 1 ([#135](https://github.com/timescale/rsigma/pull/135)):
///   `tracing::warn!` only, emitted from the CLI's startup path. Shipped in
///   v0.13.0.
/// - Phase 3 ([#136](https://github.com/timescale/rsigma/issues/136)):
///   `tracing::warn!` + `eprintln!`, emitted from both the CLI startup path
///   and the daemon hot-reload path. This helper.
/// - Phase 4 ([#137](https://github.com/timescale/rsigma/issues/137)):
///   hard parse error at v1.0; this helper is removed.
pub fn warn_pipeline_inline_sources(path: &Path, pipeline_name: &str) {
    let seen = SEEN_INLINE_SOURCES.get_or_init(|| Mutex::new(HashSet::new()));
    if !mark_inline_source_seen(seen, path) {
        return;
    }

    tracing::warn!(
        pipeline = %pipeline_name,
        path = %path.display(),
        "pipeline declares inline 'sources:' block, which is deprecated; \
         use '--source <file>' instead. Run 'rsigma rule migrate-sources' \
         to extract sources into a standalone file. Pipeline-embedded \
         sources will be removed in v1.0."
    );
    eprintln!(
        "warning: pipeline '{}' ({}) declares an inline 'sources:' block, \
         which is deprecated and will be removed in v1.0. Migrate with \
         `rsigma rule migrate-sources -p {} -o sources.yml` and load via \
         `--source sources.yml` on `rsigma engine daemon`.",
        pipeline_name,
        path.display(),
        path.display(),
    );
}

/// Clear the dedup set so the next [`warn_pipeline_inline_sources`] call for
/// a previously-seen path re-emits the warning. Intended for tests that
/// exercise multiple separate "process lifetimes" inside one test binary.
#[doc(hidden)]
pub fn reset_inline_sources_dedup_for_tests() {
    if let Some(seen) = SEEN_INLINE_SOURCES.get() {
        lock_recover(seen).clear();
    }
}

/// Read-only snapshot of the dedup set. Intended for tests that need to
/// assert that a particular caller routed through [`warn_pipeline_inline_sources`]
/// (e.g. asserting the runtime hot-reload path covers the deprecation).
#[doc(hidden)]
pub fn tests_only_snapshot() -> HashSet<PathBuf> {
    SEEN_INLINE_SOURCES
        .get()
        .map(|m| lock_recover(m).clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests exercise the dedup primitive against a local set, not the
    // process-wide `SEEN_INLINE_SOURCES`. That keeps them deterministic and
    // free of cross-test contention: cargo runs the binary's tests in parallel
    // threads, and asserting on (or resetting) a shared singleton races with
    // the runtime-level tests in `engine.rs` and poisons the mutex on failure.

    #[test]
    fn dedup_suppresses_repeat_warnings_for_same_canonical_path() {
        let file = tempfile::Builder::new().suffix(".yml").tempfile().unwrap();
        let seen = Mutex::new(HashSet::new());

        assert!(
            mark_inline_source_seen(&seen, file.path()),
            "first occurrence should be newly recorded (and warn)"
        );
        assert!(
            !mark_inline_source_seen(&seen, file.path()),
            "repeat occurrence for the same path should be suppressed"
        );

        let canonical = file.path().canonicalize().unwrap();
        assert!(lock_recover(&seen).contains(&canonical));
    }

    #[test]
    fn dedup_distinguishes_distinct_canonical_paths() {
        let a = tempfile::Builder::new().suffix(".yml").tempfile().unwrap();
        let b = tempfile::Builder::new().suffix(".yml").tempfile().unwrap();
        let seen = Mutex::new(HashSet::new());

        assert!(mark_inline_source_seen(&seen, a.path()));
        assert!(mark_inline_source_seen(&seen, b.path()));

        let guard = lock_recover(&seen);
        assert!(guard.contains(&a.path().canonicalize().unwrap()));
        assert!(guard.contains(&b.path().canonicalize().unwrap()));
    }
}
