//! Cross-rule Aho-Corasick index over positive substring patterns.
//!
//! At rule load time, builds a single double-array Aho-Corasick automaton per
//! event field over every positive substring needle from every loaded rule.
//! At eval time, the engine scans each indexed field once with the per-field
//! automaton and produces a `Vec<bool>` (one entry per rule) that is `true`
//! iff at least one of the rule's positive substring patterns matched
//! somewhere on the event.
//!
//! When a rule is **AC-prunable** (see [`rule_is_ac_prunable`]), the engine
//! drops it from the candidate set when its bit in the hit vector is `false`.
//! AC-prunable rules are exactly those whose firing requires at least one
//! positive substring match, so dropping on "no hit" is provably safe.
//!
//! # Why daachorse
//!
//! For very large pattern sets (>10K patterns total across all rules),
//! daachorse's compact double-array structure is ~3-5x faster and uses ~56%
//! less memory than the equivalent NFA/DFA built by `aho-corasick`. At this
//! scale, `aho-corasick`'s Teddy SIMD prefilter is disabled because Teddy
//! supports up to ~100 patterns, so the comparison narrows to double-array
//! AC vs full DFA AC.
//!
//! For smaller rule sets, the per-rule Phase 1 [`AhoCorasickSet`] matchers
//! are already optimal; this index is gated behind the `daachorse-index`
//! feature and turned on explicitly via [`crate::Engine::set_cross_rule_ac`].
//!
//! [`AhoCorasickSet`]: crate::matcher::CompiledMatcher::AhoCorasickSet

use std::collections::HashMap;

use daachorse::DoubleArrayAhoCorasick;
use rsigma_parser::ConditionExpr;

use crate::compiler::{CompiledDetection, CompiledRule};
use crate::event::{Event, EventValue};
use crate::matcher::CompiledMatcher;

/// Maximum number of patterns indexed per field. Beyond this cap the field
/// falls back to no cross-rule automaton (rules on that field are kept in
/// the candidate set unfiltered). Sized so that even pathologically large
/// IOC rule packs don't bloat the engine's memory footprint past tens of
/// megabytes per field.
pub(crate) const MAX_PATTERNS_PER_FIELD: usize = 100_000;

/// Per-field cross-rule automaton.
struct FieldAc {
    automaton: DoubleArrayAhoCorasick<u32>,
    /// `pattern_id → rule indices`. A pattern can be reused across multiple
    /// rules, so the inner vector is small but unbounded. Kept as `Vec<u32>`
    /// instead of a `HashSet` because iteration order doesn't matter and
    /// duplicates are deduped at insert time.
    pattern_to_rules: Vec<Vec<u32>>,
}

/// Cross-rule Aho-Corasick index. Built from a slice of compiled rules,
/// holds at most one automaton per indexed field. Fields without any
/// positive substring item across the whole rule set are absent from the
/// map.
pub(crate) struct CrossRuleAcIndex {
    per_field: HashMap<String, FieldAc>,
    rule_count: usize,
}

impl CrossRuleAcIndex {
    pub(crate) fn empty() -> Self {
        Self {
            per_field: HashMap::new(),
            rule_count: 0,
        }
    }

    /// Returns true when the index contains no per-field automaton. The
    /// engine uses this to skip the scan entirely on rule sets that don't
    /// benefit from the cross-rule index.
    pub(crate) fn is_empty(&self) -> bool {
        self.per_field.is_empty()
    }

    /// Build the index from the engine's compiled rules.
    ///
    /// Walks every rule, collects `(field, lowered_needle, rule_idx)`
    /// triples, deduplicates patterns per field, and builds one
    /// `DoubleArrayAhoCorasick` per field. Fields whose pattern count
    /// exceeds [`MAX_PATTERNS_PER_FIELD`] are dropped (no automaton built);
    /// rules referencing such fields are not pruned by the index but still
    /// evaluated normally.
    pub(crate) fn build(rules: &[CompiledRule]) -> Self {
        // (field, needle) → rule indices that own this pattern on that
        // field. The pattern strings are pre-lowered (Sigma is case-
        // insensitive by default; we lower up-front because daachorse has
        // no built-in CI matching).
        let mut per_field: HashMap<String, HashMap<String, Vec<u32>>> = HashMap::new();

        for (rule_idx, rule) in rules.iter().enumerate() {
            let rule_idx_u32 = u32::try_from(rule_idx).unwrap_or(u32::MAX);
            for detection in rule.detections.values() {
                collect_rule_needles(detection, rule_idx_u32, &mut per_field);
            }
        }

        // Build one automaton per field with patterns in stable order. The
        // build order assigns pattern ids 0..n_patterns; we keep
        // `pattern_to_rules` aligned to that order.
        let mut built: HashMap<String, FieldAc> = HashMap::new();
        for (field, needle_to_rules) in per_field {
            if needle_to_rules.is_empty() {
                continue;
            }
            if needle_to_rules.len() > MAX_PATTERNS_PER_FIELD {
                log::debug!(
                    "cross-rule AC: field '{field}' has {} patterns (> {MAX_PATTERNS_PER_FIELD}); falling back",
                    needle_to_rules.len()
                );
                continue;
            }

            // Sort by pattern string for deterministic id assignment so
            // rebuilds produce identical state on identical inputs.
            let mut entries: Vec<(String, Vec<u32>)> = needle_to_rules.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));

            let mut patterns: Vec<String> = Vec::with_capacity(entries.len());
            let mut pattern_to_rules: Vec<Vec<u32>> = Vec::with_capacity(entries.len());
            for (pattern, mut rule_ids) in entries {
                rule_ids.sort_unstable();
                rule_ids.dedup();
                patterns.push(pattern);
                pattern_to_rules.push(rule_ids);
            }

            match DoubleArrayAhoCorasick::<u32>::new(&patterns) {
                Ok(automaton) => {
                    built.insert(
                        field,
                        FieldAc {
                            automaton,
                            pattern_to_rules,
                        },
                    );
                }
                Err(e) => {
                    log::warn!(
                        "cross-rule AC: failed to build automaton for field '{field}' ({} patterns): {e}",
                        patterns.len()
                    );
                }
            }
        }

        Self {
            per_field: built,
            rule_count: rules.len(),
        }
    }

    /// Number of fields with active automatons. Used for diagnostics and
    /// tests; not on the hot path.
    #[cfg(test)]
    pub(crate) fn field_count(&self) -> usize {
        self.per_field.len()
    }

    /// Mark every rule whose at least one positive substring pattern matches
    /// the event. `hits` must have length `self.rule_count`; entries are
    /// updated in place (set to `true` for matched rules).
    ///
    /// The caller is expected to start with `hits` either zeroed (for an
    /// AC-only filter) or pre-marked for non-AC-prunable rules (so the
    /// vector represents the union of "rule must be evaluated" reasons).
    pub(crate) fn mark_hits<E: Event>(&self, event: &E, hits: &mut [bool]) {
        debug_assert_eq!(hits.len(), self.rule_count);

        for (field, ac) in &self.per_field {
            // Pull the field value off the event. Only string values feed
            // the automaton; arrays, numbers, and nested objects answer
            // `MaybeMatch` (we set no bits for them and let those rules
            // evaluate normally via the candidate set).
            let value = match event.get_field(field) {
                Some(EventValue::Str(s)) => s,
                _ => continue,
            };

            // Sigma matches case-insensitively by default; the index stores
            // pre-lowered needles, so the haystack must be lowered too.
            let lowered = crate::matcher::ascii_lowercase_cow(&value);

            for m in ac.automaton.find_overlapping_iter(lowered.as_bytes()) {
                let pattern_id = m.value() as usize;
                if let Some(rule_ids) = ac.pattern_to_rules.get(pattern_id) {
                    for &rid in rule_ids {
                        let idx = rid as usize;
                        if let Some(slot) = hits.get_mut(idx) {
                            *slot = true;
                        }
                    }
                }
            }
        }
    }
}

/// Collect `(field, lowered_needle) → rule_idx` triples from a detection
/// tree. `Not(...)` subtrees contribute nothing because their negation
/// inverts the match logic and the AC index can only prove pattern
/// presence, not absence.
fn collect_rule_needles(
    detection: &CompiledDetection,
    rule_idx: u32,
    out: &mut HashMap<String, HashMap<String, Vec<u32>>>,
) {
    match detection {
        CompiledDetection::AllOf(items) => {
            for item in items {
                if let Some(field) = &item.field {
                    extract_from_matcher(
                        &item.matcher,
                        field,
                        /*negated=*/ false,
                        rule_idx,
                        out,
                    );
                }
            }
        }
        CompiledDetection::AnyOf(subs) => {
            for sub in subs {
                collect_rule_needles(sub, rule_idx, out);
            }
        }
        CompiledDetection::And(subs) => {
            for sub in subs {
                collect_rule_needles(sub, rule_idx, out);
            }
        }
        // Array object-scope predicates are on member sub-fields, not
        // top-level fields, so they contribute no top-level needles.
        CompiledDetection::ArrayMatch { .. } => {}
        CompiledDetection::Keywords(_) => {
            // Field-less; the cross-rule index is per-field so keywords are
            // out of scope. Phase 1's per-rule Aho-Corasick still handles
            // keyword detections optimally.
        }
    }
}

fn extract_from_matcher(
    m: &CompiledMatcher,
    field: &str,
    negated: bool,
    rule_idx: u32,
    out: &mut HashMap<String, HashMap<String, Vec<u32>>>,
) {
    if negated {
        return;
    }
    match m {
        CompiledMatcher::Contains { value, .. }
        | CompiledMatcher::StartsWith { value, .. }
        | CompiledMatcher::EndsWith { value, .. } => {
            push_needle(out, field, value, rule_idx);
        }
        CompiledMatcher::AhoCorasickSet { needles, .. } => {
            for needle in needles {
                push_needle(out, field, needle, rule_idx);
            }
        }
        CompiledMatcher::AnyOf(children) | CompiledMatcher::AllOf(children) => {
            for child in children {
                extract_from_matcher(child, field, negated, rule_idx, out);
            }
        }
        CompiledMatcher::CaseInsensitiveGroup { children, .. } => {
            for child in children {
                extract_from_matcher(child, field, negated, rule_idx, out);
            }
        }
        CompiledMatcher::Not(inner) => {
            extract_from_matcher(inner, field, true, rule_idx, out);
        }
        // Exact, Regex, RegexSetMatch, Cidr, Numeric*, Exists, BoolEq,
        // FieldRef, Null, Expand, TimestampPart: not substring-prunable.
        // Exact is excluded because the rule index already pre-filters it
        // at the rule level.
        _ => {}
    }
}

fn push_needle(
    out: &mut HashMap<String, HashMap<String, Vec<u32>>>,
    field: &str,
    needle: &str,
    rule_idx: u32,
) {
    if needle.is_empty() {
        return;
    }
    out.entry(field.to_string())
        .or_default()
        .entry(needle.to_string())
        .or_default()
        .push(rule_idx);
}

/// Conservative analysis: `true` iff dropping the rule on "zero AC hits" is
/// provably correct.
///
/// A rule is AC-prunable when:
/// 1. It has at least one positive substring detection item somewhere.
/// 2. Every detection in the rule is built exclusively from positive
///    substring matchers (Contains/StartsWith/EndsWith/AhoCorasickSet,
///    optionally nested under AnyOf/AllOf/CaseInsensitiveGroup). No Exact,
///    Regex, Numeric, FieldRef, Cidr, Expand, Not, etc.
/// 3. No condition expression contains `Not`, `not 1 of`, etc. (Negated
///    selectors invert match polarity, so "no substring hits" no longer
///    implies "rule cannot fire".)
///
/// Under these constraints, the rule fires iff some substring matches some
/// field, so a `false` AC verdict provably implies the rule cannot fire.
pub(crate) fn rule_is_ac_prunable(rule: &CompiledRule) -> bool {
    if rule.detections.is_empty() {
        return false;
    }

    let mut has_positive_substring = false;
    for detection in rule.detections.values() {
        let mut found = false;
        if !detection_is_pure_positive_substring(detection, &mut found) {
            return false;
        }
        has_positive_substring |= found;
    }
    if !has_positive_substring {
        return false;
    }

    rule.conditions.iter().all(condition_is_negation_free)
}

/// Returns `true` if every leaf in the detection is a positive substring
/// matcher. Sets `*found_positive_substring = true` if at least one
/// substring leaf was seen (to distinguish empty/keyword-only detections
/// from genuine substring detections).
fn detection_is_pure_positive_substring(
    detection: &CompiledDetection,
    found_positive_substring: &mut bool,
) -> bool {
    match detection {
        CompiledDetection::AllOf(items) => {
            if items.is_empty() {
                return false;
            }
            for item in items {
                if item.field.is_none() {
                    return false;
                }
                if item.exists.is_some() {
                    return false;
                }
                if !matcher_is_pure_positive_substring(&item.matcher, found_positive_substring) {
                    return false;
                }
            }
            true
        }
        CompiledDetection::AnyOf(subs) => {
            if subs.is_empty() {
                return false;
            }
            for sub in subs {
                if !detection_is_pure_positive_substring(sub, found_positive_substring) {
                    return false;
                }
            }
            true
        }
        // Keywords are field-less and the cross-rule index is per-field, so
        // we conservatively reject keyword detections from AC pruning.
        CompiledDetection::Keywords(_) => false,
        // Array object-scope matching is not a top-level positive substring
        // assertion, so rules using it are never eligible for cross-rule AC
        // pruning (they are always evaluated).
        CompiledDetection::ArrayMatch { .. } | CompiledDetection::And(_) => false,
    }
}

fn matcher_is_pure_positive_substring(
    matcher: &CompiledMatcher,
    found_positive_substring: &mut bool,
) -> bool {
    match matcher {
        CompiledMatcher::Contains { .. }
        | CompiledMatcher::StartsWith { .. }
        | CompiledMatcher::EndsWith { .. }
        | CompiledMatcher::AhoCorasickSet { .. } => {
            *found_positive_substring = true;
            true
        }
        CompiledMatcher::AnyOf(children) | CompiledMatcher::AllOf(children) => {
            !children.is_empty()
                && children
                    .iter()
                    .all(|c| matcher_is_pure_positive_substring(c, found_positive_substring))
        }
        CompiledMatcher::CaseInsensitiveGroup { children, .. } => {
            !children.is_empty()
                && children
                    .iter()
                    .all(|c| matcher_is_pure_positive_substring(c, found_positive_substring))
        }
        // Anything else (Exact, Regex, RegexSetMatch, Cidr, Numeric*,
        // FieldRef, Null, BoolEq, Exists, Expand, TimestampPart, Not)
        // breaks the AC-prunable invariant.
        _ => false,
    }
}

fn condition_is_negation_free(cond: &ConditionExpr) -> bool {
    match cond {
        // Sigma's `not 1 of selection_*` is parsed as `Not(Selector { ... })`,
        // so any `Not` node anywhere in the tree disqualifies the rule from
        // AC pruning.
        ConditionExpr::Not(_) => false,
        ConditionExpr::Identifier(_) => true,
        ConditionExpr::Selector { .. } => true,
        ConditionExpr::And(parts) | ConditionExpr::Or(parts) => {
            parts.iter().all(condition_is_negation_free)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use crate::event::JsonEvent;
    use rsigma_parser::parse_sigma_yaml;
    use serde_json::json;

    fn engine_from(yaml: &str) -> Engine {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        engine
    }

    fn build_index(yaml: &str) -> (Engine, CrossRuleAcIndex) {
        let engine = engine_from(yaml);
        let index = CrossRuleAcIndex::build(engine.rules());
        (engine, index)
    }

    #[test]
    fn empty_when_no_substring_patterns() {
        let yaml = r#"
title: Exact Only
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
    condition: selection
"#;
        let (_, index) = build_index(yaml);
        assert!(index.is_empty());
    }

    #[test]
    fn populates_per_field_automaton() {
        let yaml = r#"
title: Contains Heavy
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'whoami'
            - 'mimikatz'
            - 'powershell'
    condition: selection
"#;
        let (_, index) = build_index(yaml);
        assert_eq!(index.field_count(), 1);
    }

    #[test]
    fn marks_hits_for_matching_rule() {
        let yaml = r#"
title: Whoami Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Mimikatz Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
"#;
        let (engine, index) = build_index(yaml);
        let mut hits = vec![false; engine.rule_count()];
        let ev = json!({"CommandLine": "execute whoami /all"});
        index.mark_hits(&JsonEvent::borrow(&ev), &mut hits);
        assert!(hits[0], "first rule should hit on 'whoami'");
        assert!(!hits[1], "second rule should not hit");
    }

    #[test]
    fn marks_hits_case_insensitive() {
        let yaml = r#"
title: Whoami Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let (engine, index) = build_index(yaml);
        let mut hits = vec![false; engine.rule_count()];
        let ev = json!({"CommandLine": "execute WHOAMI /all"});
        index.mark_hits(&JsonEvent::borrow(&ev), &mut hits);
        assert!(hits[0], "haystack lowering must match upper-case input");
    }

    #[test]
    fn negated_substring_excluded_from_index() {
        let yaml = r#"
title: Negated
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains|not: 'whoami'
    condition: selection
"#;
        let (_, index) = build_index(yaml);
        assert!(index.is_empty());
    }

    #[test]
    fn ahocorasick_needles_indexed() {
        let yaml = r#"
title: AC Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'mimikatz'
            - 'powershell'
            - 'rundll32'
            - 'regsvr32'
            - 'certutil'
            - 'bitsadmin'
            - 'mshta'
            - 'wscript'
    condition: selection
"#;
        let (engine, index) = build_index(yaml);
        let mut hits = vec![false; engine.rule_count()];
        let ev = json!({"CommandLine": "rundll32.exe foo"});
        index.mark_hits(&JsonEvent::borrow(&ev), &mut hits);
        assert!(hits[0]);
    }

    #[test]
    fn shared_pattern_marks_multiple_rules() {
        let yaml = r#"
title: Rule A
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Rule B
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let (engine, index) = build_index(yaml);
        let mut hits = vec![false; engine.rule_count()];
        let ev = json!({"CommandLine": "whoami /all"});
        index.mark_hits(&JsonEvent::borrow(&ev), &mut hits);
        assert!(hits[0] && hits[1]);
    }

    #[test]
    fn ac_prunable_pure_substring_rule() {
        let yaml = r#"
title: Pure Contains
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let engine = engine_from(yaml);
        assert!(rule_is_ac_prunable(&engine.rules()[0]));
    }

    #[test]
    fn ac_prunable_rejects_mixed_exact_and_substring() {
        let yaml = r#"
title: Mixed
logsource:
    product: windows
detection:
    selection:
        EventType: 'process_create'
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let engine = engine_from(yaml);
        assert!(!rule_is_ac_prunable(&engine.rules()[0]));
    }

    #[test]
    fn ac_prunable_rejects_negation_in_condition() {
        let yaml = r#"
title: Negated Condition
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    other:
        CommandLine|contains: 'admin'
    condition: selection and not other
"#;
        let engine = engine_from(yaml);
        assert!(!rule_is_ac_prunable(&engine.rules()[0]));
    }

    #[test]
    fn ac_prunable_rejects_keywords() {
        let yaml = r#"
title: Keyword Only
logsource:
    product: windows
detection:
    keywords:
        - 'suspicious'
        - 'malware'
    condition: keywords
"#;
        let engine = engine_from(yaml);
        assert!(!rule_is_ac_prunable(&engine.rules()[0]));
    }

    #[test]
    fn ac_prunable_accepts_anyof_substring_values() {
        let yaml = r#"
title: AnyOf Substrings
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'whoami'
            - 'mimikatz'
            - 'powershell'
    condition: selection
"#;
        let engine = engine_from(yaml);
        assert!(rule_is_ac_prunable(&engine.rules()[0]));
    }

    #[test]
    fn cap_drops_overflowing_field() {
        // Build a synthetic rule set with > MAX_PATTERNS_PER_FIELD distinct
        // patterns on the same field. The builder must skip the field
        // rather than panicking.
        let mut yaml = String::new();
        let n = MAX_PATTERNS_PER_FIELD + 5;
        for i in 0..n {
            yaml.push_str(&format!(
                "title: R{i}\n\
                 id: r-{i:08}\n\
                 logsource:\n\
                 \x20   product: windows\n\
                 detection:\n\
                 \x20   selection:\n\
                 \x20       CommandLine|contains: 'pat-{i:08}'\n\
                 \x20   condition: selection\n\
                 ---\n",
            ));
        }
        let engine = engine_from(&yaml);
        let index = CrossRuleAcIndex::build(engine.rules());
        // Field is dropped, so the index is empty for CommandLine.
        assert!(index.is_empty());
    }
}
