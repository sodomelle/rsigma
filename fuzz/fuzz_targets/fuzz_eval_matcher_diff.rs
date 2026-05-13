#![no_main]

use std::borrow::Cow;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rsigma_eval::compiler::optimizer::optimize_any_of;
use rsigma_eval::event::{EventValue, JsonEvent};
use rsigma_eval::matcher::CompiledMatcher;
use serde_json::json;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    needles: Vec<String>,
    haystack: String,
    case_insensitive: bool,
}

fuzz_target!(|input: FuzzInput| {
    if input.needles.is_empty() || input.needles.len() > 128 {
        return;
    }

    let needles: Vec<&str> = input
        .needles
        .iter()
        .filter(|n| !n.is_empty() && n.len() <= 256)
        .map(String::as_str)
        .collect();

    if needles.is_empty() {
        return;
    }

    let make_matchers = || -> Vec<CompiledMatcher> {
        needles
            .iter()
            .map(|n| {
                let value = if input.case_insensitive {
                    n.to_lowercase()
                } else {
                    n.to_string()
                };
                CompiledMatcher::Contains {
                    value,
                    case_insensitive: input.case_insensitive,
                }
            })
            .collect()
    };

    let unoptimized = CompiledMatcher::AnyOf(make_matchers());
    let optimized = optimize_any_of(make_matchers());

    let event_json = json!({});
    let event = JsonEvent::borrow(&event_json);
    let val = EventValue::Str(Cow::Borrowed(input.haystack.as_str()));

    let unopt_result = unoptimized.matches(&val, &event);
    let opt_result = optimized.matches(&val, &event);

    assert_eq!(
        unopt_result, opt_result,
        "Mismatch: needles={needles:?}, haystack={:?}, ci={}",
        input.haystack, input.case_insensitive
    );
});
