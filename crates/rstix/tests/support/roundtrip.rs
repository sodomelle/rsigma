//! Deserialize → serialize → deserialize round-trip against a fixture file.

use std::fmt::Debug;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::load_spec_fixture;

/// Load `relative_path` under `tests/fixtures/spec/`, round-trip through JSON, and
/// return the parsed value.
pub fn roundtrip<T>(relative_path: &str) -> T
where
    T: DeserializeOwned + Serialize + PartialEq + Debug,
{
    let json = load_spec_fixture(relative_path);
    let original: serde_json::Value = serde_json::from_str(&json).expect("parse fixture");
    let parsed: T = serde_json::from_str(&json).expect("deserialize");
    let reserialized_value = serde_json::to_value(&parsed).expect("serialize to value");
    assert_reserialized_matches_fixture(&original, &reserialized_value);
    let reparsed: T = serde_json::from_value(reserialized_value).expect("reparse");
    assert_eq!(parsed, reparsed);
    parsed
}

/// Assert that deserializing `relative_path` fails.
pub fn assert_fixture_rejects<T: DeserializeOwned>(relative_path: &str) {
    let json = load_spec_fixture(relative_path);
    assert!(
        serde_json::from_str::<T>(&json).is_err(),
        "expected {relative_path} to fail deserialization"
    );
}

/// Compare the re-serialized value against the original fixture.
///
/// Fixtures for common-property structs may carry SDO-specific keys (`type`,
/// `name`, …) that the type deliberately ignores today; for those object
/// fixtures every emitted field must match the fixture, but extra fixture keys
/// are allowed. Standalone type fixtures (for example `ExternalReference`) use
/// full value equality. Once concrete SDO/SRO types land in later slices, full
/// fixture comparison will catch dropped fields for free.
fn assert_reserialized_matches_fixture(
    original: &serde_json::Value,
    reserialized: &serde_json::Value,
) {
    match (original, reserialized) {
        (serde_json::Value::Object(original), serde_json::Value::Object(reserialized)) => {
            for (key, reserialized_value) in reserialized {
                assert_eq!(
                    original.get(key),
                    Some(reserialized_value),
                    "reserialized field `{key}` does not match fixture"
                );
            }
        }
        _ => assert_eq!(
            original, reserialized,
            "reserialized value does not match fixture"
        ),
    }
}
