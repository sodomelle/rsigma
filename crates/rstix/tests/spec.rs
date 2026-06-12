//! Integration tests backed by STIX JSON under `tests/fixtures/spec/`.
//!
//! Wire-format behavior lives here. Unit tests in `src/` cover pure parse logic
//! and error paths that do not need fixture files.

#![cfg(feature = "serde")]

mod support;

use rstix::core::{Confidence, SpecVersion};
use rstix::model::ModelError;
use rstix::model::common::{
    ExtensionMap, ExtensionType, ExternalReference, GranularMarking, ScoCommonProps,
    SdoSroCommonProps,
};

#[test]
fn sdo_sro_round_trips_attack_pattern() {
    let parsed = support::roundtrip::<SdoSroCommonProps>("common/sdo_attack-pattern.json");
    assert_eq!(parsed.spec_version, SpecVersion::V2_1);
    let created_by = parsed
        .created_by_ref
        .as_ref()
        .expect("fixture includes created_by_ref");
    assert_eq!(created_by.as_stix_id().type_name(), "identity");
    assert_eq!(parsed.external_references.len(), 1);
    assert_eq!(parsed.object_marking_refs.len(), 1);
}

#[test]
fn sdo_sro_minimal_omits_empty_optionals() {
    let parsed = support::roundtrip::<SdoSroCommonProps>("common/sdo_minimal.json");
    let value = serde_json::to_value(&parsed).expect("serialize");
    for absent in [
        "created_by_ref",
        "revoked",
        "labels",
        "confidence",
        "lang",
        "external_references",
        "object_marking_refs",
        "granular_markings",
        "extensions",
    ] {
        assert!(
            value.get(absent).is_none(),
            "expected {absent} to be omitted"
        );
    }
}

#[test]
fn sdo_sro_rejects_missing_spec_version() {
    support::assert_fixture_rejects::<SdoSroCommonProps>("common/sdo_missing_spec_version.json");
}

#[test]
fn sco_round_trips_ipv4_and_omits_sdo_fields() {
    let parsed = support::roundtrip::<ScoCommonProps>("common/sco_ipv4-addr.json");
    assert_eq!(parsed.spec_version, Some(SpecVersion::V2_1));

    let value = serde_json::to_value(&parsed).expect("serialize");
    for absent in [
        "created",
        "modified",
        "created_by_ref",
        "revoked",
        "labels",
        "confidence",
        "lang",
        "external_references",
    ] {
        assert!(
            value.get(absent).is_none(),
            "expected {absent} to be omitted"
        );
    }
}

#[test]
fn external_reference_round_trips_full_fixture() {
    let parsed = support::roundtrip::<ExternalReference>("common/external-reference.json");
    assert_eq!(parsed.source_name, "capec");
    assert_eq!(parsed.external_id.as_deref(), Some("CAPEC-163"));
}

#[test]
fn sdo_sro_confidence_round_trips_and_rejects_out_of_range() {
    let parsed = support::roundtrip::<SdoSroCommonProps>("common/sdo_confidence.json");
    assert_eq!(
        parsed.confidence,
        Some(Confidence::new(85).expect("in range"))
    );

    support::assert_fixture_rejects::<SdoSroCommonProps>("common/sdo_confidence-out-of-range.json");
}

#[test]
fn external_reference_minimal_omits_empty_optionals() {
    let parsed = support::roundtrip::<ExternalReference>("common/external-reference-minimal.json");
    let value = serde_json::to_value(&parsed).expect("serialize");
    assert_eq!(
        value.get("source_name").and_then(|v| v.as_str()),
        Some("capec")
    );
    assert_eq!(
        value.get("external_id").and_then(|v| v.as_str()),
        Some("CAPEC-163")
    );
    for absent in ["description", "url", "hashes"] {
        assert!(
            value.get(absent).is_none(),
            "expected {absent} to be omitted"
        );
    }
}

#[test]
fn external_reference_new_rejects_empty_source_name() {
    assert_eq!(
        ExternalReference::new("   ", None, None, None).unwrap_err(),
        ModelError::ExternalReferenceMissingSourceName
    );
}

#[test]
fn external_reference_new_rejects_source_name_without_detail() {
    assert_eq!(
        ExternalReference::new("capec", None, None, None).unwrap_err(),
        ModelError::ExternalReferenceMissingDetail
    );
}

#[test]
fn external_reference_rejects_invalid_fixtures() {
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-missing-source.json",
    );
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-empty-source.json",
    );
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-source-only.json",
    );
}

#[test]
fn extension_map_round_trips() {
    let map = support::roundtrip::<ExtensionMap>("common/extension-map.json");
    assert!(
        map.get("extension-definition--04ee437a-1b58-4f6e-8b3e-6c0d0c7b9b21")
            .is_some()
    );
}

#[test]
fn extension_type_strings_round_trip() {
    for (variant, text) in [
        (ExtensionType::NewSdo, "\"new-sdo\""),
        (ExtensionType::NewSro, "\"new-sro\""),
        (ExtensionType::NewSco, "\"new-sco\""),
        (ExtensionType::PropertyExtension, "\"property-extension\""),
        (
            ExtensionType::ToplevelPropertyExtension,
            "\"toplevel-property-extension\"",
        ),
    ] {
        assert_eq!(serde_json::to_string(&variant).unwrap(), text);
        let decoded: ExtensionType = serde_json::from_str(text).unwrap();
        assert_eq!(decoded, variant);
    }
    assert!(serde_json::from_str::<ExtensionType>("\"made-up\"").is_err());
}

#[test]
fn granular_marking_round_trips_marking_ref() {
    let parsed = support::roundtrip::<GranularMarking>("common/granular-marking-ref.json");
    assert!(parsed.marking_ref.is_some());
    assert!(parsed.lang.is_none());
}

#[test]
fn granular_marking_round_trips_lang() {
    let parsed = support::roundtrip::<GranularMarking>("common/granular-marking-lang.json");
    assert!(parsed.lang.is_some());
    assert!(parsed.marking_ref.is_none());
}

#[test]
fn granular_marking_rejects_both_and_neither() {
    support::assert_fixture_rejects::<GranularMarking>("common/granular-marking-both.json");
    support::assert_fixture_rejects::<GranularMarking>("common/granular-marking-neither.json");
}

#[test]
fn granular_marking_rejects_empty_selectors() {
    support::assert_fixture_rejects::<GranularMarking>(
        "common/granular-marking-empty-selectors.json",
    );
}

#[test]
fn granular_marking_rejects_missing_selectors() {
    support::assert_fixture_rejects::<GranularMarking>(
        "common/granular-marking-missing-selectors.json",
    );
}
