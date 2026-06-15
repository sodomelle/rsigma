//! Integration tests backed by STIX JSON under `tests/fixtures/spec/`.
//!
//! Wire-format behavior lives here. Unit tests in `src/` cover pure parse logic
//! and error paths that do not need fixture files.

#![cfg(feature = "serde")]

mod support;

use rstix::core::{Confidence, SpecVersion};
use rstix::model::common::{
    ExtensionMap, ExternalReference, GranularMarking, ScoCommonProps, SdoSroCommonProps,
};
use rstix::model::meta::{
    ExtensionDefinition, LanguageContent, MarkingDefinition, TLP1_WHITE_ID, TLP2_CLEAR_ID,
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
    let parsed = support::roundtrip_strict::<ExternalReference>("common/external-reference.json");
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
    let parsed =
        support::roundtrip_strict::<ExternalReference>("common/external-reference-minimal.json");
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
fn external_reference_rejects_invalid_fixtures() {
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-missing-source.json",
    );
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-empty-source.json",
    );
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-whitespace-source.json",
    );
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-source-only.json",
    );
}

#[test]
fn extension_map_round_trips() {
    let map = support::roundtrip_strict::<ExtensionMap>("common/extension-map.json");
    assert!(
        map.get("extension-definition--04ee437a-1b58-4f6e-8b3e-6c0d0c7b9b21")
            .is_some()
    );
}

#[test]
fn granular_marking_round_trips_marking_ref() {
    let parsed = support::roundtrip_strict::<GranularMarking>("common/granular-marking-ref.json");
    assert!(parsed.marking_ref.is_some());
    assert!(parsed.lang.is_none());
}

#[test]
fn granular_marking_round_trips_lang() {
    let parsed = support::roundtrip_strict::<GranularMarking>("common/granular-marking-lang.json");
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

#[test]
fn marking_definition_round_trips_legacy_and_current_tlp_encodings() {
    let legacy = support::roundtrip_strict::<MarkingDefinition>(
        "meta/marking-definition-tlp-v1-white-stix21.json",
    );
    assert_eq!(legacy.id.as_str(), TLP1_WHITE_ID);
    assert_eq!(legacy.definition_type.as_deref(), Some("tlp"));
    assert_eq!(
        legacy
            .definition
            .as_ref()
            .and_then(|v| v.get("tlp"))
            .and_then(|v| v.as_str()),
        Some("white")
    );
    assert!(legacy.is_non_versionable());

    let current = support::roundtrip_strict::<MarkingDefinition>(
        "meta/marking-definition-tlp-v2-clear-stix21.json",
    );
    assert_eq!(current.id.as_str(), TLP2_CLEAR_ID);
    assert!(!current.extensions.is_empty());
}

#[test]
fn marking_definition_round_trips_with_common_properties() {
    let parsed = support::roundtrip_strict::<MarkingDefinition>(
        "meta/marking-definition-with-common-props-stix21.json",
    );
    assert!(parsed.created_by_ref.is_some());
    assert_eq!(parsed.object_marking_refs.len(), 1);
    assert_eq!(parsed.external_references.len(), 1);
    assert_eq!(parsed.granular_markings.len(), 1);
}

#[test]
fn meta_types_reject_wrong_type_field() {
    support::assert_fixture_rejects::<MarkingDefinition>("meta/language-content.json");
    support::assert_fixture_rejects::<LanguageContent>(
        "meta/marking-definition-tlp-v1-white-stix21.json",
    );
    support::assert_fixture_rejects::<ExtensionDefinition>(
        "meta/marking-definition-tlp-v2-clear-stix21.json",
    );
}

#[test]
fn extension_definition_round_trips_and_rejects_missing_created_by_ref() {
    support::roundtrip_strict::<ExtensionDefinition>("meta/extension-definition.json");
    support::assert_fixture_rejects::<ExtensionDefinition>(
        "meta/extension-definition-missing-created-by-ref.json",
    );
}

#[test]
fn language_content_round_trips() {
    let parsed = support::roundtrip_strict::<LanguageContent>("meta/language-content.json");
    assert_eq!(parsed.object_ref.type_name(), "attack-pattern");
    assert!(parsed.contents.contains_key("de"));
}
