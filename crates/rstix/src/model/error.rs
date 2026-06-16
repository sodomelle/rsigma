//! Model-level validation errors raised when constructing or validating STIX
//! values whose invariants cannot be expressed in the type system alone.

/// Errors raised while constructing or validating STIX model values.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelError {
    /// An `external-reference` was missing the required `source_name`.
    #[error("external reference requires a non-empty source_name")]
    ExternalReferenceMissingSourceName,
    /// An `external-reference` must set at least one of `description`, `url`,
    /// or `external_id` (STIX §2.5.2).
    #[error("external reference requires at least one of description, url, or external_id")]
    ExternalReferenceMissingDetail,
    /// A `granular-marking` must set exactly one of `marking_ref` or `lang`.
    #[error("granular marking must set exactly one of marking_ref or lang")]
    GranularMarkingExclusivity,
    /// A `granular-marking` must name at least one selector.
    #[error("granular marking requires at least one selector")]
    GranularMarkingEmptySelectors,
    /// An `extension-definition` requires `created_by_ref` (STIX §7.2.2).
    #[error("extension definition requires created_by_ref")]
    ExtensionDefinitionMissingCreatedByRef,
    /// JSON `type` does not match the struct being deserialized.
    #[error("expected STIX type `{expected}`, got `{actual}`")]
    UnexpectedObjectType {
        /// Expected STIX `type` string.
        expected: &'static str,
        /// `type` value from the JSON document.
        actual: String,
    },
    /// A `relationship` `relationship_type` contains characters outside `[a-z0-9-]`.
    #[error("relationship type must contain only lowercase ASCII letters, digits, and hyphens")]
    RelationshipTypeInvalid,
    /// A `relationship` `stop_time` is not later than `start_time` when both are set.
    #[error("relationship stop_time must be later than start_time")]
    RelationshipStopTimeBeforeStartTime,
    /// A `sighting` `count` is outside `0..=999_999_999`.
    #[error("sighting count must be between 0 and 999_999_999 inclusive")]
    SightingCountOutOfRange,
    /// A `sighting` `last_seen` is earlier than `first_seen` when both are set.
    #[error("sighting last_seen must be greater than or equal to first_seen")]
    SightingLastSeenBeforeFirstSeen,
    /// A `sighting` `where_sighted_refs` entry is not an identity or location id.
    #[error("where_sighted_refs must reference identity or location objects")]
    SightingWhereSightedRefInvalid,
}
