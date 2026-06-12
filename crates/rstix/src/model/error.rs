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
}
