//! Hand-written serde implementations, gated behind the `serde` feature.
//!
//! Layout matches the Phase 2 architecture: bundle/object dispatch, streaming parse, and
//! core type serializers live here rather than beside domain logic. This module
//! hosts plain-string [`StixId`](crate::core::StixId) serialization,
//! precision-preserving timestamp formats, and [`Confidence`](crate::core::Confidence)
//! range validation on deserialize. Typed-ID serde is generated in the
//! [`define_typed_id!`](crate::core::id) macro so the 42-type list stays
//! single-sourced. Later Phase 2 work adds type-discriminated object dispatch,
//! extension-map routing, and streaming readers here.

mod confidence;
mod stix_id;
mod timestamp;
