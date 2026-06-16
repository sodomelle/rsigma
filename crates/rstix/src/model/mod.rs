//! STIX 2.1 data model: typed objects and the common property structures they
//! share.
//!
//! This module is being built incrementally across Phase 2. It currently
//! provides the common property containers (`common`), Meta objects (`meta`),
//! and SRO objects (`sro`); typed SCO/SDO objects, `StixObject` dispatch, and
//! `Bundle` parsing land in later work.

pub mod common;
mod error;
pub mod meta;
pub mod sro;
#[cfg(feature = "serde")]
pub(crate) mod type_check;

pub use error::ModelError;
pub use meta::MetaObject;
pub use sro::SroObject;
