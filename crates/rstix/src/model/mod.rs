//! STIX 2.1 data model: typed objects and the common property structures they
//! share.
//!
//! This module is being built incrementally across Phase 2. It currently
//! provides the common property containers (`common`) and Meta objects (`meta`)
//! shared by every STIX object family; the remaining typed object enums and
//! `Bundle` land in later Phase 2 work.

pub mod common;
mod error;
pub mod meta;

pub use error::ModelError;
pub use meta::MetaObject;
