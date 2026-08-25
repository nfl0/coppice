//! Public Coppice deterministic application-runtime facade.
//!
//! Coppice is application-blind. Names and other protocols live in external
//! application repositories and consume these Core/runtime APIs.

#![forbid(unsafe_code)]

pub use coppice_core::*;

/// Small deterministic test support for application authors.
pub mod testkit;
