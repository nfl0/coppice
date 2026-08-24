//! Generic deterministic application-runtime primitives for Zcash.
//!
//! This crate defines runtime and routing identities. It does not define any
//! application protocol or wallet policy.

#![forbid(unsafe_code)]

pub mod application;
mod hash;
pub mod identity;
