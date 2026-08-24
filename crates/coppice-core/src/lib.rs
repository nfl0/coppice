//! Generic deterministic application-runtime primitives for Zcash.
//!
//! This crate defines runtime and routing identities. It does not define any
//! application protocol or wallet policy.

#![forbid(unsafe_code)]

pub mod application;
pub mod carrier;
mod hash;
pub mod identity;
pub mod replay;
