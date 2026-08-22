//! Coppice POC: strict envelope and deterministic replay. No consensus code is modified.
pub mod bond;
pub mod carrier;
pub mod config;
pub mod constants;
pub mod envelope;
pub mod incremental;
pub mod ironwood;
pub mod name_tree;
pub mod owner;
pub mod replay;
pub mod spent;
pub mod state;

pub const DOMAIN: &[u8] = constants::PROTOCOL_ID;
