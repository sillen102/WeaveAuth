#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    clippy::unnecessary_unwrap,
    clippy::redundant_clone,
    clippy::todo,
    clippy::unimplemented
)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod config;
pub(crate) mod crypto;
pub(crate) mod model;
pub(crate) mod oidc;
pub(crate) mod plugin;
pub mod server;
pub(crate) mod storage;
