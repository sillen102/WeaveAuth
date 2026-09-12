#![deny(
    dead_code,
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

pub mod config;
pub mod server;
pub(crate) mod crypto;
pub(crate) mod model;
pub(crate) mod storage;
