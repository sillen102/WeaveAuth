//! No library code -- this crate exists only to host cross-service
//! integration tests under `tests/`, which need `backend` and `bff` linked
//! into the same test binary (a Cargo test under either crate's own
//! `tests/` can't see the other crate).
