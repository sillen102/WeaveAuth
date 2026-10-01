//! Shared support for the cross-service integration tests under `tests/`,
//! which need `backend` and `bff` linked into the same test binary (a Cargo
//! test under either crate's own `tests/` can't see the other crate). A
//! library rather than a `mod support;` in each test: every test target
//! compiles its own copy of such a module, and would see the parts it
//! doesn't use as dead code.

pub mod support;
