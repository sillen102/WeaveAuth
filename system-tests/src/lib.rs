//! Cross-service system tests: the real Ory Kratos and Hydra (testcontainers) with hooks, bff and
//! login in-process. The tests live in `tests/` and need the `docker` feature.

#[cfg(feature = "docker")]
pub mod support;
