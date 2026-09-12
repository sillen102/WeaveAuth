use std::sync::LazyLock;

use argon2::Argon2;

/// Shared, lazily-built Argon2 instance -- constructing one just fills in
/// algorithm/version/params (no expensive setup), but there's no reason for
/// every hash/verify call site to build its own copy.
pub(crate) static ARGON2: LazyLock<Argon2<'static>> = LazyLock::new(Argon2::default);