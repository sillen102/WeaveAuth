//! Support for the system tests: the real Ory stack and a stand-in browser to drive it.

pub mod browser;
pub mod edge;
pub mod flows;
pub mod idp;
pub mod stack;
pub mod stubs;

pub use stack::{Options, Stack};
use std::sync::OnceLock;

static STACK: OnceLock<Result<Stack, String>> = OnceLock::new();

/// Runs when the test binary exits, so no container outlives the run.
#[dtor::dtor(unsafe)]
fn remove_containers() {
    stack::cleanup();
}

/// The stack shared by every test of this binary, started on first use. It lives on a runtime of
/// its own: a test's runtime ends with the test, and the servers must outlive it.
pub async fn shared(options: Options) -> &'static Stack {
    let result =
        tokio::task::spawn_blocking(move || STACK.get_or_init(|| start_on_own_runtime(options)))
            .await
            .expect("stack start-up task");
    match result {
        Ok(stack) => stack,
        Err(error) => panic!("the stack did not start: {error}"),
    }
}

fn start_on_own_runtime(options: Options) -> Result<Stack, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let started = runtime
            .block_on(Stack::start(options))
            .map_err(|error| format!("{error:#}"));
        let _ = tx.send(started);
        // Keeps the in-process servers running for the rest of the process.
        runtime.block_on(std::future::pending::<()>());
    });
    rx.recv().map_err(|e| e.to_string())?
}
