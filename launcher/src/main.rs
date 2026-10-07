//! The container's entrypoint: runs hooks, bff and login side by side. The
//! runtime image is distroless, so there is no shell to do this in a script.

use std::process::{Child, Command, ExitCode};
use std::time::Duration;

const SERVICES: [&str; 3] = ["weaveauth-hooks", "weaveauth-bff", "weaveauth-login"];

const POLL: Duration = Duration::from_millis(200);

// ponytail: std-only, so no signal handling. As PID 1 it ignores SIGTERM and `docker stop` waits
// out its grace period before SIGKILL; under `docker run --init` SIGTERM ends it and the services
// go with the container. Neither is graceful: the services have no drain either, so in-flight
// requests are cut. Needs a signal crate here and a shutdown hook in each service.
fn main() -> ExitCode {
    let mut children: Vec<(&str, Child)> = Vec::new();
    for service in SERVICES {
        match Command::new(service).spawn() {
            Ok(child) => children.push((service, child)),
            Err(error) => {
                eprintln!("launcher: could not start {service}: {error}");
                return stop(children, 1);
            }
        }
    }

    // One service down means the container is broken, so it exits non-zero (even when the
    // service exited 0) and lets the orchestrator restart all of it.
    loop {
        for (service, child) in &mut children {
            match child.try_wait() {
                Ok(None) => {}
                Ok(Some(status)) => {
                    eprintln!("launcher: {service} exited with {status}");
                    let code = status
                        .code()
                        .and_then(|code| u8::try_from(code).ok())
                        .unwrap_or(1)
                        .max(1);
                    return stop(children, code);
                }
                Err(error) => {
                    eprintln!("launcher: could not check {service}: {error}");
                    return stop(children, 1);
                }
            }
        }
        std::thread::sleep(POLL);
    }
}

fn stop(children: Vec<(&str, Child)>, code: u8) -> ExitCode {
    for (_, mut child) in children {
        let _ = child.kill();
        let _ = child.wait();
    }
    ExitCode::from(code)
}
