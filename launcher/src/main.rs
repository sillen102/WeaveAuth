//! The container's entrypoint: runs backend, bff and login side by side. The
//! runtime image is distroless, so there is no shell to do this in a script.

use std::ffi::OsString;
use std::process::{Child, Command, ExitCode};
use std::time::Duration;

const SERVICES: [&str; 3] = ["weaveauth", "weaveauth-bff", "weaveauth-login"];

const POLL: Duration = Duration::from_millis(200);

/// All three services need to agree on where the login page (not bff, not
/// backend) is publicly reachable. login reads `WA_LOGIN_PUBLIC_URL` itself,
/// and bff (`WA_TRUSTED_ORIGINS`) and backend (`WA_REDIRECT_URI_ALLOWLIST`)
/// default from it -- each still wins if the deployer sets it explicitly.
fn login_public_url(configured: Option<OsString>) -> OsString {
    configured.unwrap_or_else(|| "http://localhost:8081".into())
}

/// Where login reaches bff server-side. bff runs in this same container, so
/// unless the deployer says otherwise that's loopback on bff's own port,
/// never the public `WA_BFF_URL`, which may not route back in from here.
fn bff_internal_url(configured: Option<OsString>, bff_port: Option<OsString>) -> OsString {
    configured.filter(|url| !url.is_empty()).unwrap_or_else(|| {
        let port = bff_port.unwrap_or_else(|| "8080".into());
        let mut url = OsString::from("http://127.0.0.1:");
        url.push(port);
        url
    })
}

// ponytail: no SIGTERM forwarding, so `docker stop` waits out its grace
// period before SIGKILL; run with `docker run --init` if that matters.
fn main() -> ExitCode {
    let url = login_public_url(std::env::var_os("WA_LOGIN_PUBLIC_URL"));
    let bff_url = bff_internal_url(
        std::env::var_os("WA_BFF_INTERNAL_URL"),
        std::env::var_os("WA_BFF_PORT"),
    );

    let mut children: Vec<(&str, Child)> = Vec::new();
    for service in SERVICES {
        let mut command = Command::new(service);
        command.env("WA_LOGIN_PUBLIC_URL", &url);
        if service == "weaveauth-login" {
            command.env("WA_BFF_INTERNAL_URL", &bff_url);
        }
        match command.spawn() {
            Ok(child) => children.push((service, child)),
            Err(error) => {
                eprintln!("launcher: could not start {service}: {error}");
                return stop(children, 1);
            }
        }
    }

    // One service down means the container is broken, so it exits and lets
    // the orchestrator restart all of it.
    loop {
        for (service, child) in &mut children {
            if let Ok(Some(status)) = child.try_wait() {
                eprintln!("launcher: {service} exited with {status}");
                let code = status
                    .code()
                    .and_then(|code| u8::try_from(code).ok())
                    .unwrap_or(1);
                return stop(children, code);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_the_login_public_url_when_unset() {
        assert_eq!(
            login_public_url(None),
            OsString::from("http://localhost:8081")
        );
    }

    #[test]
    fn points_login_at_the_local_bff_when_no_internal_url_is_set() {
        assert_eq!(
            bff_internal_url(None, None),
            OsString::from("http://127.0.0.1:8080")
        );
        assert_eq!(
            bff_internal_url(None, Some("9090".into())),
            OsString::from("http://127.0.0.1:9090")
        );
        // Empty counts as unset, as it does in login itself.
        assert_eq!(
            bff_internal_url(Some("".into()), None),
            OsString::from("http://127.0.0.1:8080")
        );
    }

    #[test]
    fn keeps_a_configured_bff_internal_url() {
        assert_eq!(
            bff_internal_url(Some("http://bff.internal".into()), Some("9090".into())),
            OsString::from("http://bff.internal")
        );
    }

    #[test]
    fn keeps_a_configured_login_public_url() {
        assert_eq!(
            login_public_url(Some("https://login.example".into())),
            OsString::from("https://login.example")
        );
    }
}
