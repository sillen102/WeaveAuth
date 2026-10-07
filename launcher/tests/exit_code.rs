use std::os::unix::fs::PermissionsExt;
use std::process::Command;

/// Serializes the tests: exec-ing a script while another thread still holds it open for
/// writing fails with `ETXTBSY`.
static EXEC: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Fake services on `PATH`: hooks exits with `hooks_code`, the others run until killed.
fn launcher_exit_code(hooks_code: i32) -> Option<i32> {
    let _guard = EXEC.lock().unwrap_or_else(|e| e.into_inner());
    let dir =
        std::env::temp_dir().join(format!("launcher-test-{hooks_code}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, script) in [
        ("weaveauth-hooks", format!("#!/bin/sh\nexit {hooks_code}\n")),
        ("weaveauth-bff", "#!/bin/sh\nexec sleep 30\n".to_string()),
        ("weaveauth-login", "#!/bin/sh\nexec sleep 30\n".to_string()),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let status = Command::new(env!("CARGO_BIN_EXE_weaveauth-launcher"))
        .env("PATH", format!("{}:/bin:/usr/bin", dir.display()))
        .status()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    status.code()
}

#[test]
fn a_service_that_exits_zero_still_ends_the_container_with_a_failure() {
    assert_eq!(launcher_exit_code(0), Some(1));
}

#[test]
fn a_service_failure_code_is_passed_on() {
    assert_eq!(launcher_exit_code(3), Some(3));
}
