#![cfg(unix)]
//! The Google provider overlays and the `start.sh` that renders them. No Docker: `start.sh` runs
//! against a stand-in `kratos` that prints its arguments.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn scope_line(text: &str) -> &str {
    text.lines()
        .find(|line| line.trim_start().starts_with("scope:"))
        .unwrap_or_else(|| panic!("no scope line in {text}"))
        .trim()
}

#[test]
fn the_phone_overlay_asks_for_the_scope_hooks_reads_the_phone_with() {
    let hooks_scope = scope_line(&read("hooks/config.yaml"))
        .trim_start_matches("scope:")
        .trim()
        .to_string();
    let phone = read("ory/kratos/oidc-google-phone.yml");

    assert!(
        scope_line(&phone).contains(&hooks_scope),
        "{hooks_scope} is not in {}",
        scope_line(&phone)
    );
    assert!(!scope_line(&read("ory/kratos/oidc-google.yml")).contains(&hooks_scope));
}

#[test]
fn the_two_overlays_differ_only_in_the_scope() {
    let provider = |path: &str| -> Vec<String> {
        read(path)
            .lines()
            .skip_while(|line| !line.starts_with("selfservice:"))
            .filter(|line| !line.trim_start().starts_with("scope:"))
            .map(str::to_string)
            .collect()
    };

    assert_eq!(
        provider("ory/kratos/oidc-google.yml"),
        provider("ory/kratos/oidc-google-phone.yml")
    );
}

/// A directory of its own holding what `start.sh` reads and writes, with a stand-in `kratos` that
/// prints its arguments.
fn setup(name: &str) -> TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("wa-start-sh-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for file in ["kratos.yml", "oidc-google.yml", "oidc-google-phone.yml"] {
        std::fs::copy(repo().join("ory/kratos").join(file), dir.join(file)).unwrap();
    }
    let fake = dir.join("kratos");
    std::fs::write(&fake, "#!/bin/sh\necho \"kratos $*\"\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    TempDir(dir)
}

struct TempDir(PathBuf);

impl std::ops::Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// Runs a copy of `start.sh` that reads and renders its files in `dir`, loading `overlays`;
/// returns (exit ok, stdout, stderr).
fn start(dir: &Path, overlays: &[&str], id: &str, secret: &str) -> (bool, String, String) {
    let in_dir = format!("{}/", dir.display());
    let script = read("ory/kratos/start.sh")
        .replace("/tmp/", &in_dir)
        .replace("/etc/kratos/", &in_dir);
    std::fs::write(dir.join("start.sh"), script).unwrap();
    let extra: Vec<String> = overlays
        .iter()
        .map(|file| format!("{in_dir}{file}"))
        .collect();
    let out = Command::new("sh")
        .arg(dir.join("start.sh"))
        .env("PATH", format!("{}:/usr/bin:/bin", dir.display()))
        .env("WA_HOOKS_API_KEY", "hook-key")
        .env("KRATOS_CONFIG_EXTRA", extra.join(" "))
        .env("GOOGLE_CLIENT_ID", id)
        .env("GOOGLE_CLIENT_SECRET", secret)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn start_sh_renders_the_phone_overlay_with_the_credentials() {
    let dir = setup("phone");

    let (ok, stdout, stderr) = start(&dir, &["oidc-google-phone.yml"], "id1", "secret1");

    assert!(ok, "{stderr}");
    let rendered = dir.join("2-oidc-google-phone.yml");
    assert!(
        stdout.contains(&format!("-c {}", rendered.display())),
        "{stdout}"
    );
    let rendered = std::fs::read_to_string(rendered).unwrap();
    assert!(rendered.contains("client_id: \"id1\"") && rendered.contains("contacts.readonly"));
}

#[test]
fn start_sh_renders_the_plain_overlay_with_the_credentials() {
    let dir = setup("plain");

    let (ok, stdout, stderr) = start(&dir, &["oidc-google.yml"], "id1", "secret1");

    assert!(ok, "{stderr}");
    assert!(stdout.contains("2-oidc-google.yml"), "{stdout}");
}

#[test]
fn start_sh_refuses_a_google_overlay_without_both_credentials() {
    let dir = setup("credentials");

    for (id, secret) in [("", "secret1"), ("id1", "")] {
        let (ok, _, stderr) = start(&dir, &["oidc-google-phone.yml"], id, secret);
        assert!(
            !ok && stderr.contains("oidc-google-phone.yml is loaded"),
            "{stderr}"
        );
    }
}

#[test]
fn start_sh_refuses_both_google_overlays_in_either_order() {
    let dir = setup("both");

    for overlays in [
        ["oidc-google-phone.yml", "oidc-google.yml"],
        ["oidc-google.yml", "oidc-google-phone.yml"],
    ] {
        let (ok, _, stderr) = start(&dir, &overlays, "id1", "secret1");
        assert!(!ok && stderr.contains("load only one"), "{stderr}");
    }
}
