//! Starts a plugin as its own user:
//! `weaveauth-plugin-exec <uid> <gid> <command> [args...]`.
//!
//! The only binary in the image with `CAP_SETUID`/`CAP_SETGID`, so backend
//! itself holds no capabilities: a compromised backend, bff or login (all
//! running as `weaveauth`) can reach a plugin's user through this, but never
//! root, because uid and gid 0 are refused here.
//! Backend spawns it with the plugin's environment and connection already in
//! place, and it execs the plugin in its own process, so the plugin's parent
//! is still backend.
//!
//! The image installs it `root:weaveauth 0710`: only backend's user can run
//! it, so a plugin can't use it to become another plugin's user or backend's.

use std::ffi::OsString;
use std::fmt;
use std::process::ExitCode;

const USAGE: &str = "usage: weaveauth-plugin-exec <uid> <gid> <command> [args...]";

#[derive(Debug, PartialEq, Eq)]
struct Spec {
    uid: u32,
    gid: u32,
    command: OsString,
    args: Vec<OsString>,
}

#[derive(Debug, PartialEq, Eq)]
enum ParseError {
    Usage,
    NotAnId(OsString),
    Root,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => write!(formatter, "{USAGE}"),
            Self::NotAnId(raw) => write!(formatter, "{raw:?} is not a numeric uid/gid ({USAGE})"),
            Self::Root => write!(formatter, "refusing to run a plugin as uid or gid 0"),
        }
    }
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Spec, ParseError> {
    let mut args = args.into_iter();
    let uid = id(args.next().ok_or(ParseError::Usage)?)?;
    let gid = id(args.next().ok_or(ParseError::Usage)?)?;
    let command = args.next().ok_or(ParseError::Usage)?;
    if uid == 0 || gid == 0 {
        return Err(ParseError::Root);
    }
    Ok(Spec {
        uid,
        gid,
        command,
        args: args.collect(),
    })
}

fn id(raw: OsString) -> Result<u32, ParseError> {
    raw.to_str()
        .and_then(|text| text.parse().ok())
        .ok_or(ParseError::NotAnId(raw))
}

fn main() -> ExitCode {
    let spec = match parse(std::env::args_os().skip(1)) {
        Ok(spec) => spec,
        Err(error) => {
            eprintln!("weaveauth-plugin-exec: {error}");
            return ExitCode::from(2);
        }
    };
    // Only returns if the plugin could not be started.
    eprintln!("weaveauth-plugin-exec: {}", exec(spec));
    ExitCode::from(126)
}

#[cfg(target_os = "linux")]
fn exec(spec: Spec) -> String {
    use std::os::unix::process::CommandExt;

    const NEEDS: &str = "this needs CAP_SETUID and CAP_SETGID: check for no-new-privileges, \
                         --cap-drop or capabilities.drop: [ALL]";

    let Spec {
        uid,
        gid,
        command,
        args,
    } = spec;
    // Setting a uid also makes std clear the supplementary groups, so the
    // plugin doesn't keep group read access to backend's files (its config).
    let error = std::process::Command::new(&command)
        .args(&args)
        .uid(uid)
        .gid(gid)
        .exec();
    format!("could not start {command:?} as uid {uid}/gid {gid}: {error} ({NEEDS})")
}

#[cfg(not(target_os = "linux"))]
fn exec(spec: Spec) -> String {
    let Spec {
        uid,
        gid,
        command,
        args,
    } = spec;
    format!("cannot start {command:?} {args:?} as uid {uid}/gid {gid}: only supported on Linux")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(raw: &[&str]) -> Vec<OsString> {
        raw.iter().map(OsString::from).collect()
    }

    // The positive control for the refusals below.
    #[test]
    fn parses_the_ids_the_command_and_its_arguments() {
        let spec = parse(args(&["1001", "1002", "/plugins/register", "--verbose"])).expect("valid");

        assert_eq!(
            spec,
            Spec {
                uid: 1001,
                gid: 1002,
                command: "/plugins/register".into(),
                args: args(&["--verbose"])
            }
        );
    }

    // The whole reason the helper exists rather than backend holding the
    // capabilities: whatever calls it can't become root through it.
    #[test]
    fn refuses_uid_0() {
        assert_eq!(
            parse(args(&["0", "1001", "/plugins/register"])),
            Err(ParseError::Root)
        );
    }

    #[test]
    fn refuses_gid_0() {
        assert_eq!(
            parse(args(&["1001", "0", "/plugins/register"])),
            Err(ParseError::Root)
        );
    }

    #[test]
    fn refuses_an_id_that_is_not_a_number() {
        assert_eq!(
            parse(args(&["root", "1001", "/plugins/register"])),
            Err(ParseError::NotAnId("root".into()))
        );
    }

    #[test]
    fn refuses_a_missing_command() {
        assert_eq!(parse(args(&["1001", "1001"])), Err(ParseError::Usage));
    }
}
