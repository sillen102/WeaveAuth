//! A WeaveAuth plugin that talks to Postgres over the socket capability,
//! used by the plugin system tests.
//!
//! Only `handle_registration` is exported, because that is all a system
//! test can reach: it drives backend's real `POST /register`. Which
//! behaviour to run is selected by the `probe` extra field, which is itself
//! just an extra registration field -- exactly the mechanism under test.
//!
//! Where the database lives is passed the same way, so a test can point it
//! at whatever port it got.

mod postgres;

use std::collections::HashMap;

use extism_pdk::*;
use serde::Deserialize;
use weaveauth_plugin_sdk::sockets::Socket;

use postgres::Session;

struct Target {
    host: String,
    port: u16,
    user: String,
    database: String,
}

#[derive(Deserialize)]
struct Registration {
    user_id: String,
    email: String,
    fields: HashMap<String, String>,
}

impl Registration {
    fn field(&self, key: &str) -> Result<&str, Error> {
        self.fields.get(key).map(String::as_str).ok_or_else(|| Error::msg(format!("missing field {key}")))
    }

    fn target(&self) -> Result<Target, Error> {
        Ok(Target {
            host: self.field("db_host")?.to_string(),
            port: self.field("db_port")?.parse().map_err(|_| Error::msg("db_port is not a port"))?,
            user: self.field("db_user")?.to_string(),
            database: self.field("db_name")?.to_string(),
        })
    }

    fn insert(&self) -> String {
        format!(
            "insert into profile (user_id, email, company) values ('{}', '{}', '{}')",
            escape(&self.user_id),
            escape(&self.email),
            escape(self.fields.get("company").map(String::as_str).unwrap_or_default()),
        )
    }
}

fn escape(value: &str) -> String {
    value.replace('\'', "''")
}

/// Opens (or reuses) a connection and runs `f`. The error carries whether
/// the connection was freshly dialled, which is what decides if a retry
/// could help.
fn attempt<T>(target: &Target, f: &dyn Fn(&Session) -> Result<T, Error>) -> Result<T, (Error, bool)> {
    let socket = Socket::open(&target.host, target.port, false).map_err(|error| (error, true))?;
    let fresh = socket.fresh;

    let session = if fresh {
        match Session::start(&socket, &target.user, &target.database) {
            Ok(session) => session,
            Err(error) => {
                let _ = socket.release(false);
                return Err((error, fresh));
            }
        }
    } else {
        Session::resume(&socket)
    };

    match f(&session) {
        Ok(value) => match socket.release(true) {
            Ok(()) => Ok(value),
            Err(error) => Err((error, fresh)),
        },
        Err(error) => {
            // Mid-protocol, so the connection is not safe for the next call.
            let _ = socket.release(false);
            Err((error, fresh))
        }
    }
}

/// Runs `f` against a session, retrying once if a *pooled* connection turned
/// out to be dead.
///
/// A connection can be closed by the server while it sits idle in the host's
/// pool -- a restart, an idle timeout, an administrator dropping the backend.
/// The host can't detect that for us: it doesn't know the protocol, so to it
/// a closed socket looks like any other read failure. Releasing the dead one
/// with `reuse: false` drops it from the pool, so the retry dials fresh.
fn with_retry<T>(target: &Target, f: impl Fn(&Session) -> Result<T, Error>) -> Result<T, Error> {
    match attempt(target, &f) {
        Ok(value) => Ok(value),
        Err((_, false)) => attempt(target, &f).map_err(|(error, _)| error),
        Err((error, true)) => Err(error),
    }
}

#[plugin_fn]
pub fn handle_registration(input: String) -> FnResult<()> {
    let registration: Registration = serde_json::from_str(&input)?;
    let target = registration.target()?;

    match registration.fields.get("probe").map(String::as_str).unwrap_or("insert") {
        // The real hook: start or resume a session, insert, release cleanly.
        "insert" => with_retry(&target, |session| session.query(&registration.insert()))?,

        // The same insert with no retry, so a test can see what a plugin
        // that doesn't handle a dead pooled connection actually gets.
        "no_retry" => attempt(&target, &|session| session.query(&registration.insert()))
            .map_err(|(error, _)| error)?,

        // Outlives the host's per-operation socket timeout.
        "slow_query" => with_retry(&target, |session| session.query("select pg_sleep(30)"))?,

        // Opens connections until the host refuses. The count is not
        // reported -- a system test sees only the HTTP status -- so the
        // test counts accepted connections at the server instead.
        "open_limit" => {
            let mut opened = Vec::new();
            loop {
                match Socket::open(&target.host, target.port, false) {
                    Ok(socket) => opened.push(socket),
                    Err(error) => return Err(error.into()),
                }
                if opened.len() > 64 {
                    return Err(Error::msg("the host never refused another connection").into());
                }
            }
        }

        other => return Err(Error::msg(format!("unknown probe {other}")).into()),
    };

    Ok(())
}
