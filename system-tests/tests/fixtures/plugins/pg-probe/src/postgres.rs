//! Just enough of the Postgres v3 wire protocol to prove the socket
//! capability works against a real server: start a session, run statements,
//! read the result tags.
//!
//! Deliberately minimal -- no TLS negotiation, no password authentication
//! (the test server runs `trust`), no prepared statements, no typed row
//! decoding. The point is that the *protocol* lives in the plugin and
//! WeaveAuth only moved bytes.

use extism_pdk::*;

use weaveauth_plugin_sdk::sockets::Socket;

const PROTOCOL_VERSION: i32 = 196_608; // 3.0

/// One message off the wire: a tag byte and its payload.
struct Message {
    tag: u8,
    body: Vec<u8>,
}

pub struct Session<'a> {
    socket: &'a Socket,
}

impl<'a> Session<'a> {
    /// Sends the startup message and waits for the server to be ready.
    /// Only done on a `fresh` connection -- a pooled one is already past
    /// this point, and repeating it would confuse the server.
    pub fn start(socket: &'a Socket, user: &str, database: &str) -> Result<Self, Error> {
        let mut body = Vec::new();
        body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        for (key, value) in [("user", user), ("database", database)] {
            body.extend_from_slice(key.as_bytes());
            body.push(0);
            body.extend_from_slice(value.as_bytes());
            body.push(0);
        }
        body.push(0);

        // The startup message is the one message with no tag byte.
        let mut startup = Vec::new();
        startup.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        startup.extend_from_slice(&body);
        socket.write(&startup)?;

        let session = Self { socket };
        loop {
            let message = session.read_message()?;
            match message.tag {
                // AuthenticationOk is the only auth exchange supported here.
                b'R' => match message.body.get(..4) {
                    Some([0, 0, 0, 0]) => continue,
                    _ => return Err(Error::msg("server asked for authentication this plugin can't do")),
                },
                b'E' => return Err(Error::msg(error_text(&message.body))),
                b'Z' => return Ok(session),
                _ => continue,
            }
        }
    }

    /// Adopts a pooled connection that is already past startup and idle at
    /// `ReadyForQuery`.
    pub fn resume(socket: &'a Socket) -> Self {
        Self { socket }
    }

    /// Runs one simple-query statement and returns its command tag (e.g.
    /// `INSERT 0 1`), leaving the connection idle at `ReadyForQuery` so it
    /// is safe to pool.
    pub fn query(&self, sql: &str) -> Result<String, Error> {
        let mut message = vec![b'Q'];
        message.extend_from_slice(&((sql.len() + 5) as i32).to_be_bytes());
        message.extend_from_slice(sql.as_bytes());
        message.push(0);
        self.socket.write(&message)?;

        let mut tag = String::new();
        let mut failure = None;
        loop {
            let message = self.read_message()?;
            match message.tag {
                b'C' => tag = cstr(&message.body),
                b'E' => failure = Some(error_text(&message.body)),
                // Drain to ReadyForQuery even on failure: stopping early
                // would leave bytes on the wire and make the connection
                // unsafe to reuse.
                b'Z' => break,
                _ => continue,
            }
        }

        match failure {
            Some(failure) => Err(Error::msg(failure)),
            None => Ok(tag),
        }
    }

    fn read_message(&self) -> Result<Message, Error> {
        let header = self.socket.read_exact(5)?;
        let tag = *header.first().ok_or_else(|| Error::msg("truncated message header"))?;
        let length = i32::from_be_bytes([
            *header.get(1).ok_or_else(|| Error::msg("truncated length"))?,
            *header.get(2).ok_or_else(|| Error::msg("truncated length"))?,
            *header.get(3).ok_or_else(|| Error::msg("truncated length"))?,
            *header.get(4).ok_or_else(|| Error::msg("truncated length"))?,
        ]);

        let remaining = usize::try_from(length - 4).map_err(|_| Error::msg("negative message length"))?;
        let body = if remaining == 0 { Vec::new() } else { self.socket.read_exact(remaining)? };
        Ok(Message { tag, body })
    }
}

/// Pulls the human-readable text out of an ErrorResponse, which is a series
/// of NUL-terminated `<field-code><value>` pairs.
fn error_text(body: &[u8]) -> String {
    let mut rest = body;
    while let Some((&code, tail)) = rest.split_first() {
        if code == 0 {
            break;
        }
        let end = tail.iter().position(|byte| *byte == 0).unwrap_or(tail.len());
        let (value, tail) = tail.split_at(end);
        if code == b'M' {
            return String::from_utf8_lossy(value).into_owned();
        }
        rest = tail.get(1..).unwrap_or_default();
    }
    "postgres reported an error".to_string()
}

fn cstr(body: &[u8]) -> String {
    let end = body.iter().position(|byte| *byte == 0).unwrap_or(body.len());
    String::from_utf8_lossy(body.get(..end).unwrap_or_default()).into_owned()
}
