//! How a program working on a person's behalf asks for what only the
//! person can give.
//!
//! An AI agent, or any other program, can read a workspace and sort it by
//! itself, through the command line or the MCP server. A signature is
//! different: it takes the PIN of a YubiKey and a touch, and the PIN is
//! never given to a program. So whatever needs one is not done by the
//! program at all. It is handed to the app, which shows its own dialog
//! with what is asked and who asks; the person checks it, types the PIN
//! and touches the key, and the program is told how it went. The same goes
//! for what destroys something.
//!
//! The app listens on a socket in its own folder, which only its user can
//! reach. One line of JSON asks; lines of JSON answer: that the request
//! waits its turn or is shown, and in the end how it went. A program can
//! ask the app to show a dialog and nothing more: what is signed is
//! decided by whoever sits at the window.
//!
//! The person is never interrupted. A request that arrives while they are
//! in the middle of something waits until they are done, and one whose
//! program has gone away in the meantime is dropped: the connection is the
//! request, and closing it takes the request back.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::device::CaRole;
use crate::{ExportForm, LeafProfile};

/// The name the app goes by on its system: the identifier of its bundle,
/// and the name of its folder among its user's application data. It stays
/// what it is once a release is out: an app under another name would not
/// find what this one left, nor be found by the `yca` command of before.
pub const APP_IDENTIFIER: &str = "io.github.yca-app.yca";

/// Where the app listens for programs that ask on a person's behalf.
/// `None` where that folder cannot be told.
pub fn socket_path() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let data = if cfg!(target_os = "macos") {
        home.join("Library/Application Support")
    } else {
        match std::env::var_os("XDG_DATA_HOME") {
            Some(data) => PathBuf::from(data),
            None => home.join(".local/share"),
        }
    };
    Some(data.join(APP_IDENTIFIER).join("agent.sock"))
}

/// What a program asks the app to put before the person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    /// Told back with every answer, to tell requests apart.
    pub id: String,
    /// Who asks, in the words the program gave for itself. Shown to the
    /// person; it is a claim, not a proof.
    pub from: String,
    /// The workspace it is about. The app opens it if another one is open.
    pub workspace: Option<String>,
    pub ask: Ask,
}

/// The things only a person at the window can do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum Ask {
    /// A new certificate with a new key.
    Issue {
        profile: LeafProfile,
        names: Vec<String>,
        /// What the device's upload form asks for, which decides the
        /// files that are written.
        #[serde(default)]
        files: ExportForm,
        #[serde(default)]
        days: Option<u32>,
        #[serde(default)]
        key: KeyKind,
        #[serde(default)]
        p12_compatible: bool,
        #[serde(default)]
        sign_with_root: bool,
        #[serde(default)]
        group: Option<String>,
    },
    /// A certificate for a request (CSR) a device made.
    SignRequest {
        csr_path: String,
        profile: LeafProfile,
        /// The names to certify; none means those the device asked for.
        #[serde(default)]
        names: Vec<String>,
        /// What the device's upload form asks for. There is no private
        /// key to hand over, so not everything in one `.p12` file.
        #[serde(default)]
        files: ExportForm,
        #[serde(default)]
        days: Option<u32>,
        #[serde(default)]
        sign_with_root: bool,
        #[serde(default)]
        group: Option<String>,
    },
    /// A certificate issued again for the key of an existing one.
    Reissue {
        serial: String,
        /// New names; none keeps the names as they are.
        #[serde(default)]
        names: Vec<String>,
        #[serde(default)]
        days: Option<u32>,
        #[serde(default)]
        revoke_old: bool,
    },
    /// The revocation list of one CA.
    SignList { role: CaRole },
    /// A certificate deleted from the register, its private key with it.
    Delete { serial: String },
    /// The wizard that creates a certificate authority on YubiKeys: a new
    /// one, or an issuing CA for the workspace that is open.
    Setup {
        #[serde(default)]
        issuing: bool,
    },
}

/// The kind of key a new certificate gets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyKind {
    #[default]
    Rsa,
    Ecdsa,
}

/// What the app says to a request: first where it stands, later how it
/// ended.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum Reply {
    /// The person is in the middle of something else; the request is
    /// shown once they are done with it.
    Queued,
    /// The dialog is up; the person has not decided yet.
    Shown,
    /// Done, with what came of it.
    Done { result: serde_json::Value },
    /// The person closed the dialog without doing it.
    Declined,
    /// It could not be done, or not be shown.
    Failed { message: String },
}

impl Reply {
    /// Whether anything more follows this answer.
    pub fn is_final(&self) -> bool {
        !matches!(self, Reply::Queued | Reply::Shown)
    }
}

#[cfg(unix)]
pub use desk::Desk;

#[cfg(unix)]
mod desk {
    use std::io::{BufRead, BufReader, ErrorKind, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::Duration;

    use super::{Reply, Request};
    use crate::Error;

    /// A request that is with the app, and the line its answers come on.
    #[derive(Debug)]
    pub struct Desk {
        answers: BufReader<UnixStream>,
        // What has arrived of an answer that is not whole yet.
        partial: String,
    }

    impl Desk {
        /// Hands a request to the app that listens at `socket`. Fails if no
        /// app does.
        pub fn ask(socket: &Path, request: &Request) -> Result<Self, Error> {
            let mut stream = UnixStream::connect(socket).map_err(|e| {
                Error::Store(format!(
                    "the app is not listening at {}: {e}",
                    socket.display()
                ))
            })?;
            let mut line = serde_json::to_string(request)
                .map_err(|e| Error::Store(format!("could not encode the request: {e}")))?;
            line.push('\n');
            stream
                .write_all(line.as_bytes())
                .map_err(|e| Error::Store(format!("could not reach the app: {e}")))?;
            Ok(Self {
                answers: BufReader::new(stream),
                partial: String::new(),
            })
        }

        /// Waits for the app's next answer, for as long as `patience`
        /// lasts. `None` if none came in that time; the request stays
        /// with the app and can be waited for again.
        pub fn wait(&mut self, patience: Duration) -> Result<Option<Reply>, Error> {
            let gone = |e| Error::Store(format!("the app stopped answering: {e}"));
            // An app that has said its last word and hung up leaves a
            // socket that takes no setting any more, on macOS at least.
            // What it said is still there to be read, and reading it does
            // not wait, so that is no reason to stop.
            let _ = self.answers.get_ref().set_read_timeout(Some(patience));
            match self.answers.read_line(&mut self.partial) {
                Ok(0) => Err(Error::Store(
                    "the app closed the request without an answer".to_owned(),
                )),
                Ok(_) if self.partial.ends_with('\n') => {
                    let line = std::mem::take(&mut self.partial);
                    serde_json::from_str(line.trim()).map(Some).map_err(|e| {
                        Error::Store(format!("the app gave an answer yca cannot read: {e}"))
                    })
                }
                // Out of patience in the middle of a line: the rest comes
                // with the next wait.
                Ok(_) => Ok(None),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    Ok(None)
                }
                Err(e) => Err(gone(e)),
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_request_reads_the_way_the_window_spells_it() {
        let request: Request = serde_json::from_str(
            r#"{"id":"7","from":"Claude Code","workspace":"/w",
                "ask":{"kind":"issue","profile":"tls-server","names":["nas.home.example"],
                       "files":"p12","p12Compatible":true,"group":"Office"}}"#,
        )
        .unwrap();
        assert_eq!(
            request.ask,
            Ask::Issue {
                profile: LeafProfile::TlsServer,
                names: vec!["nas.home.example".to_owned()],
                files: ExportForm::Pkcs12,
                days: None,
                key: KeyKind::Rsa,
                p12_compatible: true,
                sign_with_root: false,
                group: Some("Office".to_owned()),
            }
        );
        let back = serde_json::to_value(&request).unwrap();
        assert_eq!(back["ask"]["kind"], "issue");
        assert_eq!(back["ask"]["signWithRoot"], false);
        assert_eq!(back["ask"]["files"], "p12");
        assert_eq!(
            serde_json::to_value(Ask::SignList { role: CaRole::Root }).unwrap(),
            serde_json::json!({ "kind": "sign-list", "role": "root" })
        );
        assert_eq!(
            serde_json::from_str::<Reply>(r#"{"state":"failed","message":"no"}"#).unwrap(),
            Reply::Failed {
                message: "no".to_owned()
            }
        );
        assert_eq!(
            serde_json::from_str::<Reply>(r#"{"state":"queued"}"#).unwrap(),
            Reply::Queued
        );
        assert!(!Reply::Queued.is_final());
        assert!(!Reply::Shown.is_final());
        assert!(Reply::Declined.is_final());
    }

    #[test]
    fn a_request_is_answered_twice_first_shown_then_how_it_ended() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        // The app: shows the request at once, and takes its time over it.
        let app = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut lines = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            lines.read_line(&mut line).unwrap();
            let request: Request = serde_json::from_str(&line).unwrap();
            let mut stream = stream;
            writeln!(stream, r#"{{"state":"shown"}}"#).unwrap();
            std::thread::sleep(Duration::from_millis(250));
            // The answer need not come in one piece.
            write!(stream, r#"{{"state":"done","#).unwrap();
            stream.flush().unwrap();
            std::thread::sleep(Duration::from_millis(100));
            writeln!(stream, r#""result":{{"serial":"ab12"}}}}"#).unwrap();
            request
        });

        let request = Request {
            id: "1".to_owned(),
            from: "a test".to_owned(),
            workspace: None,
            ask: Ask::Delete {
                serial: "ab12".to_owned(),
            },
        };
        let mut desk = Desk::ask(&socket, &request).unwrap();
        assert_eq!(
            desk.wait(Duration::from_secs(5)).unwrap(),
            Some(Reply::Shown)
        );
        // The person has not decided yet.
        assert_eq!(desk.wait(Duration::from_millis(50)).unwrap(), None);
        let ended = loop {
            if let Some(reply) = desk.wait(Duration::from_millis(60)).unwrap() {
                break reply;
            }
        };
        assert_eq!(
            ended,
            Reply::Done {
                result: serde_json::json!({ "serial": "ab12" })
            }
        );
        assert_eq!(app.join().unwrap(), request);
        // The app is gone: no more answers, and nobody to ask.
        assert!(desk.wait(Duration::from_millis(50)).is_err());
        drop(dir);
        assert!(Desk::ask(&socket, &request).is_err());
    }
}
