//! `yca mcp`: the workspace for an AI agent, over the Model Context
//! Protocol.
//!
//! An agent that is given this server can look at a workspace and at the
//! connected YubiKeys, sort certificates into groups and mark them as
//! revoked by itself: the same things, through the same core, that a
//! person does in the window. What takes a signature it cannot do and is
//! not meant to. A YubiKey signs for a PIN and a touch, and the PIN is
//! never given to a program. So those tools hand the request to the app
//! (`yca_core::agent`): its window shows what is asked and who asks, the
//! person types the PIN and touches the key, and the agent is told how it
//! went. There is no tool that takes a PIN, a PUK or a password, and none
//! that resets a YubiKey.
//!
//! The protocol is JSON-RPC, one message per line, requests on standard
//! input and answers on standard output. Only tools are served.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use time::OffsetDateTime;
use yca_core::agent::{self, Ask, Desk, Reply, Request};
use yca_core::device;
use yca_core::{ExportForm, P12Encryption, Repack, Store, view};

/// The revisions of the protocol this server speaks, newest first.
const VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// How long one call waits for the person at the window. Shorter than the
/// minute after which programs tend to give up on a tool; a person who
/// takes longer is waited for with another call.
const PATIENCE: Duration = Duration::from_secs(45);

/// The same, or what a test asks for instead so as not to take a minute.
fn patience() -> Duration {
    std::env::var("YCA_AGENT_PATIENCE_MS")
        .ok()
        .and_then(|milliseconds| milliseconds.parse().ok())
        .map_or(PATIENCE, Duration::from_millis)
}

/// What the agent is told about this server before it uses it.
const INSTRUCTIONS: &str = "\
yca keeps a private certificate authority (CA) whose keys live on YubiKeys. \
A workspace is the folder that holds everything about one CA: its \
certificates, their files and the list of what was issued. Tools take the \
workspace folder as an absolute path.

You can look and sort by yourself: list_devices, get_workspace, trust_info, \
set_group, repackage_certificate, revoke_certificate, revoke_replaced_ca, \
adopt_workspace.

A certificate's folder holds exactly the files the upload form of its device \
asks for, chosen with `files`: fullchain (fullchain.crt, which is the \
certificate followed by the intermediate CA, and private-key.key), separate \
(certificate.crt, intermediate-ca.crt and private-key.key) or p12 \
(certificate.p12, everything in one file that opens with a password the \
person chooses). Ask the person what the form looks like if you do not know. \
If it turns out to ask for something else, repackage_certificate writes the \
files again without issuing anything. The root CA certificate is not among \
them; trust_info says where it is.

Whatever needs a signature, deletes something or creates a CA is done by the \
person, not by you: issue_certificate, sign_request, reissue_certificate, \
sign_revocation_list, delete_certificate, open_setup. These show a dialog in \
the CA for YubiKey app with what you asked for. The person checks it, types \
the PIN of the YubiKey and touches the key. Tell them to look at the app's \
window and their YubiKey. If they have not finished when the call returns, \
you get state \"waiting\" and a request_id: call wait_for_request with it. \
The person is never interrupted: if they are in the middle of something in \
the window, your request waits its turn there, and you wait the same way. \
Nothing needs the person as long as you only read, sort or revoke.

Never ask for a PIN, PUK or password, and never offer to enter one: you \
cannot, and the person should not tell you. A revoked certificate is refused \
by devices only once they have a revocation list that names it, so after \
revoking, have the list signed (sign_revocation_list).";

/// Serves until the program at the other end closes standard input.
pub(crate) fn serve() -> Result<()> {
    // Nothing but the protocol may be written to standard output.
    crate::JSON.store(true, Ordering::Relaxed);
    let mut server = Server::default();
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let line = line.context("could not read the request")?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(message) => server.handle(&message),
            Err(_) => Some(failure(Value::Null, -32700, "the message is not JSON")),
        };
        if let Some(reply) = reply {
            writeln!(out, "{reply}")?;
            out.flush()?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct Server {
    /// What the program at the other end calls itself; what the person is
    /// shown as the one who asks.
    client: Option<String>,
    /// Requests that are with the person at the window, by their id.
    waiting: HashMap<String, Desk>,
    /// How many requests were handed over, to tell them apart.
    handed: u64,
}

fn failure(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

impl Server {
    /// Answers one message; `None` for one that wants no answer.
    fn handle(&mut self, message: &Value) -> Option<Value> {
        let method = message.get("method").and_then(Value::as_str);
        // A message without an id is a notification: nothing to answer.
        let id = message.get("id").cloned()?;
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let result = match method {
            Some("initialize") => {
                self.client = params["clientInfo"]["name"]
                    .as_str()
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty());
                let asked = params["protocolVersion"].as_str().unwrap_or_default();
                // The revision the program asks for if this server knows
                // it, its own newest otherwise.
                let version = if VERSIONS.contains(&asked) {
                    asked
                } else {
                    VERSIONS[0]
                };
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "yca",
                        "title": "CA for YubiKey",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "instructions": INSTRUCTIONS,
                })
            }
            Some("ping") => json!({}),
            Some("tools/list") => json!({ "tools": tools() }),
            Some("tools/call") => {
                let name = params["name"].as_str().unwrap_or_default().to_owned();
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                // A tool that fails says so in its result, where the agent
                // reads it, rather than as an error of the protocol.
                match self.call(&name, &arguments) {
                    Ok(value) => json!({
                        "content": [{ "type": "text", "text": pretty(&value) }],
                        "isError": false,
                    }),
                    Err(error) => json!({
                        "content": [{ "type": "text", "text": format!("{error:#}") }],
                        "isError": true,
                    }),
                }
            }
            Some(_) => return Some(failure(id, -32601, "this server does not know that method")),
            None => return Some(failure(id, -32600, "the message names no method")),
        };
        Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }

    fn call(&mut self, tool: &str, arguments: &Value) -> Result<Value> {
        match tool {
            "list_devices" => {
                let workspace = optional_folder(arguments)?;
                let found = device::list_devices()?;
                Ok(serde_json::to_value(view::devices(
                    found,
                    workspace.as_deref(),
                ))?)
            }
            "get_workspace" => get_workspace(arguments),
            "trust_info" => {
                let store = Store::open(folder(arguments)?)?;
                let prints = store.ca_fingerprints(device::CaRole::Root)?;
                Ok(json!({
                    "file": store.root_for_devices()?.to_string_lossy(),
                    "sha256": prints.sha256,
                    "sha1": prints.sha1,
                    "how": "Install the file on the computer or phone as a trusted root \
                            certificate. It is not a secret. The app's menu of the root CA \
                            has the steps for macOS, Windows, iPhone and Android.",
                }))
            }
            "adopt_workspace" => {
                let dir = folder(arguments)?;
                crate::adopt(
                    &dir,
                    device_serial(arguments, "root_device")?,
                    device_serial(arguments, "issuing_device")?,
                )?;
                Ok(serde_json::to_value(view::workspace(&Store::open(&dir)?)?)?)
            }
            "set_group" => {
                let mut store = Store::open(folder(arguments)?)?;
                let group = arguments["group"].as_str();
                // Every certificate is found before any is moved.
                let mut found = Vec::new();
                for serial in strings(arguments, "serials")? {
                    found.push(store.find(&serial)?.serial.clone());
                }
                if found.is_empty() {
                    bail!("name at least one certificate in `serials`");
                }
                let now = OffsetDateTime::now_utc();
                let mut moved = Vec::new();
                for serial in &found {
                    let record = store.set_group(serial, group)?.clone();
                    moved.push(view::certificate_view(&store, &record, now));
                }
                Ok(json!({ "certificates": moved }))
            }
            "revoke_certificate" => {
                let mut store = Store::open(folder(arguments)?)?;
                let now = OffsetDateTime::now_utc();
                let record = store.revoke(&text(arguments, "serial")?, now)?.clone();
                Ok(json!({
                    "certificate": view::certificate_view(&store, &record, now),
                    "next": format!(
                        "Devices refuse it only once they have a revocation list that names it: \
                         have the {}'s list signed with sign_revocation_list and installed on \
                         the devices that check certificates.",
                        record.issued_by
                    ),
                }))
            }
            "revoke_replaced_ca" => {
                let dir = folder(arguments)?;
                crate::revoke_ca(&dir, arguments["serial"].as_str())?;
                let workspace = view::workspace(&Store::open(&dir)?)?;
                Ok(json!({
                    "retired": workspace.retired,
                    "next": "Devices learn of it from the root CA's revocation list: have it \
                             signed with sign_revocation_list (ca: root).",
                }))
            }
            "repackage_certificate" => {
                let mut store = Store::open(folder(arguments)?)?;
                let record = store.find(&text(arguments, "serial")?)?.clone();
                // Whatever takes a password is the person's to do.
                let form: ExportForm = serde_json::from_value(arguments["files"].clone())
                    .map_err(|_| anyhow!("`files` is fullchain or separate"))?;
                if form == ExportForm::Pkcs12 {
                    bail!(
                        "a .p12 file takes a password, which is the person's to choose: they \
                         do this in the app's window (\"Files in another form…\" in the \
                         certificate's menu) or with `yca repackage`"
                    );
                }
                if store.form(&record) == Some(ExportForm::Pkcs12) {
                    bail!(
                        "its private key is inside a .p12 file, which opens with a password \
                         only the person has: they do this in the app's window (\"Files in \
                         another form…\" in the certificate's menu) or with `yca repackage`"
                    );
                }
                let repacked = store.repackage(
                    &record.serial,
                    Repack {
                        form,
                        opens: None,
                        password: None,
                        encryption: P12Encryption::Modern,
                    },
                )?;
                Ok(json!({
                    "certificate": view::certificate_view(
                        &store,
                        &record,
                        OffsetDateTime::now_utc(),
                    ),
                    "files": repacked.files.iter().map(|file| json!({
                        "name": file.name,
                        "purpose": file.purpose,
                    })).collect::<Vec<_>>(),
                }))
            }
            "issue_certificate" => {
                let ask: Ask = asked("issue", arguments, &[])?;
                self.hand_over(arguments, ask)
            }
            "sign_request" => {
                let ask: Ask = asked("sign-request", arguments, &[("csr_file", "csrPath")])?;
                if matches!(
                    ask,
                    Ask::SignRequest {
                        files: ExportForm::Pkcs12,
                        ..
                    }
                ) {
                    bail!(
                        "a .p12 file holds the private key, which stays in the device that \
                         made the request: `files` is fullchain or separate here"
                    );
                }
                self.hand_over(arguments, ask)
            }
            "reissue_certificate" => {
                let ask: Ask = asked("reissue", arguments, &[])?;
                self.hand_over(arguments, ask)
            }
            "sign_revocation_list" => {
                let ask: Ask = asked("sign-list", arguments, &[("ca", "role")])?;
                self.hand_over(arguments, ask)
            }
            "delete_certificate" => {
                let ask: Ask = asked("delete", arguments, &[])?;
                self.hand_over(arguments, ask)
            }
            "open_setup" => {
                let ask = Ask::Setup {
                    issuing: arguments["issuing_ca_for_open_workspace"]
                        .as_bool()
                        .unwrap_or(false),
                };
                self.hand(None, ask)
            }
            "wait_for_request" => {
                let id = text(arguments, "request_id")?;
                let desk = self.waiting.remove(&id).ok_or_else(|| {
                    anyhow!("no request {id} is waiting; it has ended or was never made")
                })?;
                self.settle(id, desk, true)
            }
            other => bail!("yca has no tool called {other}"),
        }
    }

    /// Hands a request about a workspace to the app.
    fn hand_over(&mut self, arguments: &Value, ask: Ask) -> Result<Value> {
        let workspace = folder(arguments)?;
        // Not worth bothering the person with if the folder is no workspace.
        Store::open(&workspace)?;
        self.hand(Some(workspace), ask)
    }

    fn hand(&mut self, workspace: Option<PathBuf>, ask: Ask) -> Result<Value> {
        self.handed += 1;
        let id = format!("{}-{}", std::process::id(), self.handed);
        let request = Request {
            id: id.clone(),
            from: self
                .client
                .clone()
                .unwrap_or_else(|| "A program".to_owned()),
            workspace: workspace.map(|folder| folder.to_string_lossy().into_owned()),
            ask,
        };
        let desk = reach_the_app(&request)?;
        self.settle(id, desk, false)
    }

    /// Waits for the person, for as long as one call may take, and says
    /// where things stand. `taken` says whether the window has said
    /// before that it has the request.
    fn settle(&mut self, id: String, mut desk: Desk, mut taken: bool) -> Result<Value> {
        let started = Instant::now();
        let patience = patience();
        loop {
            let left = patience.saturating_sub(started.elapsed());
            let reply = if left.is_zero() {
                None
            } else {
                desk.wait(left)?
            };
            match reply {
                // Waiting its turn or before the person's eyes: either
                // way it is with the window now.
                Some(Reply::Queued) | Some(Reply::Shown) => taken = true,
                Some(Reply::Done { result }) => {
                    return Ok(json!({ "state": "done", "result": result }));
                }
                Some(Reply::Declined) => {
                    return Ok(json!({
                        "state": "declined",
                        "message": "The person closed the dialog without doing it. Do not ask \
                                    again unless they tell you to.",
                    }));
                }
                Some(Reply::Failed { message }) => bail!(message),
                None if taken => {
                    self.waiting.insert(id.clone(), desk);
                    return Ok(json!({
                        "state": "waiting",
                        "request_id": id,
                        "message": "The request is with the app's window and the person has not \
                                    finished; if they were in the middle of something else, it \
                                    is shown as soon as they are done. Tell them to look at the \
                                    CA for YubiKey window and their YubiKey, then call \
                                    wait_for_request with this request_id. If you stop waiting, \
                                    the request is taken back.",
                    }));
                }
                None => bail!("the app took the request and said nothing about it; ask again"),
            }
        }
    }
}

/// Reaches the app with a request, starting the app if it is not running.
fn reach_the_app(request: &Request) -> Result<Desk> {
    // A socket named from outside is a stand-in for the app, as in tests:
    // then there is no app to start either.
    let named = std::env::var_os("YCA_AGENT_SOCKET").map(PathBuf::from);
    let socket = match &named {
        Some(socket) => socket.clone(),
        None => agent::socket_path()
            .ok_or_else(|| anyhow!("this system has no place for the app to listen"))?,
    };
    if let Ok(desk) = Desk::ask(&socket, request) {
        return Ok(desk);
    }
    if named.is_none() && cfg!(target_os = "macos") {
        // Not running: open it, and give it a moment to come up.
        let opened = std::process::Command::new("open")
            .args(["-b", agent::APP_IDENTIFIER])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if opened.is_ok_and(|status| status.success()) {
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(15) {
                std::thread::sleep(Duration::from_millis(500));
                if let Ok(desk) = Desk::ask(&socket, request) {
                    return Ok(desk);
                }
            }
        }
    }
    bail!(
        "The CA for YubiKey app is not running, and this needs the person at its window: a \
         signature takes their PIN and their touch. Ask them to open the app, then try again."
    )
}

/// The request the app is handed, read from a tool's arguments. `renamed`
/// lists the arguments that the agent is offered under a plainer name
/// than the app knows them by.
fn asked(kind: &str, arguments: &Value, renamed: &[(&str, &str)]) -> Result<Ask> {
    let mut ask = serde_json::Map::new();
    ask.insert("kind".to_owned(), json!(kind));
    for (name, value) in arguments.as_object().into_iter().flatten() {
        if name == "workspace" || value.is_null() {
            continue;
        }
        let known_as = renamed
            .iter()
            .find(|(offered, _)| offered == name)
            .map(|(_, known)| (*known).to_owned())
            // The app spells its fields in camelCase.
            .unwrap_or_else(|| camel(name));
        ask.insert(known_as, value.clone());
    }
    serde_json::from_value(Value::Object(ask))
        .map_err(|error| anyhow!("the arguments do not make a request: {error}"))
}

fn camel(name: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in name.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// The workspace as a client is shown it, narrowed down if asked: a
/// workspace with hundreds of certificates is a lot to read in one go.
fn get_workspace(arguments: &Value) -> Result<Value> {
    let store = Store::open(folder(arguments)?)?;
    let mut workspace = view::workspace(&store)?;
    let total = workspace.certificates.len();
    let groups = store.groups();
    if let Some(group) = arguments["group"].as_str() {
        let wanted = store.group_name(group)?;
        workspace
            .certificates
            .retain(|certificate| certificate.group == wanted);
    }
    if let Some(status) = arguments["status"].as_str() {
        workspace
            .certificates
            .retain(|certificate| certificate.status == status);
    }
    if let Some(search) = arguments["search"].as_str() {
        let needle = search.trim().to_lowercase();
        workspace.certificates.retain(|certificate| {
            certificate.serial.starts_with(&needle)
                || certificate
                    .names
                    .iter()
                    .any(|name| name.to_lowercase().contains(&needle))
        });
    }
    let mut value = serde_json::to_value(&workspace)?;
    value["groups"] = json!(groups);
    value["certificatesInWorkspace"] = json!(total);
    Ok(value)
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn text(arguments: &Value, name: &str) -> Result<String> {
    arguments[name]
        .as_str()
        .map(str::to_owned)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("`{name}` is required"))
}

fn strings(arguments: &Value, name: &str) -> Result<Vec<String>> {
    arguments[name]
        .as_array()
        .ok_or_else(|| anyhow!("`{name}` is required, as a list"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("`{name}` is a list of text"))
        })
        .collect()
}

fn device_serial(arguments: &Value, name: &str) -> Result<Option<u32>> {
    match &arguments[name] {
        Value::Null => Ok(None),
        value => value
            .as_u64()
            .and_then(|serial| u32::try_from(serial).ok())
            .map(Some)
            .ok_or_else(|| anyhow!("`{name}` is the serial number of a YubiKey")),
    }
}

/// The workspace folder a tool is about.
fn folder(arguments: &Value) -> Result<PathBuf> {
    optional_folder(arguments)?.ok_or_else(|| {
        anyhow!("`workspace` is required: the workspace folder, as an absolute path")
    })
}

fn optional_folder(arguments: &Value) -> Result<Option<PathBuf>> {
    let Some(given) = arguments["workspace"]
        .as_str()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    else {
        return Ok(None);
    };
    // A home folder is often written the short way.
    let path = match (given.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => Path::new(&home).join(rest),
        _ => PathBuf::from(given),
    };
    if !path.is_absolute() {
        bail!("`workspace` has to be an absolute path, not {given}");
    }
    Ok(Some(path))
}

/// The tools, as the agent is told about them.
fn tools() -> Value {
    let workspace = json!({
        "type": "string",
        "description": "The workspace folder of the CA, as an absolute path.",
    });
    let profile = json!({
        "type": "string",
        "enum": ["tls-server", "ipsec-gateway", "ipsec-client", "tls-client"],
        "description": "What the certificate is for: tls-server for a web server or any TLS \
                        server, ipsec-gateway for a VPN gateway, ipsec-client for a VPN client \
                        (laptop, phone), tls-client for signing in to a server with a certificate.",
    });
    let days = json!({
        "type": "integer",
        "minimum": 1,
        "description": "Expire after this many days. Leave out for as long as possible \
                        (825 days for a tls-server, otherwise as long as the CA itself).",
    });
    let group = json!({
        "type": "string",
        "description": "Group to sort the certificate into, such as a customer or a site. \
                        A group that is not there yet is made.",
    });
    let with_root = json!({
        "type": "boolean",
        "description": "Sign with the root CA instead of the issuing CA. Only for a device \
                        that cannot handle a certificate chain.",
    });
    let serial = json!({
        "type": "string",
        "description": "Serial number of the certificate, or an unambiguous beginning of it.",
    });
    let handed = "Shows a dialog in the CA for YubiKey app; the person checks it there, types \
                  the PIN and touches the YubiKey. Returns state done, declined or waiting.";
    let files_with_key = json!({
        "type": "string",
        "enum": ["fullchain", "separate", "p12"],
        "description": "What the upload form of the device asks for, which decides the files \
                        written into the certificate's folder. fullchain (the default): a \
                        field for the certificate and one for the private key; writes \
                        fullchain.crt (the certificate followed by the intermediate CA) and \
                        private-key.key. separate: a field each for the certificate, the \
                        intermediate CA and the private key; writes certificate.crt, \
                        intermediate-ca.crt and private-key.key. p12: one file and a \
                        password, also what a laptop or phone imports; writes \
                        certificate.p12, whose password the person types in the dialog.",
    });
    let files_without_key = json!({
        "type": "string",
        "enum": ["fullchain", "separate"],
        "description": "What the upload form of the device asks for. fullchain (the default) \
                        writes fullchain.crt, the certificate followed by the intermediate \
                        CA; separate writes certificate.crt and intermediate-ca.crt.",
    });
    let tool = |name: &str,
                title: &str,
                description: String,
                properties: Value,
                required: &[&str],
                hints: Value| {
        json!({
            "name": name,
            "title": title,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
            "annotations": hints,
        })
    };
    let reads = json!({ "readOnlyHint": true, "openWorldHint": false });
    let changes =
        json!({ "readOnlyHint": false, "destructiveHint": false, "openWorldHint": false });
    let destroys =
        json!({ "readOnlyHint": false, "destructiveHint": true, "openWorldHint": false });
    json!([
        tool(
            "list_devices",
            "Connected YubiKeys",
            "The connected YubiKeys and the CA each holds. Reads only and needs no PIN. With a \
             workspace named, says whether each key holds what that workspace expects.".to_owned(),
            json!({ "workspace": workspace }),
            &[],
            reads.clone(),
        ),
        tool(
            "get_workspace",
            "Workspace and its certificates",
            "The CAs of a workspace, how their revocation lists stand, the groups, and the \
             certificates with status, expiry, group and where their files are. Narrow a large \
             workspace down with group, status or search.".to_owned(),
            json!({
                "workspace": workspace,
                "group": { "type": "string", "description": "Only the certificates of this group." },
                "status": {
                    "type": "string",
                    "enum": ["valid", "expires-soon", "revoked", "expired"],
                    "description": "Only the certificates in this state.",
                },
                "search": {
                    "type": "string",
                    "description": "Only certificates with this in one of their names, or whose \
                                    serial number begins with it.",
                },
            }),
            &["workspace"],
            reads.clone(),
        ),
        tool(
            "trust_info",
            "How devices come to trust the CA",
            "The root CA certificate as a file to install on computers and phones that are to \
             trust this CA, and its fingerprints to compare. The file is not a secret.".to_owned(),
            json!({ "workspace": workspace }),
            &["workspace"],
            reads,
        ),
        tool(
            "adopt_workspace",
            "Start a workspace from YubiKeys",
            "Starts a workspace folder from the CAs that are already on the connected YubiKeys, \
             or adds the issuing CA to an existing workspace. Reads the YubiKeys only and needs \
             no PIN. To create a new CA, use open_setup.".to_owned(),
            json!({
                "workspace": workspace,
                "root_device": { "type": "integer", "description": "Serial number of the YubiKey with the root CA, if more than one root is connected." },
                "issuing_device": { "type": "integer", "description": "Serial number of the YubiKey with the issuing CA, if more than one is connected." },
            }),
            &["workspace"],
            changes.clone(),
        ),
        tool(
            "set_group",
            "Sort certificates into a group",
            "Moves certificates into a group, or out of their group. Their folders in the \
             workspace move along. Needs no YubiKey.".to_owned(),
            json!({
                "workspace": workspace,
                "serials": { "type": "array", "items": { "type": "string" }, "description": "Serial numbers of the certificates, or unambiguous beginnings." },
                "group": { "type": ["string", "null"], "description": "The group to move them into. Leave out, or null, to take them out of their group." },
            }),
            &["workspace", "serials"],
            changes.clone(),
        ),
        tool(
            "repackage_certificate",
            "Write a certificate's files in another form",
            "Writes the files of a certificate again in the form another kind of upload form \
             asks for. Nothing is issued and no YubiKey is needed: it is the same certificate \
             and the same key. The folder ends up with the files of the new form and none of \
             the old. Not into or out of a .p12 file, which takes a password: that is the \
             person's to do in the app's window.".to_owned(),
            json!({
                "workspace": workspace,
                "serial": serial,
                "files": files_without_key,
            }),
            &["workspace", "serial", "files"],
            changes.clone(),
        ),
        tool(
            "revoke_certificate",
            "Revoke a certificate",
            "Marks a certificate as revoked. This cannot be undone. Needs no YubiKey, but \
             devices refuse the certificate only once they have a revocation list that names \
             it: follow with sign_revocation_list.".to_owned(),
            json!({ "workspace": workspace, "serial": serial }),
            &["workspace", "serial"],
            destroys.clone(),
        ),
        tool(
            "revoke_replaced_ca",
            "Revoke a replaced issuing CA",
            "Has the root CA revoke an issuing CA that was replaced, for when its YubiKey is in \
             someone else's hands. Every certificate that CA signed is then refused by devices \
             that have the root CA's revocation list. Cannot be undone.".to_owned(),
            json!({
                "workspace": workspace,
                "serial": { "type": "string", "description": "Serial number of the replaced issuing CA's certificate, from get_workspace. Not needed if only one was replaced." },
            }),
            &["workspace"],
            destroys.clone(),
        ),
        tool(
            "issue_certificate",
            "Issue a certificate",
            format!("Asks for a new certificate with a new private key. {handed} The files are \
                     written into the certificate's folder in the workspace."),
            json!({
                "workspace": workspace,
                "profile": profile,
                "names": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Host names or IP addresses for a server or gateway; one name or e-mail address for a client. The first is the main name." },
                "files": files_with_key,
                "days": days,
                "key": { "type": "string", "enum": ["rsa", "ecdsa"], "description": "RSA 2048 works with every device and is the default; ECDSA P-256 is smaller, but some older devices cannot use it." },
                "p12_compatible": { "type": "boolean", "description": "For files p12: encrypt the .p12 the way older systems need it." },
                "sign_with_root": with_root,
                "group": group,
            }),
            &["workspace", "profile", "names"],
            changes.clone(),
        ),
        tool(
            "sign_request",
            "Sign a device's request (CSR)",
            format!("Asks for a certificate for a request file (CSR) made by a device that keeps its own private key. {handed}"),
            json!({
                "workspace": workspace,
                "csr_file": { "type": "string", "description": "The request file, PEM or DER, as an absolute path." },
                "profile": profile,
                "names": { "type": "array", "items": { "type": "string" }, "description": "The names to certify. Leave out to use the names the device asked for." },
                "files": files_without_key,
                "days": days,
                "sign_with_root": with_root,
                "group": group,
            }),
            &["workspace", "csr_file", "profile"],
            changes.clone(),
        ),
        tool(
            "reissue_certificate",
            "Renew a certificate or change its names",
            format!("Asks for a new certificate for the key of an existing one: to renew it, or with names to change what it is for. The device keeps its key; only the new certificate has to be installed. {handed}"),
            json!({
                "workspace": workspace,
                "serial": serial,
                "names": { "type": "array", "items": { "type": "string" }, "description": "New names. Leave out to keep the names: a renewal." },
                "days": days,
                "revoke_old": { "type": "boolean", "description": "Mark the old certificate as revoked. Default false." },
            }),
            &["workspace", "serial"],
            changes.clone(),
        ),
        tool(
            "sign_revocation_list",
            "Sign a revocation list (CRL)",
            format!("Asks for the revocation list of one CA to be signed: the file devices need in order to refuse revoked certificates. {handed}"),
            json!({
                "workspace": workspace,
                "ca": { "type": "string", "enum": ["issuing", "root"], "description": "Whose list: the issuing CA's, or the root CA's, which names what the root signed directly and any revoked issuing CA. A workspace on one YubiKey has only root." },
            }),
            &["workspace", "ca"],
            changes.clone(),
        ),
        tool(
            "delete_certificate",
            "Delete a certificate",
            "Asks the person to delete a certificate from the workspace: its entry and its files, a private key included. Shows a question in the app's window; they agree or not. Deleting does not stop a certificate from working: to do that, revoke it.".to_owned(),
            json!({ "workspace": workspace, "serial": serial }),
            &["workspace", "serial"],
            destroys,
        ),
        tool(
            "open_setup",
            "Open the wizard that creates a CA",
            "Opens the wizard in the app's window in which the person creates a certificate authority on YubiKeys: a new one, or an issuing CA for the workspace that is open there. The person goes through it; it writes to YubiKeys and sets their PINs. Returns as soon as the wizard is open; look at list_devices and get_workspace afterwards.".to_owned(),
            json!({
                "issuing_ca_for_open_workspace": { "type": "boolean", "description": "True to add or replace the issuing CA of the workspace open in the window; false, the default, for a new CA." },
            }),
            &[],
            changes.clone(),
        ),
        tool(
            "wait_for_request",
            "Wait for the person at the window",
            "Waits further for a request that returned state waiting, until the person has signed, declined, or the wait is over again.".to_owned(),
            json!({ "request_id": { "type": "string", "description": "The request_id that came with state waiting." } }),
            &["request_id"],
            changes,
        ),
    ])
}
