//! `yca mcp`, driven the way an agent's program drives it: messages in on
//! standard input, answers out on standard output. The app is stood in
//! for by a socket that answers as the window would.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};
use time::OffsetDateTime;
use yca_core::device::CaRole;
use yca_core::{Authority, KeyPair, LeafRequest, PKCS_ECDSA_P256_SHA256, Store};

fn key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
}

/// A workspace with two certificates; gives back their serial numbers.
fn workspace(dir: &Path) -> Vec<String> {
    let at = OffsetDateTime::now_utc();
    let root = Authority::create_root("Test Root CA", key(), at).unwrap();
    let issuing = root.create_issuing("Test Issuing CA", key(), at).unwrap();
    let mut store = Store::create(dir, root.certificate_der(), 1001).unwrap();
    store.set_issuing(issuing.certificate_der(), 1002).unwrap();
    ["nas.acme.example", "printer.home.example"]
        .into_iter()
        .map(|name| {
            let request = LeafRequest::tls_server([name]).unwrap();
            let issued = issuing.issue(&request, &key(), at).unwrap();
            store
                .record(&issued, &request, CaRole::Issuing, None, at)
                .unwrap()
                .serial
                .clone()
        })
        .collect()
}

/// The program at the other end of the server.
struct Agent {
    server: Child,
    to: ChildStdin,
    from: BufReader<ChildStdout>,
    asked: u64,
}

impl Agent {
    fn start(socket: &Path) -> Self {
        let mut server = Command::new(env!("CARGO_BIN_EXE_yca"))
            .arg("mcp")
            .env("YCA_AGENT_SOCKET", socket)
            // One call waits this long for the person, not most of a minute.
            .env("YCA_AGENT_PATIENCE_MS", "150")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let to = server.stdin.take().unwrap();
        let from = BufReader::new(server.stdout.take().unwrap());
        Self {
            server,
            to,
            from,
            asked: 0,
        }
    }

    /// Sends a request and gives back the result, or the error.
    fn ask(&mut self, method: &str, params: Value) -> Value {
        self.asked += 1;
        let message =
            json!({ "jsonrpc": "2.0", "id": self.asked, "method": method, "params": params });
        writeln!(self.to, "{message}").unwrap();
        let mut line = String::new();
        self.from.read_line(&mut line).unwrap();
        let answer: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(answer["id"], self.asked, "{line}");
        answer
    }

    /// Calls a tool; gives back whether it failed and what it said, as
    /// JSON if it is JSON.
    fn call(&mut self, tool: &str, arguments: Value) -> (bool, Value) {
        let answer = self.ask(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        );
        let result = &answer["result"];
        let said = result["content"][0]["text"].as_str().unwrap().to_owned();
        let value = serde_json::from_str(&said).unwrap_or(Value::String(said));
        (result["isError"].as_bool().unwrap(), value)
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

#[test]
fn an_agent_reads_and_sorts_a_workspace_by_itself() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace");
    let serials = workspace(&path);
    let folder = path.to_str().unwrap();
    let mut agent = Agent::start(&dir.path().join("no-app.sock"));

    // It says what it is, and takes the revision it is asked for.
    let hello = agent.ask(
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "Test Agent", "version": "1" },
        }),
    );
    assert_eq!(hello["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(hello["result"]["serverInfo"]["name"], "yca");
    assert!(
        hello["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("Never ask for a PIN")
    );
    // A notification gets no answer; the next answer is the next request's.
    writeln!(
        agent.to,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
    )
    .unwrap();
    assert_eq!(agent.ask("ping", json!({}))["result"], json!({}));
    assert_eq!(
        agent.ask("resources/list", json!({}))["error"]["code"],
        -32601
    );

    // The tools describe themselves; none of them takes a secret.
    let listed = agent.ask("tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    for expected in [
        "get_workspace",
        "issue_certificate",
        "repackage_certificate",
        "revoke_certificate",
        "wait_for_request",
    ] {
        assert!(names.contains(&expected), "{names:?}");
    }
    assert!(
        !names
            .iter()
            .any(|name| name.contains("reset") || name.contains("pin"))
    );
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        let said = tool.to_string().to_lowercase();
        assert!(
            !said.contains("\"pin\"") && !said.contains("\"password\""),
            "{tool}"
        );
    }

    // The workspace, as the window shows it.
    let (failed, seen) = agent.call("get_workspace", json!({ "workspace": folder }));
    assert!(!failed, "{seen}");
    assert_eq!(seen["root"]["subject"], "CN=Test Root CA");
    assert_eq!(seen["certificates"].as_array().unwrap().len(), 2);
    assert_eq!(seen["certificates"][0]["status"], "valid");

    // Sorted into a group, and found by it.
    let (failed, moved) = agent.call(
        "set_group",
        json!({ "workspace": folder, "serials": [serials[0]], "group": "Acme" }),
    );
    assert!(!failed, "{moved}");
    assert_eq!(moved["certificates"][0]["group"], "Acme");
    let moved_to = path.join("certificates/Acme/nas.acme.example");
    assert!(moved_to.is_dir());

    // Its files, written for a form with a field each for the certificate
    // and the intermediate CA. Nothing is issued, and nothing has to be
    // asked of the person.
    let (failed, repacked) = agent.call(
        "repackage_certificate",
        json!({ "workspace": folder, "serial": serials[0], "files": "separate" }),
    );
    assert!(!failed, "{repacked}");
    assert_eq!(repacked["certificate"]["form"], "separate");
    assert_eq!(repacked["certificate"]["hasKey"], false);
    assert_eq!(repacked["files"][0]["name"], "certificate.crt");
    assert_eq!(repacked["files"][1]["name"], "intermediate-ca.crt");
    assert!(moved_to.join("intermediate-ca.crt").is_file());
    let (failed, repacked) = agent.call(
        "repackage_certificate",
        json!({ "workspace": folder, "serial": serials[0], "files": "fullchain" }),
    );
    assert!(!failed, "{repacked}");
    assert!(moved_to.join("fullchain.crt").is_file());
    assert!(!moved_to.join("certificate.crt").exists());
    // One file with a password is the person's to make.
    let (failed, said) = agent.call(
        "repackage_certificate",
        json!({ "workspace": folder, "serial": serials[0], "files": "p12" }),
    );
    assert!(
        failed && said.as_str().unwrap().contains("the person's to choose"),
        "{said}"
    );
    assert!(moved_to.join("fullchain.crt").is_file());
    let (_, seen) = agent.call(
        "get_workspace",
        json!({ "workspace": folder, "group": "acme" }),
    );
    assert_eq!(seen["certificates"].as_array().unwrap().len(), 1);
    assert_eq!(seen["groups"], json!(["Acme"]));
    assert_eq!(seen["certificatesInWorkspace"], 2);

    // Revoked, with what has to follow.
    let (failed, revoked) = agent.call(
        "revoke_certificate",
        json!({ "workspace": folder, "serial": serials[1] }),
    );
    assert!(!failed, "{revoked}");
    assert_eq!(revoked["certificate"]["status"], "revoked");
    assert!(
        revoked["next"]
            .as_str()
            .unwrap()
            .contains("sign_revocation_list")
    );
    let (_, seen) = agent.call(
        "get_workspace",
        json!({ "workspace": folder, "status": "revoked" }),
    );
    assert_eq!(seen["certificates"][0]["names"][0], "printer.home.example");
    assert_eq!(seen["issuing"]["revocation"]["unlisted"], 1);

    // What a device needs in order to trust the CA.
    let (failed, trust) = agent.call("trust_info", json!({ "workspace": folder }));
    assert!(!failed, "{trust}");
    assert!(
        trust["file"]
            .as_str()
            .unwrap()
            .ends_with("Test Root CA.crt")
    );
    assert_eq!(trust["sha256"].as_str().unwrap().split(' ').count(), 32);

    // Mistakes are said in words the agent can act on.
    let (failed, said) = agent.call("get_workspace", json!({ "workspace": "relative/path" }));
    assert!(
        failed && said.as_str().unwrap().contains("absolute"),
        "{said}"
    );
    let (failed, _) = agent.call(
        "revoke_certificate",
        json!({ "workspace": folder, "serial": "ffff" }),
    );
    assert!(failed);
    let (failed, said) = agent.call("reset_yubikey", json!({}));
    assert!(
        failed && said.as_str().unwrap().contains("no tool"),
        "{said}"
    );

    // A signature needs the person: without the app, the agent is told so
    // and nothing is signed.
    let (failed, said) = agent.call(
        "issue_certificate",
        json!({ "workspace": folder, "profile": "tls-server", "names": ["new.home.example"] }),
    );
    assert!(failed, "{said}");
    assert!(said.as_str().unwrap().contains("not running"), "{said}");
}

#[test]
fn what_needs_a_signature_is_handed_to_the_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace");
    let serials = workspace(&path);
    let folder = path.to_str().unwrap().to_owned();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();

    // The window: shows whatever comes, and says it was done.
    let window = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..3 {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let mut stream = stream;
            writeln!(stream, r#"{{"state":"shown"}}"#).unwrap();
            let end = match request["ask"]["kind"].as_str().unwrap() {
                "issue" => {
                    json!({ "state": "done", "result": { "serial": "ab12", "names": request["ask"]["names"] } })
                }
                "delete" => json!({ "state": "declined" }),
                _ => json!({ "state": "failed", "message": "This workspace has no issuing CA." }),
            };
            writeln!(stream, "{end}").unwrap();
            seen.push(request);
        }
        seen
    });

    let mut agent = Agent::start(&socket);
    agent.ask(
        "initialize",
        json!({ "protocolVersion": "1999-01-01", "clientInfo": { "name": "Test Agent" } }),
    );
    let (failed, issued) = agent.call(
        "issue_certificate",
        json!({
            "workspace": folder,
            "profile": "ipsec-client",
            "names": ["alice@example.com"],
            "files": "p12",
            "days": 365,
            "key": "ecdsa",
            "p12_compatible": true,
            "group": "Family",
        }),
    );
    assert!(!failed, "{issued}");
    assert_eq!(issued["state"], "done");
    assert_eq!(issued["result"]["serial"], "ab12");

    let (failed, declined) = agent.call(
        "delete_certificate",
        json!({ "workspace": folder, "serial": serials[0] }),
    );
    assert!(!failed, "{declined}");
    assert_eq!(declined["state"], "declined");

    let (failed, said) = agent.call(
        "sign_revocation_list",
        json!({ "workspace": folder, "ca": "issuing" }),
    );
    assert!(
        failed && said.as_str().unwrap().contains("no issuing CA"),
        "{said}"
    );

    // What cannot be a request never reaches the window.
    let (failed, _) = agent.call(
        "issue_certificate",
        json!({ "workspace": folder, "profile": "nonsense", "names": ["x"] }),
    );
    assert!(failed);
    let (failed, _) = agent.call(
        "issue_certificate",
        json!({ "workspace": folder, "profile": "tls-server", "names": ["x"], "files": "everything" }),
    );
    assert!(failed);
    // A device that made its own key keeps it: nothing to put in a .p12.
    let (failed, said) = agent.call(
        "sign_request",
        json!({ "workspace": folder, "csr_file": "/tmp/device.csr", "profile": "tls-server", "files": "p12" }),
    );
    assert!(
        failed && said.as_str().unwrap().contains("fullchain or separate"),
        "{said}"
    );
    let (failed, _) = agent.call(
        "issue_certificate",
        json!({ "workspace": dir.path().join("elsewhere"), "profile": "tls-server", "names": ["x"] }),
    );
    assert!(failed);

    // The window was told who asks, about which workspace, and for what,
    // in its own words.
    let seen = window.join().unwrap();
    assert_eq!(seen[0]["from"], "Test Agent");
    assert_eq!(seen[0]["workspace"], folder.as_str());
    assert_eq!(
        seen[0]["ask"],
        json!({
            "kind": "issue",
            "profile": "ipsec-client",
            "names": ["alice@example.com"],
            "files": "p12",
            "days": 365,
            "key": "ecdsa",
            "p12Compatible": true,
            "signWithRoot": false,
            "group": "Family",
        })
    );
    assert_eq!(
        seen[1]["ask"],
        json!({ "kind": "delete", "serial": serials[0] })
    );
    assert_eq!(
        seen[2]["ask"],
        json!({ "kind": "sign-list", "role": "issuing" })
    );
    // Nothing in the workspace changed by any of it.
    assert_eq!(Store::open(&path).unwrap().records().len(), 2);
}

#[test]
fn a_person_who_takes_their_time_is_waited_for() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace");
    workspace(&path);
    let folder = path.to_str().unwrap().to_owned();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();

    // The window: busy with something else at first, then showing the
    // request, and signing after longer than one call waits.
    let window = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let mut stream = stream;
        writeln!(stream, r#"{{"state":"queued"}}"#).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(350));
        writeln!(stream, r#"{{"state":"shown"}}"#).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(350));
        writeln!(stream, r#"{{"state":"done","result":{{"number":3}}}}"#).unwrap();
    });

    let mut agent = Agent::start(&socket);
    agent.ask(
        "initialize",
        json!({ "protocolVersion": "2025-06-18", "clientInfo": { "name": "Test Agent" } }),
    );
    let asked = std::time::Instant::now();
    let (failed, mut said) = agent.call(
        "sign_revocation_list",
        json!({ "workspace": folder, "ca": "issuing" }),
    );
    assert!(!failed, "{said}");
    // The person has something else open: the agent is told so at once,
    // to tell them, and does not wait out a whole call first.
    assert_eq!(said["state"], "queued");
    assert!(
        said["message"]
            .as_str()
            .unwrap()
            .contains("something else open"),
        "{said}"
    );
    assert!(asked.elapsed() < std::time::Duration::from_millis(300));
    let id = said["request_id"].as_str().unwrap().to_owned();
    let mut waits = 0;
    let mut shown = false;
    while said["state"] == "queued" || said["state"] == "waiting" {
        shown |= said["state"] == "waiting";
        waits += 1;
        assert!(waits < 50, "{said}");
        let (failed, next) = agent.call("wait_for_request", json!({ "request_id": id }));
        assert!(!failed, "{next}");
        said = next;
    }
    assert!(waits >= 2, "waited {waits} times");
    assert!(shown, "the agent was never told the dialog is up");
    assert_eq!(said["state"], "done");
    assert_eq!(said["result"]["number"], 3);
    window.join().unwrap();

    // Once it has ended there is nothing left to wait for.
    let (failed, _) = agent.call("wait_for_request", json!({ "request_id": id }));
    assert!(failed);
}
