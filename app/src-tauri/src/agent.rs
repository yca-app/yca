//! The app's side of `yca_core::agent`: where a program working on a
//! person's behalf leaves what only the person can do.
//!
//! A request that comes in is passed to the window, which shows its usual
//! dialog filled in with what was asked and says who asks. Nothing is
//! signed, deleted or created here: that happens through the window's own
//! commands once the person has agreed, exactly as if they had started it
//! themselves. This file only carries the question in and the answer out,
//! and tells the window when the program that asked has gone, so that
//! nothing is put before the person that nobody waits for any more.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager};
use yca_core::agent::{self, Reply, Request};

/// The event that carries a request to the window.
const ASKED: &str = "yca://agent-request";
/// The event that tells the window a request's program has gone.
const GONE: &str = "yca://agent-gone";

/// How long a request waits for the window to come up, as when the app
/// was started for its sake.
const STARTING: Duration = Duration::from_secs(20);

/// What a connection hears about: from the program, and from the window.
enum Event {
    /// A line the program wrote: a request.
    Line(String),
    /// What the window says to the request with this id.
    Reply(String, Reply),
    /// The program hung up.
    Gone,
}

/// The requests that are with the window, waiting for the person.
#[derive(Default)]
pub(crate) struct Desk {
    /// Whether the window is there to be shown anything yet.
    ready: AtomicBool,
    waiting: Mutex<HashMap<String, mpsc::Sender<Event>>>,
}

/// What a connection needs of the window. Apart from the app there is a
/// stand-in for tests.
trait Window {
    /// Passes a request to the window. What the window says to it comes
    /// back through `told`.
    fn show(&self, request: &Request, told: mpsc::Sender<Event>) -> Result<(), String>;
    /// Brings the window before the person: there is something to look at.
    fn come_forward(&self);
    /// The request has been answered for good.
    fn settled(&self, id: &str);
    /// The program that made the request has gone without an answer.
    fn gone(&self, id: &str);
}

impl Window for AppHandle {
    fn show(&self, request: &Request, told: mpsc::Sender<Event>) -> Result<(), String> {
        let desk = self.state::<Desk>();
        // An app that was started for this request needs a moment.
        let started = Instant::now();
        while !desk.ready.load(Ordering::Acquire) {
            if started.elapsed() > STARTING {
                return Err("the app's window did not come up".to_owned());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        desk.waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(request.id.clone(), told);
        self.emit(ASKED, request).map_err(|error| {
            self.settled(&request.id);
            format!("the window could not be shown the request: {error}")
        })
    }

    fn come_forward(&self) {
        if let Some(window) = self.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
    }

    fn settled(&self, id: &str) {
        self.state::<Desk>()
            .waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
    }

    fn gone(&self, id: &str) {
        self.settled(id);
        let _ = self.emit(GONE, id);
    }
}

/// Starts listening for requests. Without a place to listen the app works
/// as before; programs are then told that it is not there.
pub(crate) fn listen(app: &AppHandle) {
    let Some(path) = agent::socket_path() else {
        return;
    };
    let Some(folder) = path.parent() else {
        return;
    };
    // Only the user of this computer may ask the app for anything.
    if std::fs::create_dir_all(folder).is_err() {
        return;
    }
    let _ = std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700));
    // A socket left behind by an earlier run would be in the way.
    let _ = std::fs::remove_file(&path);
    let Ok(listener) = UnixListener::bind(&path) else {
        return;
    };
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    let app = app.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let app = app.clone();
            std::thread::spawn(move || serve(&app, stream));
        }
    });
}

/// Takes the requests of one program for as long as it stays connected.
/// One request is with the window at a time; what the program asks on top
/// of it waits here. When the program hangs up, the request it has with
/// the window is taken back.
fn serve(window: &impl Window, stream: UnixStream) {
    let Ok(reading) = stream.try_clone() else {
        return;
    };
    let mut answers = stream;
    let (tell, events) = mpsc::channel();
    let lines = tell.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(reading).lines() {
            let Ok(line) = line else {
                break;
            };
            if lines.send(Event::Line(line)).is_err() {
                return;
            }
        }
        let _ = lines.send(Event::Gone);
    });

    let mut with_window: Option<String> = None;
    let mut later: VecDeque<String> = VecDeque::new();
    for event in events {
        match event {
            Event::Line(line) if line.trim().is_empty() => {}
            Event::Line(line) => later.push_back(line),
            // An answer to a request that is not with the window any more
            // is nobody's to hear.
            Event::Reply(id, _) if with_window.as_deref() != Some(id.as_str()) => {}
            Event::Reply(id, reply) => {
                // The person is wanted at the window once there is
                // something to look at, not for a request that is turned
                // down unseen or still waits its turn.
                if matches!(reply, Reply::Shown) {
                    window.come_forward();
                }
                if say(&mut answers, &reply).is_err() {
                    window.gone(&id);
                    return;
                }
                if reply.is_final() {
                    window.settled(&id);
                    with_window = None;
                }
            }
            Event::Gone => {
                if let Some(id) = with_window {
                    window.gone(&id);
                }
                return;
            }
        }
        // The next request goes to the window as soon as it has none.
        while with_window.is_none() {
            let Some(line) = later.pop_front() else {
                break;
            };
            let said = match serde_json::from_str::<Request>(&line) {
                Ok(request) => match window.show(&request, tell.clone()) {
                    Ok(()) => {
                        with_window = Some(request.id);
                        Ok(())
                    }
                    Err(message) => say(&mut answers, &Reply::Failed { message }),
                },
                Err(error) => say(
                    &mut answers,
                    &Reply::Failed {
                        message: format!("the request cannot be read: {error}"),
                    },
                ),
            };
            if said.is_err() {
                // The program hung up.
                if let Some(id) = with_window {
                    window.gone(&id);
                }
                return;
            }
        }
    }
}

fn say(answers: &mut UnixStream, reply: &Reply) -> std::io::Result<()> {
    let mut line = serde_json::to_string(reply).map_err(std::io::Error::other)?;
    line.push('\n');
    answers.write_all(line.as_bytes())
}

/// The window is up and listening for requests.
#[tauri::command]
pub fn agent_ready(desk: tauri::State<'_, Desk>) {
    desk.ready.store(true, Ordering::Release);
}

/// What the window says to a request: that it waits its turn, that it is
/// shown, or how it ended. An answer to a request nobody waits for any
/// more, as when the program has gone, is dropped.
#[tauri::command]
pub fn answer_agent(desk: tauri::State<'_, Desk>, id: String, reply: Reply) {
    let waiting = desk.waiting.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(told) = waiting.get(&id) {
        let _ = told.send(Event::Reply(id, reply));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use yca_core::agent::Ask;

    use super::*;

    /// A window that notes what it is shown and told, and answers when
    /// the test says so.
    #[derive(Default)]
    struct Stand {
        shown: Mutex<Vec<(String, mpsc::Sender<Event>)>>,
        log: Mutex<Vec<String>>,
    }

    impl Stand {
        fn note(&self, what: String) {
            self.log.lock().unwrap().push(what);
        }
        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
        /// Answers the request with this id, as the window would.
        fn answer(&self, id: &str, reply: Reply) {
            let shown = self.shown.lock().unwrap();
            let (_, told) = shown.iter().find(|(shown, _)| shown == id).unwrap();
            told.send(Event::Reply(id.to_owned(), reply)).unwrap();
        }
        /// Waits until the log has this many entries.
        fn wait_for(&self, entries: usize) {
            let started = Instant::now();
            while self.log().len() < entries {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "{:?}",
                    self.log()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Window for Arc<Stand> {
        fn show(&self, request: &Request, told: mpsc::Sender<Event>) -> Result<(), String> {
            self.note(format!("show {}", request.id));
            self.shown.lock().unwrap().push((request.id.clone(), told));
            Ok(())
        }
        fn come_forward(&self) {
            self.note("forward".to_owned());
        }
        fn settled(&self, id: &str) {
            self.note(format!("settled {id}"));
        }
        fn gone(&self, id: &str) {
            self.note(format!("gone {id}"));
        }
    }

    fn request(id: &str) -> String {
        let request = Request {
            id: id.to_owned(),
            from: "a test".to_owned(),
            workspace: None,
            ask: Ask::Delete {
                serial: "ab12".to_owned(),
            },
        };
        format!("{}\n", serde_json::to_string(&request).unwrap())
    }

    /// A program connected to a window that is stood in for.
    fn connected() -> (Arc<Stand>, UnixStream, BufReader<UnixStream>) {
        let (program, app) = UnixStream::pair().unwrap();
        let stand = Arc::new(Stand::default());
        let window = stand.clone();
        std::thread::spawn(move || serve(&window, app));
        let answers = BufReader::new(program.try_clone().unwrap());
        (stand, program, answers)
    }

    fn heard(answers: &mut BufReader<UnixStream>) -> Reply {
        let mut line = String::new();
        answers.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    #[test]
    fn one_request_is_with_the_window_at_a_time() {
        let (stand, mut program, mut answers) = connected();
        // Two requests at once, and something that is no request.
        program.write_all(request("1").as_bytes()).unwrap();
        program.write_all(request("2").as_bytes()).unwrap();
        program.write_all(b"nonsense\n").unwrap();
        stand.wait_for(1);
        assert_eq!(stand.log(), ["show 1"]);

        // The first waits its turn, is shown, and is done; only being
        // shown brings the window forward.
        stand.answer("1", Reply::Queued);
        assert_eq!(heard(&mut answers), Reply::Queued);
        stand.answer("1", Reply::Shown);
        assert_eq!(heard(&mut answers), Reply::Shown);
        stand.answer("1", Reply::Declined);
        assert_eq!(heard(&mut answers), Reply::Declined);
        // Then the second goes to the window.
        stand.wait_for(4);
        assert_eq!(stand.log(), ["show 1", "forward", "settled 1", "show 2"]);

        // A late word about the first is nobody's to hear.
        stand.answer("1", Reply::Shown);
        stand.answer(
            "2",
            Reply::Failed {
                message: "no such certificate".to_owned(),
            },
        );
        assert!(
            matches!(heard(&mut answers), Reply::Failed { message } if message.contains("no such"))
        );
        // What was no request is said to be none.
        assert!(
            matches!(heard(&mut answers), Reply::Failed { message } if message.contains("cannot be read"))
        );
        stand.wait_for(5);
        assert_eq!(stand.log()[4], "settled 2");
    }

    #[test]
    fn a_program_that_hangs_up_takes_its_request_back() {
        let (stand, mut program, mut answers) = connected();
        program.write_all(request("1").as_bytes()).unwrap();
        program.write_all(request("2").as_bytes()).unwrap();
        stand.wait_for(1);
        stand.answer("1", Reply::Shown);
        assert_eq!(heard(&mut answers), Reply::Shown);

        // The program goes away while the person is still looking.
        drop(answers);
        program.shutdown(std::net::Shutdown::Both).unwrap();
        drop(program);
        stand.wait_for(3);
        // The window is told, and the request that waited behind it is
        // never shown.
        assert_eq!(stand.log(), ["show 1", "forward", "gone 1"]);
    }
}
