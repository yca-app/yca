//! One program at a time talks to the YubiKeys.
//!
//! A YubiKey forgets that the PIN was given as soon as anything else
//! talks to it, and it does not matter which program that is. The window
//! looks at the keys every few seconds, the command line lists them
//! before it signs, and an agent may start either at any moment. A look
//! by one of them between the PIN and the signature of another makes
//! that signature fail, and one in the middle of a new CA leaves a key
//! without its certificate.
//!
//! So whatever talks to a YubiKey takes a turn first, and the others
//! wait until it is done. A turn is a lock on a file in the app's folder.
//! The lock is the operating system's, on the open file: a program that
//! dies gives it up along with everything else it had open, and nothing
//! is ever left to tidy.
//!
//! Inside one program a turn can be taken again while it is kept. What it
//! keeps apart are programs, not the parts of one: those have to settle
//! it between themselves, as the app does.
//!
//! A program that is not yca knows nothing of this, and against one that
//! talks to the same YubiKey at the same moment nothing here helps.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::Error;
use crate::agent::app_folder;

/// The file whose lock says that a program is talking to the YubiKeys.
const LOCK_FILE: &str = "keys.lock";

/// How long a program waits for another one to finish. The longest thing
/// done in one turn is a signature or two with their touches, and a
/// YubiKey gives up on a touch after some fifteen seconds.
const PATIENCE: Duration = Duration::from_secs(30);

/// How often a waiting program looks whether the other one is done.
const LOOK_AGAIN: Duration = Duration::from_millis(50);

/// The turns of this program.
static OURS: LazyLock<Turns> = LazyLock::new(|| Turns::at(app_folder().map(|f| f.join(LOCK_FILE))));

/// A turn at the YubiKeys, kept for as long as this is.
#[derive(Debug)]
pub struct Turn {
    of: &'static Turns,
}

impl Turn {
    /// Takes the turn, waiting for another program that has it. Gives up
    /// once that has taken longer than anything a program does in one
    /// turn.
    pub fn wait() -> Result<Self, Error> {
        OURS.take(PATIENCE).ok_or(Error::KeysBusy)
    }

    /// Takes the turn if no other program has it: for a look that can as
    /// well be had a moment later.
    pub fn now() -> Option<Self> {
        OURS.take(Duration::ZERO)
    }

    /// Whether another program has the turn at this moment: for telling
    /// a person what the wait that follows is for.
    pub fn is_another_programs() -> bool {
        Self::now().is_none()
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        let mut taken = self.of.taken();
        taken.times = taken.times.saturating_sub(1);
        if taken.times == 0 {
            // Closing the file gives up its lock.
            taken.lock = None;
        }
    }
}

/// Who has the turn, as far as one program knows.
#[derive(Debug)]
struct Turns {
    /// The file all programs lock. `None` where the app's folder cannot
    /// be told.
    path: Option<PathBuf>,
    taken: Mutex<Taken>,
}

#[derive(Debug)]
struct Taken {
    /// How many parts of this program keep the turn.
    times: usize,
    /// The locked file. `None` while the turn is kept without one: where
    /// there is no file to agree on, or it cannot be opened or locked,
    /// that must not keep a program from its YubiKeys.
    lock: Option<fs::File>,
}

impl Turns {
    fn at(path: Option<PathBuf>) -> Self {
        Self {
            path,
            taken: Mutex::new(Taken {
                times: 0,
                lock: None,
            }),
        }
    }

    fn taken(&self) -> MutexGuard<'_, Taken> {
        // What is guarded is a count and a file; they are as good after a
        // panic elsewhere as before it.
        self.taken.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The turn, once no other program has it, or `None` if one still has
    /// it when `patience` is over.
    fn take(&'static self, patience: Duration) -> Option<Turn> {
        let started = Instant::now();
        let mut file = self.path.as_deref().and_then(open);
        loop {
            {
                let mut taken = self.taken();
                // Another part of this program has it: so has this one.
                let ours = taken.times > 0
                    || match file.as_ref().map(fs::File::try_lock) {
                        Some(Ok(())) => {
                            taken.lock = file.take();
                            true
                        }
                        Some(Err(fs::TryLockError::WouldBlock)) => false,
                        // No file, or one that cannot be locked.
                        Some(Err(fs::TryLockError::Error(_))) | None => true,
                    };
                if ours {
                    taken.times += 1;
                    return Some(Turn { of: self });
                }
            }
            if started.elapsed() >= patience {
                return None;
            }
            std::thread::sleep(LOOK_AGAIN);
        }
    }
}

/// Opens the file that is locked, and makes it if this is the first
/// program to ask. Reading is enough to lock a file, and it is all a
/// program may be allowed in the app's folder.
fn open(path: &Path) -> Option<fs::File> {
    if let Ok(file) = fs::File::open(path) {
        return Some(file);
    }
    let folder = path.parent()?;
    let mut make = fs::DirBuilder::new();
    make.recursive(true);
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        // The folder and the file are their user's alone, as the app
        // makes them: nobody else is to hold up this user's YubiKeys.
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        make.mode(0o700);
        options.mode(0o600);
    }
    make.create(folder).ok()?;
    options.open(path).ok()
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    use super::*;

    /// The turns of a program of its own, as far as these tests go: each
    /// has its own count and its own open file.
    fn program(path: &Path) -> &'static Turns {
        Box::leak(Box::new(Turns::at(Some(path.to_owned()))))
    }

    /// The turn, for a program that finds it taken at this moment.
    fn refused(program: &'static Turns) -> bool {
        program.take(Duration::ZERO).is_none()
    }

    /// The turn, for a program whose turn it is.
    ///
    /// Not asked for at the very instant the other one let go: a test
    /// beside this one may be starting a program just then, and for the
    /// blink of an eye that program holds everything this one has open.
    fn given(program: &'static Turns) -> Turn {
        program
            .take(Duration::from_secs(10))
            .expect("nobody else has the turn")
    }

    #[test]
    fn one_program_at_a_time_has_the_turn() {
        let folder = tempfile::tempdir().unwrap();
        // The app's folder may not be there yet: the first program to ask
        // makes it.
        let path = folder.path().join("app").join(LOCK_FILE);
        let window = program(&path);
        let command = program(&path);

        let signing = given(window);
        assert!(refused(command));
        drop(signing);
        let listing = given(command);
        assert!(refused(window));
        drop(listing);
    }

    #[test]
    fn a_program_that_has_the_turn_can_take_it_again() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join(LOCK_FILE);
        let window = program(&path);
        let command = program(&path);

        // A root CA that is open while the key of an issuing CA is made,
        // say: two parts of one program, each with the turn.
        let root = given(window);
        let issuing = window
            .take(Duration::ZERO)
            .expect("the program has the turn already");
        drop(root);
        // The turn is the program's until its last part is done.
        assert!(refused(command));
        drop(issuing);
        drop(given(command));
    }

    #[test]
    fn a_program_waits_for_the_other_to_finish() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join(LOCK_FILE);
        let window = program(&path);
        let command = program(&path);

        let signing = given(window);
        let touched = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(signing);
        });
        let started = Instant::now();
        // Not for ever, though: a program that never finishes is not
        // waited for.
        assert!(command.take(Duration::from_millis(100)).is_none());
        let turn = command.take(Duration::from_secs(10));
        assert!(turn.is_some());
        assert!(started.elapsed() >= Duration::from_millis(250));
        touched.join().unwrap();
    }

    #[test]
    fn where_there_is_no_file_to_lock_nothing_is_held_up() {
        // No home folder, say, or one that cannot be written to.
        let nowhere: &'static Turns = Box::leak(Box::new(Turns::at(None)));
        let first = nowhere.take(Duration::ZERO);
        assert!(first.is_some());
        drop(first);

        let folder = tempfile::tempdir().unwrap();
        let file = folder.path().join("a file");
        fs::write(&file, "").unwrap();
        // A folder that cannot be made: its place is taken by a file.
        let unusable = program(&file.join("app").join(LOCK_FILE));
        assert!(unusable.take(Duration::ZERO).is_some());
    }

    /// Set for the copy of this test program that plays the other one.
    const PLAYS_THE_OTHER: &str = "YCA_TEST_OTHER_PROGRAM_LOCKS";

    /// Another program: a second copy of this test program, which takes
    /// the turn on the file named and keeps it until told to finish.
    struct Other {
        program: std::process::Child,
        /// Whether it got the turn: "taken" or "busy".
        said: &'static str,
        says: std::io::Lines<BufReader<std::process::ChildStdout>>,
    }

    impl Other {
        fn start(path: &Path) -> Self {
            let mut program = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "turn::tests::another_program_really_is_kept_waiting",
                    "--nocapture",
                ])
                .env(PLAYS_THE_OTHER, path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut says = BufReader::new(program.stdout.take().unwrap()).lines();
            let said = says
                .find_map(|line| {
                    let line = line.ok()?;
                    ["taken", "busy"]
                        .into_iter()
                        .find(|word| line.ends_with(word))
                })
                .expect("the other program says how it went");
            Self {
                program,
                said,
                says,
            }
        }

        /// Tells it to let go, and hears it out to its end.
        fn finish(mut self) {
            self.program.stdin.take().unwrap().write_all(b"\n").unwrap();
            for _ in self.says.by_ref() {}
            assert!(self.program.wait().unwrap().success());
        }
    }

    #[test]
    fn another_program_really_is_kept_waiting() {
        // Run as the other program: take the turn, say so, and keep it
        // until told to finish, or until this program is gone.
        if let Some(path) = std::env::var_os(PLAYS_THE_OTHER) {
            let turn = program(Path::new(&path)).take(Duration::from_millis(500));
            println!("{}", if turn.is_some() { "taken" } else { "busy" });
            let mut told = String::new();
            let _ = std::io::stdin().read_line(&mut told);
            return;
        }

        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join(LOCK_FILE);
        let other = || Other::start(&path);

        // The other program is first, and this one has to wait.
        let first = other();
        assert_eq!(first.said, "taken");
        let here = program(&path);
        assert!(here.take(Duration::from_millis(100)).is_none());
        assert!(refused(here));

        // A third one fares no better.
        let third = other();
        assert_eq!(third.said, "busy");
        third.finish();

        // Once the first has finished, the turn is there to take.
        first.finish();
        drop(given(here));

        // And a program that dies with the turn leaves nothing behind.
        let mut dying = other();
        assert_eq!(dying.said, "taken");
        dying.program.kill().unwrap();
        dying.program.wait().unwrap();
        drop(given(here));
    }
}
