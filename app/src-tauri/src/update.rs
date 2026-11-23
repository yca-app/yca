//! Looking for a newer release of the app, and putting it in place of this
//! one.
//!
//! Only a released app does this. Where to ask, and the key the answer has
//! to be signed with, are added to the app's configuration when a release
//! is built (see `scripts/release.sh`). An app built from source has
//! neither: it makes no connection of its own and says that it cannot
//! update itself.
//!
//! Nothing is fetched or installed unasked. The window asks whether there
//! is a newer version, and a person says that it is to be installed. What
//! was downloaded is checked against the key built into this app before
//! any of it is used, and the app that is running stays where it is until
//! the new one is in its place.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::menu::{Menu, MenuItem, MenuItemKind};
use tauri::{App, AppHandle, Emitter, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::{KeyLock, timestamp};

/// Sent to the window while a new version comes in: how much of it is
/// here, and once it is all here, that it is being put in place.
const PROGRESS_EVENT: &str = "yca://update-progress";

/// Sent to the window when "Check for Updates…" is chosen in the menu.
const ASKED_EVENT: &str = "yca://check-for-updates";

const MENU_ITEM: &str = "check-for-updates";

/// How long the question whether there is a newer version may take.
const PATIENCE: Duration = Duration::from_secs(20);

/// How long a download may go without a single byte arriving, and how long
/// it may take in all. A server that stops answering, or that feeds the
/// app a trickle for ever, does not keep the app waiting on it.
const STALLED: Duration = Duration::from_secs(30);
const DOWNLOAD_PATIENCE: Duration = Duration::from_secs(30 * 60);

/// More than an update can be. The app is some ten megabytes; what
/// arrives is kept in memory until its signature is checked, so a server
/// that sends without end is cut off here and not when memory runs out.
const LARGEST_UPDATE: u64 = 300 * 1024 * 1024;

/// What the window is told when a download was given up because the
/// person said so, which is not something that went wrong.
const CANCELLED: &str = "cancelled";

/// The newer version that was found last, kept for when it is installed:
/// what a person agreed to is then what they get.
#[derive(Default)]
pub(crate) struct Found(Mutex<Option<Update>>);

/// Something that stops a download when it is called.
type Stop = Box<dyn Fn() + Send + Sync>;

/// How to stop the download that is under way, if one is.
#[derive(Default)]
pub(crate) struct Downloading(Mutex<Option<Stop>>);

impl Downloading {
    fn set(&self, stop: Option<Stop>) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = stop;
    }

    fn stop(&self) {
        if let Some(stop) = self.0.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            stop();
        }
    }
}

/// Whether this app was built to update itself.
fn enabled(app: &AppHandle) -> bool {
    app.config().plugins.0.contains_key("updater")
}

/// Sets the updater up in an app that was built with one, and puts
/// "Check for Updates…" into the menu, under About.
pub(crate) fn setup(app: &App) -> tauri::Result<()> {
    app.manage(Found::default());
    app.manage(Downloading::default());
    if !enabled(app.handle()) {
        return Ok(());
    }
    app.handle()
        .plugin(tauri_plugin_updater::Builder::new().build())?;

    let menu = Menu::default(app.handle())?;
    if let Some(MenuItemKind::Submenu(of_the_app)) = menu.items()?.into_iter().next() {
        let item = MenuItem::with_id(
            app.handle(),
            MENU_ITEM,
            "Check for Updates…",
            true,
            None::<&str>,
        )?;
        of_the_app.insert(&item, 1)?;
    }
    app.set_menu(menu)?;
    app.on_menu_event(|app, event| {
        if event.id() == MENU_ITEM {
            let _ = app.emit(ASKED_EVENT, ());
        }
    });
    Ok(())
}

/// What the window is told about updates before it asks for one.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    /// This app can look for a newer version and install it.
    available: bool,
    /// The version that is running.
    version: String,
}

#[tauri::command]
pub fn update_status(app: AppHandle) -> UpdateStatus {
    UpdateStatus {
        available: enabled(&app),
        version: app.package_info().version.to_string(),
    }
}

/// A newer version than the one that is running.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewVersion {
    version: String,
    /// What changed, as the release says it.
    notes: Option<String>,
    /// When it was released.
    date: Option<String>,
}

/// Asks whether there is a newer version. Makes one request, to where the
/// releases are published, and changes nothing.
#[tauri::command]
pub async fn check_for_update(app: AppHandle) -> Result<Option<NewVersion>, String> {
    if !enabled(&app) {
        return Err("this app was not built to update itself".to_owned());
    }
    // The release says where to ask, and that is an address with TLS.
    // What the answer names as the place to download from is held to the
    // same: the library would fetch the archive over plain HTTP, and
    // follow a redirect there, with only a note in a log. A build that is
    // told to ask a plain address, as one for trying updates out on this
    // Mac is, is left to it.
    let secure = !plain_addresses_allowed(&app);
    let update = app
        .updater_builder()
        .timeout(PATIENCE)
        .configure_client(move |client| client.read_timeout(STALLED).https_only(secure))
        .build()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| e.to_string())?;

    let found = update.as_ref().map(|update| NewVersion {
        version: update.version.clone(),
        notes: update.body.clone().filter(|notes| !notes.trim().is_empty()),
        date: update.date.map(timestamp),
    });
    *app.state::<Found>()
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = update;
    Ok(found)
}

/// Whether this build was told that it may ask a plain HTTP address for
/// updates, which no release is.
fn plain_addresses_allowed(app: &AppHandle) -> bool {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|updater| updater.get("dangerousInsecureTransportProtocol"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// How far a download has come.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    /// Bytes that are here.
    downloaded: u64,
    /// Bytes in all, if the server said.
    total: Option<u64>,
    /// Everything is here and checked, and is being put in place.
    installing: bool,
}

/// Downloads the version that was found, checks its signature, puts it in
/// place of this app and starts it. `version` is the one the person was
/// shown: nothing else is installed in its name.
///
/// The download can be given up with [`cancel_update`] for as long as it
/// lasts, and gives up by itself if nothing arrives for a while, if it
/// takes too long in all, or if more arrives than an update can be. Once
/// everything is here and checked it is seen through.
///
/// Does not come back when it works: the app is started anew.
#[tauri::command]
pub async fn install_update(app: AppHandle, version: String) -> Result<(), String> {
    let mut update = app
        .state::<Found>()
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .filter(|update| update.version == version)
        .ok_or_else(|| "that version is not the one that was found; look again".to_owned())?;
    // The question whether there is an update has its own, shorter limit;
    // what it found comes without one.
    update.timeout = Some(DOWNLOAD_PATIENCE);

    // The download runs as a task of its own, so that it can be stopped
    // from outside: by the person, and by the count of what has arrived.
    let too_large = Arc::new(AtomicBool::new(false));
    let stop: Arc<Mutex<Option<Stop>>> = Arc::default();
    let task = tauri::async_runtime::spawn({
        let update = update.clone();
        let progress = app.clone();
        let (too_large, stop) = (too_large.clone(), stop.clone());
        let mut downloaded = 0;
        async move {
            update
                .download(
                    move |chunk, total| {
                        downloaded += chunk as u64;
                        if downloaded > LARGEST_UPDATE
                            || total.is_some_and(|all| all > LARGEST_UPDATE)
                        {
                            too_large.store(true, Ordering::Relaxed);
                            if let Some(stop) =
                                stop.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
                            {
                                stop();
                            }
                            return;
                        }
                        let _ = progress.emit(
                            PROGRESS_EVENT,
                            Progress {
                                downloaded,
                                total,
                                installing: false,
                            },
                        );
                    },
                    || {},
                )
                .await
        }
    });
    let stopper = || -> Stop {
        let task = task.inner().abort_handle();
        Box::new(move || task.abort())
    };
    *stop.lock().unwrap_or_else(|e| e.into_inner()) = Some(stopper());
    app.state::<Downloading>().set(Some(stopper()));
    let arrived = task.await;
    app.state::<Downloading>().set(None);

    let archive = match arrived {
        Ok(Ok(archive)) => archive,
        Ok(Err(e)) => return Err(e.to_string()),
        // Stopped: because too much came, or because the person said so.
        Err(_) if too_large.load(Ordering::Relaxed) => {
            return Err(
                "the download is larger than an update can be, and was given up".to_owned(),
            );
        }
        Err(_) => return Err(CANCELLED.to_owned()),
    };

    // All of it is here and its signature holds. From here it is seen
    // through.
    let _ = app.emit(
        PROGRESS_EVENT,
        Progress {
            downloaded: 0,
            total: None,
            installing: true,
        },
    );
    update.install(archive).map_err(|e| e.to_string())?;

    // The new app is in place. This one makes way for it, once nothing is
    // talking to a YubiKey any more.
    let lock = app.state::<KeyLock>();
    let _idle = lock.wait();
    app.restart();
}

/// Gives up the download that is under way. The window then hears from
/// [`install_update`] that it was cancelled. Too late once the download is
/// done: what is being put in place is not interrupted.
#[tauri::command]
pub fn cancel_update(app: AppHandle) {
    app.state::<Downloading>().stop();
}
